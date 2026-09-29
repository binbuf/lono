import { useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { Api, Finding, RequestDetail } from "../api";
import {
  buildNeedleRegex,
  extractRequestMessages,
  extractResponseSummary,
  fmtTime,
  offendersFromFindings,
  pretty,
  type Offender,
} from "../util";
import { ChangeChip, Reveal } from "./Reveal";

interface IndexedOffender extends Offender {
  _idx: number;
}

export function Popout({
  api,
  requestId,
  onClose,
  status,
}: {
  api: Api;
  requestId: string;
  onClose: () => void;
  status: (msg: string, isError?: boolean) => void;
}) {
  const [record, setRecord] = useState<RequestDetail | null>(null);
  const [index, setIndex] = useState(0);
  const navRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let cancelled = false;
    api
      .get<RequestDetail>("/audit/requests/" + requestId)
      .then((r) => {
        if (!cancelled) {
          setRecord(r);
          setIndex(0);
        }
      })
      .catch((e) => status(e.message, true));
    return () => {
      cancelled = true;
    };
  }, [api, requestId, status]);

  const offenders = useMemo<IndexedOffender[]>(() => {
    if (!record) return [];
    return offendersFromFindings(record.findings as Finding[] | null).map((o, i) => ({ ...o, _idx: i }));
  }, [record]);

  const byBefore = useMemo(() => {
    const map = new Map<string, IndexedOffender>();
    for (const o of offenders) if (o.before && !map.has(o.before)) map.set(o.before, o);
    return map;
  }, [offenders]);

  const regex = useMemo(() => buildNeedleRegex(offenders), [offenders]);

  useEffect(() => {
    if (!offenders.length) return;
    document.querySelectorAll("#popout mark.offender.active").forEach((el) => el.classList.remove("active"));
    document.querySelectorAll("#popout .modal-nav .chip.active").forEach((el) => el.classList.remove("active"));
    document.querySelectorAll(`#popout mark.offender[data-offender="${index}"]`).forEach((el) => el.classList.add("active"));
    const chip = document.querySelector(`#popout .modal-nav .chip[data-idx="${index}"]`);
    chip?.classList.add("active");
    const first = document.querySelector(`#popout mark.offender[data-offender="${index}"]`);
    first?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, [index, offenders]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      if (!offenders.length) return;
      if (e.key === "Enter" || e.key === "n" || e.key === "ArrowDown" || e.key === "ArrowRight") {
        e.preventDefault();
        setIndex((i) => (i + 1) % offenders.length);
      }
      if (e.key === "p" || e.key === "ArrowUp" || e.key === "ArrowLeft") {
        e.preventDefault();
        setIndex((i) => (i - 1 + offenders.length) % offenders.length);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [offenders.length, onClose]);

  const renderAnnotated = (text: string): ReactNode => {
    if (!text) return <span className="muted">(empty)</span>;
    if (!regex) return <>{text}</>;
    const nodes: ReactNode[] = [];
    regex.lastIndex = 0;
    let last = 0;
    let match: RegExpExecArray | null;
    let count = 0;
    while ((match = regex.exec(text)) !== null && count < 5000) {
      count += 1;
      if (match.index > last) nodes.push(text.slice(last, match.index));
      const value = match[1];
      const offender = byBefore.get(value);
      nodes.push(
        <mark
          key={nodes.length}
          className="offender"
          data-offender={offender ? offender._idx : -1}
          title={offender ? `${offender.kind} · ${offender.action}` : undefined}
          onClick={() => offender && setIndex(offender._idx)}
        >
<del className="red">
            <Reveal secret={!!offender?.before} forceOpen={offender?._idx === index}>
              {value}
            </Reveal>
          </del>
          {offender?.after ? <ins className="green"> {offender.after}</ins> : null}
        </mark>,
      );
      last = match.index + value.length;
    }
    if (last < text.length) nodes.push(text.slice(last));
    return <>{nodes}</>;
  };

  const allowCategory = async (kind: string) => {
    try {
      await api.post("/audit/overrides", { kind: "category", category: kind, minutes: 120, note: "console " + requestId });
      status("allow-through added for " + kind);
    } catch (e) {
      status((e as Error).message, true);
    }
  };
  const allowValue = async (kind: string, value: string) => {
    if (!value) return;
    try {
      await api.post("/audit/overrides", { kind: "value", category: kind, value, minutes: 120, note: "console " + requestId });
      status("allow-through added for one " + kind + " value");
    } catch (e) {
      status((e as Error).message, true);
    }
  };

  const conversation = record ? extractRequestMessages(record.request_original) : [];
  const response = record ? extractResponseSummary(record.response_final, record.response_raw) : null;

  return (
    <div className="overlay" id="popout">
      <div className="backdrop" onClick={onClose} />
      <div className="modal">
        <div className="modal-head">
          <div>
            <div className="title">
              {record ? `${record.method || ""} ${record.path || ""}` : "Loading…"}
            </div>
            <div className="muted" style={{ fontSize: 12 }}>
              {record
                ? `${fmtTime(record.created_at)} · ${record.model || "unknown model"} · ${record.status} · session ${record.session_id || "?"}`
                : ""}
            </div>
          </div>
          <div className="modal-tools">
            <button onClick={() => setIndex((i) => (i - 1 + offenders.length) % (offenders.length || 1))}>‹ prev</button>
            <span className="muted">
              {offenders.length ? index + 1 : 0} / {offenders.length}
            </span>
            <button onClick={() => setIndex((i) => (i + 1) % (offenders.length || 1))}>next ›</button>
            <button className="primary" onClick={onClose}>
              close ✕
            </button>
          </div>
        </div>

        <div className="modal-nav" ref={navRef}>
          {!offenders.length && <span className="muted">No redactions in this request.</span>}
          {offenders.map((o, i) => (
            <span key={i} data-idx={i} onClick={() => setIndex(i)}>
              <ChangeChip kind={o.kind} before={o.before} after={o.after} action={o.action} title={o.preview} />
            </span>
          ))}
        </div>

        <div className="modal-body">
          {record && (
            <>
              {offenders.length > 0 && (
                <section className="pop-section">
                  <h4>Redactions (timeline)</h4>
                  <div className="timeline">
                    {offenders.map((o) => (
                      <div className={"item " + o.action} key={o._idx} onClick={() => setIndex(o._idx)}>
                        <span className="dot" />
                        <div>
                          <div className="meta">
                            <span className="kind">{o.kind}</span> · <span className={"act act-" + o.action}>{o.action}</span>
                          </div>
                          <div className="mono">
                            <del className="red">
                              <Reveal secret={!!o.before} forceOpen={o._idx === index}>
                                {o.before || "••••••"}
                              </Reveal>
                            </del>{" "}
                            <span className="sep">→</span> <ins className="green">{o.after || "«removed»"}</ins>
                          </div>
                          <div className="row" style={{ marginTop: 4 }}>
                            <button className="subtle" onClick={() => allowCategory(o.kind)}>
                              allow category
                            </button>
                            <button className="subtle" onClick={() => allowValue(o.kind, o.before || "")}>
                              allow this value
                            </button>
                            {o.preview && <span className="muted excerpt">{o.preview}</span>}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </section>
              )}

              <section className="pop-section">
                <h4>Question (what was sent)</h4>
                {conversation.length ? (
                  conversation.map((m, i) => (
                    <div className="msg" key={i}>
                      <div>
                        <span className="msg-role">{m.role}</span>
                      </div>
                      <div className="pop-text">{renderAnnotated(m.text)}</div>
                    </div>
                  ))
                ) : (
                  <div className="pop-text">{pretty(record.request_original) || "(none)"}</div>
                )}
              </section>

              {response?.thinking && (
                <section className="pop-section">
                  <h4>Thinking</h4>
                  <div className="pop-text">{renderAnnotated(response.thinking)}</div>
                </section>
              )}
              <section className="pop-section">
                <h4>Response</h4>
                <div className="pop-text">{renderAnnotated(response?.text || "")}</div>
              </section>
              {response?.tool && (
                <section className="pop-section">
                  <h4>Tool calls</h4>
                  <div className="pop-text">{response.tool}</div>
                </section>
              )}

              {(["findings", "request_original", "request_sanitized", "response_raw", "response_final"] as const).map(
                (key) => (
                  <details key={key} style={{ marginTop: 10 }}>
                    <summary className="muted" style={{ cursor: "pointer" }}>
                      {{
                        findings: "Findings (all)",
                        request_original: "1 · Client original",
                        request_sanitized: "2 · Provider payload (sanitized)",
                        response_raw: "3 · Provider response (raw)",
                        response_final: "4 · Client response (final)",
                      }[key]}
                    </summary>
                    <pre className="stage">
                      {key === "findings"
                        ? pretty(record.findings)
                        : pretty(record[key as keyof RequestDetail]) || "(none)"}
                    </pre>
                  </details>
                ),
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}