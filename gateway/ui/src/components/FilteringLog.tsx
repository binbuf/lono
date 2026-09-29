import { useCallback, useEffect, useState } from "react";
import type { Api, RequestSummary } from "../api";
import { fmtTime } from "../util";
import { ChangeChip } from "./Reveal";

const COLUMNS = [
  { id: "time", label: "time", width: "165px" },
  { id: "request", label: "request", width: "200px" },
  { id: "model", label: "model", width: "150px" },
  { id: "session", label: "session", width: "130px" },
  { id: "status", label: "status", width: "110px" },
  { id: "changes", label: "changes", width: "" },
] as const;

type ColumnId = (typeof COLUMNS)[number]["id"];

function columnText(item: RequestSummary, col: ColumnId): string {
  switch (col) {
    case "time":
      return fmtTime(item.created_at);
    case "request":
      return `${item.method || ""} ${item.path || ""}`.trim();
    case "model":
      return item.model || "";
    case "session":
      return item.session_id || "";
    case "status":
      return (item.status || "") + (item.blocked ? " blocked" : "");
    case "changes":
      return (item.changes || []).map((c) => [c.kind, c.before, c.after].filter(Boolean).join(" ")).join(" ");
  }
}

export function FilteringLog({
  api,
  onInspect,
  status,
}: {
  api: Api;
  onInspect: (id: string) => void;
  status: (msg: string, isError?: boolean) => void;
}) {
  const [items, setItems] = useState<RequestSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [query, setQuery] = useState("");
  const [auto, setAuto] = useState(true);
  const [revealAll, setRevealAll] = useState(false);
  const [filters, setFilters] = useState<Record<string, string>>({});
  const [expanded, setExpanded] = useState<Record<string, boolean>>({});

  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams({ limit: "300" });
      if (query.trim()) params.set("q", query.trim());
      const data = await api.get<{ items: RequestSummary[]; total: number }>("/audit/requests?" + params);
      setItems(data.items || []);
      setTotal(data.total || 0);
      status("");
    } catch (e) {
      status((e as Error).message, true);
    }
  }, [api, query, status]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    const timer = setInterval(() => {
      if (auto) load();
    }, 5000);
    return () => clearInterval(timer);
  }, [auto, load]);

  const filtered = items.filter((item) =>
    (COLUMNS as readonly { id: ColumnId }[]).every((col) => {
      const needle = (filters[col.id] || "").trim().toLowerCase();
      return !needle || columnText(item, col.id).toLowerCase().includes(needle);
    }),
  );

  const setFilter = (col: ColumnId, value: string) => setFilters((f) => ({ ...f, [col]: value }));

  return (
    <>
      <div className="toolbar">
        <input
          placeholder="search all stages (full text)"
          size={30}
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") load();
          }}
        />
        <button className="primary" onClick={load}>
          Refresh
        </button>
        <label className="muted row" style={{ gap: 6 }}>
          <input type="checkbox" checked={auto} onChange={(e) => setAuto(e.target.checked)} /> auto 5s
        </label>
        <label className="muted row" style={{ gap: 6 }}>
          <input type="checkbox" checked={revealAll} onChange={(e) => setRevealAll(e.target.checked)} /> reveal values
        </label>
        <button className="ghost" onClick={() => setFilters({})}>
          Clear filters
        </button>
        <span className="spacer" />
        <span className="muted">
          {filtered.length} of {items.length} loaded · {total} total
        </span>
      </div>
      <p className="muted" style={{ margin: "0 0 10px", fontSize: 12 }}>
        Red = text that was there, green = what replaced it. Secret and PII values stay hidden until you reveal them.
      </p>
      <div style={{ overflowX: "auto" }}>
        <table className="grid">
          <thead>
            <tr>
              {COLUMNS.map((col) => (
                <th key={col.id} style={col.width ? { width: col.width } : undefined}>
                  {col.label}
                </th>
              ))}
              <th style={{ width: 90 }} />
            </tr>
            <tr className="filters-row">
              {COLUMNS.map((col) => (
                <th key={col.id}>
                  <input
                    placeholder="filter"
                    value={filters[col.id] || ""}
                    onChange={(e) => setFilter(col.id, e.target.value)}
                  />
                </th>
              ))}
              <th />
            </tr>
          </thead>
          <tbody>
            {filtered.map((item) => {
              const changes = item.changes || [];
              const isOpen = expanded[item.id];
              const shown = isOpen ? changes : changes.slice(0, 6);
              const hidden = changes.length - shown.length;
              return (
                <tr key={item.id}>
                  <td className="mono">{fmtTime(item.created_at)}</td>
                  <td className="mono wrap">{columnText(item, "request")}</td>
                  <td>{item.model || ""}</td>
                  <td className="mono">
                    <span
                      style={{ cursor: "pointer" }}
                      onClick={() => setFilter("session", item.session_id || "")}
                      title={item.session_id || ""}
                    >
                      {item.session_id || ""}
                    </span>
                  </td>
                  <td
                    className={"act act-" + (item.status === "blocked" ? "blocked" : "pseudonymized")}
                    style={{ cursor: "pointer" }}
                    onClick={() => setFilter("status", columnText(item, "status"))}
                  >
                    {item.status}
                    {item.blocked ? " (blocked)" : ""}
                  </td>
                  <td className="wrap">
                    <div className="changes-cell">
                      {shown.map((c, i) => (
                        <ChangeChip
                          key={i}
                          kind={c.kind}
                          before={c.before}
                          after={c.after}
                          action={c.action}
                          forceReveal={revealAll}
                          title={c.preview || undefined}
                          onClick={() => onInspect(item.id)}
                        />
                      ))}
                      {hidden > 0 && (
                        <button
                          className="subtle"
                          onClick={() => setExpanded((e) => ({ ...e, [item.id]: true }))}
                        >
                          +{hidden} more
                        </button>
                      )}
                      {isOpen && changes.length > 6 && (
                        <button className="subtle" onClick={() => setExpanded((e) => ({ ...e, [item.id]: false }))}>
                          show less
                        </button>
                      )}
                      {item.changes_truncated && (
                        <button className="subtle" onClick={() => onInspect(item.id)}>
                          view all {item.changes_count} changes
                        </button>
                      )}
                      {!changes.length && <span className="muted">—</span>}
                    </div>
                  </td>
                  <td className="actions">
                    <button className="primary" onClick={() => onInspect(item.id)}>
                      inspect
                    </button>
                  </td>
                </tr>
              );
            })}
            {!filtered.length && (
              <tr>
                <td colSpan={COLUMNS.length + 1} className="empty-state">
                  No requests match.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </>
  );
}