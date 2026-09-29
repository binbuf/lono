import { useCallback, useEffect, useState } from "react";
import type { Api, Dashboard as DashboardData } from "../api";
import { BarList, ChartLegend, Donut, TimeSeriesChart } from "./Charts";
import { fmtClock, fmtCost, fmtDuration, fmtNumber } from "../util";

const WINDOWS = [
  { label: "1h", hours: 1 },
  { label: "6h", hours: 6 },
  { label: "24h", hours: 24 },
  { label: "7d", hours: 168 },
  { label: "30d", hours: 720 },
];

export function Dashboard({ api, status }: { api: Api; status: (msg: string, isError?: boolean) => void }) {
  const [hours, setHours] = useState(24);
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setData(await api.get<DashboardData>(`/audit/dashboard?hours=${hours}`));
      status("");
    } catch (e) {
      status((e as Error).message, true);
    } finally {
      setLoading(false);
    }
  }, [api, hours, status]);

  useEffect(() => {
    load();
  }, [load]);

  const labels = (data?.timeseries || []).map((b) => fmtClock(b.t));
  const requests = (data?.timeseries || []).map((b) => b.requests);
  const blocked = (data?.timeseries || []).map((b) => b.blocked);
  const findings = (data?.timeseries || []).map((b) => b.findings);
  const tokens = (data?.timeseries || []).map((b) => b.tokens);
  const cost = (data?.timeseries || []).map((b) => b.cost_usd);

  const t = data?.totals;
  const all = data?.all_time || {};

  return (
    <>
      <div className="dash-controls">
        <div className="seg">
          {WINDOWS.map((w) => (
            <button key={w.hours} className={w.hours === hours ? "active" : ""} onClick={() => setHours(w.hours)}>
              {w.label}
            </button>
          ))}
        </div>
        <button className="primary" onClick={load} disabled={loading}>
          {loading ? "Loading…" : "Refresh"}
        </button>
        {data && (
          <span className="muted">
            window since {new Date(data.window.since).toLocaleString()}
          </span>
        )}
      </div>

      <div className="grid-cards">
        <Stat label="Requests" value={fmtNumber(t?.requests)} sub={`${fmtNumber(all.requests as number)} all time`} />
        <Stat
          label="Blocked"
          value={fmtNumber(t?.blocked)}
          sub={`${(100 * (t?.blocked_rate || 0)).toFixed(1)}% of requests`}
          tone={(t?.blocked_rate || 0) > 0.1 ? "err" : t?.blocked ? "warn" : "good"}
        />
        <Stat label="Findings" value={fmtNumber(t?.findings)} sub="detections in window" tone="info" />
        <Stat label="Tokens" value={fmtNumber(t?.tokens)} sub="prompt + completion" />
        <Stat label="Cost" value={fmtCost(t?.cost_usd)} sub={`${fmtCost(all.cost_usd as number)} all time`} tone="good" />
        <Stat
          label="Latency p95"
          value={fmtDuration(data?.latency.p95)}
          sub={`avg ${fmtDuration(data?.latency.avg)} · p99 ${fmtDuration(data?.latency.p99)}`}
        />
        <Stat label="Errors" value={fmtNumber(t?.errors)} sub="upstream / gateway" tone={t?.errors ? "err" : "good"} />
        <Stat label="Sessions" value={fmtNumber(all.sessions as number)} sub={`${fmtNumber(all.mappings as number)} mappings`} />
      </div>

      <div className="charts">
        <div className="card" style={{ gridColumn: "1 / -1" }}>
          <h4>
            Traffic <span className="hint">requests &amp; blocked per hour</span>
          </h4>
          <TimeSeriesChart
            labels={labels}
            series={[
              { name: "requests", color: "#4da3ff", values: requests },
              { name: "blocked", color: "#ff5c5c", values: blocked },
              { name: "findings", color: "#7c5cff", values: findings },
            ]}
            format={(n) => fmtNumber(n)}
          />
          <ChartLegend
            items={[
              { name: "requests", color: "#4da3ff" },
              { name: "blocked", color: "#ff5c5c" },
              { name: "findings", color: "#7c5cff" },
            ]}
          />
        </div>

        <div className="card">
          <h4>
            Tokens &amp; cost <span className="hint">per hour</span>
          </h4>
          <TimeSeriesChart
            labels={labels}
            series={[
              { name: "tokens", color: "#35d07f", values: tokens },
              { name: "cost", color: "#f0b429", values: cost },
            ]}
            format={(n) => fmtNumber(n)}
          />
          <ChartLegend
            items={[
              { name: "tokens", color: "#35d07f" },
              { name: "cost", color: "#f0b429" },
            ]}
          />
        </div>

        <div className="card">
          <h4>
            Findings by action <span className="hint">window</span>
          </h4>
          <Donut slices={(data?.by_action || []).map((a) => ({ name: a.name, value: a.count }))} />
        </div>

        <div className="card">
          <h4>
            Top finding categories <span className="hint">window</span>
          </h4>
          <BarList items={data?.by_kind || []} />
        </div>

        <div className="card">
          <h4>
            Detectors <span className="hint">hits</span>
          </h4>
          <BarList items={(data?.by_detector || []).map((d) => ({ name: d.name, count: d.count }))} color="#7c5cff" />
        </div>

        <div className="card">
          <h4>
            Models <span className="hint">requests · tokens</span>
          </h4>
          <table className="grid">
            <thead>
              <tr>
                <th>model</th>
                <th style={{ textAlign: "right" }}>reqs</th>
                <th style={{ textAlign: "right" }}>tokens</th>
                <th style={{ textAlign: "right" }}>cost</th>
              </tr>
            </thead>
            <tbody>
              {(data?.by_model || []).map((m) => (
                <tr key={m.model}>
                  <td>{m.model}</td>
                  <td style={{ textAlign: "right" }}>{fmtNumber(m.requests)}</td>
                  <td style={{ textAlign: "right" }}>{fmtNumber(m.tokens)}</td>
                  <td style={{ textAlign: "right" }}>{fmtCost(m.cost_usd)}</td>
                </tr>
              ))}
              {!data?.by_model?.length && (
                <tr>
                  <td colSpan={4} className="empty-state">
                    No data yet
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="card">
          <h4>
            Busiest sessions <span className="hint">window</span>
          </h4>
          <table className="grid">
            <thead>
              <tr>
                <th>session</th>
                <th style={{ textAlign: "right" }}>reqs</th>
                <th style={{ textAlign: "right" }}>findings</th>
                <th style={{ textAlign: "right" }}>tokens</th>
              </tr>
            </thead>
            <tbody>
              {(data?.top_sessions || []).map((s) => (
                <tr key={s.session_id}>
                  <td className="mono">{s.session_id}</td>
                  <td style={{ textAlign: "right" }}>{fmtNumber(s.requests)}</td>
                  <td style={{ textAlign: "right" }}>{fmtNumber(s.findings)}</td>
                  <td style={{ textAlign: "right" }}>{fmtNumber(s.tokens)}</td>
                </tr>
              ))}
              {!data?.top_sessions?.length && (
                <tr>
                  <td colSpan={4} className="empty-state">
                    No data yet
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        <div className="card">
          <h4>
            Latency <span className="hint">milliseconds</span>
          </h4>
          <BarList
            items={[
              { name: "avg", count: data?.latency.avg || 0 },
              { name: "p50", count: data?.latency.p50 || 0 },
              { name: "p95", count: data?.latency.p95 || 0 },
              { name: "p99", count: data?.latency.p99 || 0 },
              { name: "max", count: data?.latency.max || 0 },
            ]}
            color="#39c0ed"
          />
        </div>
      </div>
    </>
  );
}

function Stat({ label, value, sub, tone }: { label: string; value: string; sub?: string; tone?: string }) {
  return (
    <div className={"stat " + (tone || "")}>
      <div className="label">{label}</div>
      <div className="value">{value}</div>
      {sub && <div className="sub">{sub}</div>}
    </div>
  );
}