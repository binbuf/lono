import { useCallback, useEffect, useState } from "react";
import type { Api, Mapping } from "../api";
import { fmtTime } from "../util";
import { Reveal } from "./Reveal";

export function Mappings({ api, status }: { api: Api; status: (msg: string, isError?: boolean) => void }) {
  const [scope, setScope] = useState("");
  const [items, setItems] = useState<Mapping[]>([]);

  const load = useCallback(
    async (withScope: string) => {
      try {
        const data = await api.get<{ items: Mapping[] }>(
          "/audit/mappings" + (withScope ? "?scope=" + encodeURIComponent(withScope) : ""),
        );
        setItems(data.items);
        status(data.items.length + " mappings");
      } catch (e) {
        status((e as Error).message, true);
      }
    },
    [api, status],
  );

  useEffect(() => {
    load("");
  }, [load]);

  return (
    <div className="panel">
      <h3>Pseudonym mappings</h3>
      <div className="row" style={{ marginBottom: 12 }}>
        <input
          placeholder="scope e.g. session:key-ab12 or global"
          size={34}
          value={scope}
          onChange={(e) => setScope(e.target.value)}
        />
        <button className="primary" onClick={() => load(scope.trim())}>
          Load
        </button>
      </div>
      <table className="grid">
        <thead>
          <tr>
            <th>scope</th>
            <th>category</th>
            <th>original (was)</th>
            <th>pseudonym (now)</th>
            <th>created</th>
          </tr>
        </thead>
        <tbody>
          {items.map((m, i) => (
            <tr key={i}>
              <td className="mono">{m.scope}</td>
              <td>
                <span className="kind">{m.entity_type}</span>
              </td>
              <td className="mono">
                <del className="red">
                  <Reveal>{m.original}</Reveal>
                </del>
              </td>
              <td className="mono">
                <ins className="green">{m.pseudonym}</ins>
              </td>
              <td>{fmtTime(m.created_at)}</td>
            </tr>
          ))}
          {!items.length && (
            <tr>
              <td colSpan={5} className="empty-state">
                No mappings.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}