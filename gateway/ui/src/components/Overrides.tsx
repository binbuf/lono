import { useCallback, useEffect, useState } from "react";
import type { Api, Override } from "../api";
import { fmtTime } from "../util";
import { Reveal } from "./Reveal";

export function Overrides({ api, status }: { api: Api; status: (msg: string, isError?: boolean) => void }) {
  const [items, setItems] = useState<Override[]>([]);
  const [kind, setKind] = useState("category");
  const [category, setCategory] = useState("");
  const [value, setValue] = useState("");
  const [minutes, setMinutes] = useState(60);
  const [permanent, setPermanent] = useState(false);
  const [note, setNote] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await api.get<{ items: Override[] }>("/audit/overrides");
      setItems(data.items);
    } catch (e) {
      status((e as Error).message, true);
    }
  }, [api, status]);

  useEffect(() => {
    load();
  }, [load]);

  const add = async () => {
    if (!category.trim()) {
      status("category is required", true);
      return;
    }
    try {
      await api.post("/audit/overrides", {
        kind,
        category: category.trim(),
        value: value.trim() || null,
        minutes: permanent ? null : minutes,
        permanent,
        note: note.trim() || null,
      });
      status("override added");
      setValue("");
      setNote("");
      load();
    } catch (e) {
      status((e as Error).message, true);
    }
  };

  const revoke = async (id: number) => {
    try {
      await api.del("/audit/overrides/" + id);
      load();
    } catch (e) {
      status((e as Error).message, true);
    }
  };

  return (
    <div className="panel">
      <h3>Allow data through temporarily</h3>
      <p className="muted">
        A category override lets a whole finding type pass through unchanged (still logged as "allowed"). A value
        override lets one specific original value pass through for a category.
      </p>
      <div className="row" style={{ marginBottom: 14 }}>
        <select value={kind} onChange={(e) => setKind(e.target.value)}>
          <option value="category">category</option>
          <option value="value">value</option>
        </select>
        <input
          placeholder="category e.g. PERSON, EMAIL_ADDRESS, secrets"
          size={34}
          value={category}
          onChange={(e) => setCategory(e.target.value)}
        />
        <input
          placeholder="value (for kind=value)"
          size={26}
          value={value}
          onChange={(e) => setValue(e.target.value)}
          disabled={kind !== "value"}
        />
        <label className="muted row" style={{ gap: 6 }}>
          minutes
          <input
            type="number"
            min={1}
            style={{ width: 90 }}
            value={minutes}
            onChange={(e) => setMinutes(parseInt(e.target.value, 10) || 0)}
            disabled={permanent}
          />
        </label>
        <label className="muted row" style={{ gap: 6 }}>
          <input type="checkbox" checked={permanent} onChange={(e) => setPermanent(e.target.checked)} /> permanent
        </label>
        <input placeholder="note" size={20} value={note} onChange={(e) => setNote(e.target.value)} />
        <button className="primary" onClick={add}>
          Add override
        </button>
      </div>
      <table className="grid">
        <thead>
          <tr>
            <th>id</th>
            <th>kind</th>
            <th>category</th>
            <th>value</th>
            <th>expires</th>
            <th>state</th>
            <th>note</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {items.map((o) => (
            <tr key={o.id}>
              <td>{o.id}</td>
              <td>{o.kind}</td>
              <td><span className="kind">{o.category}</span></td>
              <td className="mono">
                {o.value_display ? (
                  <Reveal>{o.value_display}</Reveal>
                ) : (
                  <span className="muted">—</span>
                )}
              </td>
              <td>{o.expires_at ? fmtTime(o.expires_at) : "until revoked"}</td>
              <td className={o.active ? "act act-allowed" : "muted"}>{o.active ? "active" : "expired"}</td>
              <td>{o.note || ""}</td>
              <td>
                <button className="danger" onClick={() => revoke(o.id)}>
                  revoke
                </button>
              </td>
            </tr>
          ))}
          {!items.length && (
            <tr>
              <td colSpan={8} className="empty-state">
                No overrides.
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}