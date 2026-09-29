import { useCallback, useEffect, useMemo, useState } from "react";
import { Api, getMode } from "./api";
import { Dashboard } from "./components/Dashboard";
import { FilteringLog } from "./components/FilteringLog";
import { Mappings } from "./components/Mappings";
import { Overrides } from "./components/Overrides";
import { Popout } from "./components/Popout";

type Tab = "log" | "dashboard" | "overrides" | "mappings";

const TABS: { id: Tab; label: string }[] = [
  { id: "log", label: "Filtering log" },
  { id: "dashboard", label: "Stats" },
  { id: "overrides", label: "Overrides" },
  { id: "mappings", label: "Mappings" },
];

export default function App() {
  const [key, setKey] = useState(() => localStorage.getItem("lono.key") || "");
  const [draftKey, setDraftKey] = useState(key);
  const [mode, setMode] = useState("…");
  const [tab, setTab] = useState<Tab>("log");
  const [statusMsg, setStatusMsg] = useState("");
  const [statusErr, setStatusErr] = useState(false);
  const [inspectId, setInspectId] = useState<string | null>(null);

  const api = useMemo(() => new Api(key), [key]);

  const status = useCallback((msg: string, isError = false) => {
    setStatusMsg(msg);
    setStatusErr(isError);
  }, []);

  useEffect(() => {
    getMode().then(setMode);
  }, []);

  useEffect(() => {
    if (!key) status("enter the admin key to load data");
  }, [key, status]);

  const saveKey = () => {
    const value = draftKey.trim();
    setKey(value);
    localStorage.setItem("lono.key", value);
    status("key saved");
  };

  return (
    <div className="app">
      <header className="top">
        <div className="brand">
          <span className="logo" />
          <h1>Lono Console</h1>
        </div>
        <span className="badge mode">{mode}</span>
        <div className="spacer" />
        <div className="auth">
          <input
            type="password"
            placeholder="admin key"
            autoComplete="off"
            value={draftKey}
            onChange={(e) => setDraftKey(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") saveKey();
            }}
          />
          <button className="primary" onClick={saveKey}>
            Save
          </button>
          <span id="status" className={statusErr ? "err" : statusMsg ? "ok" : ""}>
            {statusMsg}
          </span>
        </div>
      </header>

      <nav className="tabs">
        {TABS.map((t) => (
          <button key={t.id} className={t.id === tab ? "active" : ""} onClick={() => setTab(t.id)}>
            {t.label}
          </button>
        ))}
      </nav>

      <main>
        {key ? (
          <>
            {tab === "log" && <FilteringLog api={api} onInspect={setInspectId} status={status} />}
            {tab === "dashboard" && <Dashboard api={api} status={status} />}
            {tab === "overrides" && <Overrides api={api} status={status} />}
            {tab === "mappings" && <Mappings api={api} status={status} />}
          </>
        ) : (
          <div className="panel empty-state">Enter the admin key above to load data.</div>
        )}
      </main>

      {inspectId && key && (
        <Popout api={api} requestId={inspectId} onClose={() => setInspectId(null)} status={status} />
      )}
    </div>
  );
}