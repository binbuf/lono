<script lang="ts">
  import { onMount } from "svelte";
  import type { Api, ClientDetail, ClientSummary } from "../lib/api";
  import { goQuery } from "../lib/router.svelte";
  import { fmtAgo, fmtCost, fmtDuration, fmtNumber, fmtTime, prettyJson } from "../lib/format";
  import Stat from "../components/Stat.svelte";

  let { api, status }: { api: Api; status: (msg: string, isError?: boolean) => void } = $props();

  const WINDOWS = [
    { hours: 1, label: "1h" },
    { hours: 6, label: "6h" },
    { hours: 24, label: "24h" },
    { hours: 168, label: "7d" },
    { hours: 720, label: "30d" },
  ];

  let hours = $state(24);
  let query = $state("");
  let auto = $state(false);
  let items = $state<ClientSummary[]>([]);
  let total = $state(0);
  let loading = $state(false);
  let selected = $state<string | null>(null);
  let detail = $state<ClientDetail | null>(null);
  let detailLoading = $state(false);
  let labelDraft = $state("");
  let savingLabel = $state(false);

  const totals = $derived({
    clients: total,
    requests: items.reduce((sum, item) => sum + item.requests, 0),
    blocked: items.reduce((sum, item) => sum + item.blocked, 0),
    errors: items.reduce((sum, item) => sum + item.errors, 0),
    tokens: items.reduce((sum, item) => sum + item.tokens, 0),
    cost: items.reduce((sum, item) => sum + item.cost_usd, 0),
  });

  function since(h: number): string {
    return new Date(Date.now() - h * 3_600_000).toISOString();
  }

  function label(client: ClientSummary): string {
    return client.label || client.user_agent || "unknown client";
  }

  async function load(): Promise<void> {
    if (loading) return;
    loading = true;
    try {
      const params = new URLSearchParams({ limit: "200", since: since(hours) });
      if (query.trim()) params.set("q", query.trim());
      const data = await api.get<{ items: ClientSummary[]; total: number }>("/audit/clients?" + params);
      items = data.items || [];
      total = data.total || 0;
      status("");
    } catch (error) {
      status((error as Error).message, true);
    } finally {
      loading = false;
    }
  }

  async function fetchDetail(clientId: string): Promise<void> {
    detailLoading = true;
    try {
      detail = await api.get<ClientDetail>(`/audit/clients/${encodeURIComponent(clientId)}?hours=${hours}&limit=25`);
    } catch (error) {
      status((error as Error).message, true);
      selected = null;
    } finally {
      detailLoading = false;
    }
  }

  async function open(clientId: string): Promise<void> {
    selected = clientId;
    detail = null;
    labelDraft = "";
    await fetchDetail(clientId);
  }

  async function saveLabel(label: string): Promise<void> {
    if (!selected) return;
    savingLabel = true;
    try {
      await api.put(`/audit/clients/${encodeURIComponent(selected)}`, { label });
      labelDraft = "";
      await load();
      await fetchDetail(selected);
      status(label.trim() ? "client renamed" : "client label cleared");
    } catch (error) {
      status((error as Error).message, true);
    } finally {
      savingLabel = false;
    }
  }

  function close(): void {
    selected = null;
    detail = null;
    labelDraft = "";
  }

  function setWindow(next: number): void {
    hours = next;
    load();
  }

  onMount(() => {
    load();
    const timer = setInterval(() => {
      if (auto && !loading && !selected) load();
    }, 10000);
    return () => clearInterval(timer);
  });
</script>

<div class="page">
  <div class="toolbar">
    <div class="seg">
      {#each WINDOWS as window (window.hours)}
        <button class={hours === window.hours ? "active" : ""} onclick={() => setWindow(window.hours)}>
          {window.label}
        </button>
      {/each}
    </div>
    <input
      placeholder="search client / user-agent / project"
      bind:value={query}
      onkeydown={(e) => e.key === "Enter" && load()}
    />
    <button class="primary" onclick={load} disabled={loading}>{loading ? "Loading…" : "Refresh"}</button>
    <label class="check"><input type="checkbox" bind:checked={auto} /> auto 10s</label>
    <div class="spacer"></div>
    <span class="muted">{fmtNumber(total)} client{total === 1 ? "" : "s"} in window</span>
  </div>

  <p class="muted small">
    Every client that reaches Lono is fingerprinted by an anonymous hash of its credential, user agent and any
    <code>x-lono-client</code> header — the API key itself is never stored. Click a client for its traffic, the models
    and paths it uses, and a sample of the incoming HTTP headers.
  </p>

  <div class="stat-grid">
    <Stat label="Clients" value={fmtNumber(totals.clients)} sub="distinct in window" tone="info" />
    <Stat label="Requests" value={fmtNumber(totals.requests)} sub="loaded clients" />
    <Stat label="Blocked" value={fmtNumber(totals.blocked)} tone={totals.blocked ? "err" : "good"} sub="policy blocks" />
    <Stat label="Errors" value={fmtNumber(totals.errors)} tone={totals.errors ? "warn" : "good"} sub="upstream / client" />
    <Stat label="Tokens" value={fmtNumber(totals.tokens)} sub="prompt + completion" />
    <Stat label="Cost" value={fmtCost(totals.cost)} sub="reported by provider" />
  </div>

  <div class="table-scroll">
    <table class="grid">
      <thead>
        <tr>
          <th>client</th>
          <th>user agent</th>
          <th class="right">requests</th>
          <th class="right">sessions</th>
          <th class="right">blocked</th>
          <th class="right">errors</th>
          <th class="right">tokens</th>
          <th class="right">cost</th>
          <th class="right">avg latency</th>
          <th>last seen</th>
        </tr>
      </thead>
      <tbody>
        {#each items as client (client.client_id)}
          <tr class="clickable" onclick={() => open(client.client_id)}>
            <td>
              <b>{label(client)}</b>
              <div class="muted mono small">{client.client_id}</div>
            </td>
            <td class="wrap muted small">{client.user_agent ?? "—"}</td>
            <td class="right">{fmtNumber(client.requests)}</td>
            <td class="right">{fmtNumber(client.sessions)}</td>
            <td class="right" class:err={client.blocked > 0}>{fmtNumber(client.blocked)}</td>
            <td class="right" class:err={client.errors > 0}>{fmtNumber(client.errors)}</td>
            <td class="right">{fmtNumber(client.tokens)}</td>
            <td class="right">{fmtCost(client.cost_usd)}</td>
            <td class="right">{fmtDuration(client.avg_latency_ms)}</td>
            <td class="muted">{fmtAgo(client.last_seen)}</td>
          </tr>
        {:else}
          <tr><td colspan="10" class="empty-state">No client traffic in this window.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>

{#if selected}
  <div class="drawer-backdrop" onclick={close} role="presentation"></div>
  <div class="drawer">
    <header class="drawer-head">
      <div>
        <strong>{detail ? label(detail) : "Client"}</strong>
        <div class="muted mono small">{selected}</div>
      </div>
      <div class="spacer"></div>
      <button class="ghost small" onclick={() => goQuery("requests", { client: selected! })}>View all requests</button>
      <button class="ghost small" onclick={close}>✕</button>
    </header>

    {#if detail}
      <div class="meta-grid">
        <span><b>requests</b>{fmtNumber(detail.requests)}</span>
        <span><b>sessions</b>{fmtNumber(detail.sessions)}</span>
        <span><b>blocked</b>{fmtNumber(detail.blocked)}</span>
        <span><b>errors</b>{fmtNumber(detail.errors)}</span>
        <span><b>tokens</b>{fmtNumber(detail.tokens)}</span>
        <span><b>cost</b>{fmtCost(detail.cost_usd)}</span>
        <span><b>avg latency</b>{fmtDuration(detail.avg_latency_ms)}</span>
        <span><b>first seen</b>{fmtTime(detail.first_seen)}</span>
        <span><b>last seen</b>{fmtTime(detail.last_seen)}</span>
        <span><b>window</b>{fmtNumber(detail.window.requests)} in {detail.window.hours}h</span>
      </div>

      <div class="drawer-body">
        <div class="row" style="gap:8px; margin-bottom:12px">
          <input
            class="wide"
            placeholder={detail.label ? `current name: ${detail.label}` : "name this client"}
            bind:value={labelDraft}
            onkeydown={(e) => e.key === "Enter" && saveLabel(labelDraft)}
          />
          <button class="primary small" onclick={() => saveLabel(labelDraft)} disabled={savingLabel}>Save name</button>
          {#if detail.label}
            <button class="ghost small" onclick={() => saveLabel("")} disabled={savingLabel}>Clear</button>
          {/if}
        </div>
        <p class="muted small">
          Names are stored in <code>runtime_config.json</code> against the client fingerprint, so they persist across
          restarts and work for clients that can't send <code>X-Lono-Client</code>.
        </p>

        <div class="charts">
          <div class="card">
            <h4>Top models</h4>
            {#if detail.by_model.length}
              <table class="grid compact">
                <thead><tr><th>model</th><th class="right">requests</th><th class="right">tokens</th></tr></thead>
                <tbody>
                  {#each detail.by_model as row (row.model)}
                    <tr><td>{row.model}</td><td class="right">{fmtNumber(row.requests)}</td><td class="right">{fmtNumber(row.tokens)}</td></tr>
                  {/each}
                </tbody>
              </table>
            {:else}
              <div class="empty-state">No model traffic.</div>
            {/if}
          </div>
          <div class="card">
            <h4>Paths</h4>
            {#if detail.by_path.length}
              <table class="grid compact">
                <thead><tr><th>path</th><th class="right">requests</th><th class="right">errors</th></tr></thead>
                <tbody>
                  {#each detail.by_path as row (row.path)}
                    <tr><td class="mono">{row.path}</td><td class="right">{fmtNumber(row.requests)}</td><td class="right" class:err={row.errors > 0}>{fmtNumber(row.errors)}</td></tr>
                  {/each}
                </tbody>
              </table>
            {:else}
              <div class="empty-state">No path traffic.</div>
            {/if}
          </div>
        </div>

        <h4>Recent requests</h4>
        <table class="grid compact">
          <thead><tr><th>time</th><th>request</th><th>model</th><th>status</th><th class="right">latency</th></tr></thead>
          <tbody>
            {#each detail.recent as request (request.id)}
              <tr class="clickable" onclick={() => goQuery("requests", { id: request.id })}>
                <td class="mono">{fmtTime(request.created_at)}</td>
                <td class="mono wrap">{request.method} {request.path}</td>
                <td>{request.model ?? "—"}</td>
                <td class="act">{request.status}{request.blocked ? " (blocked)" : ""}</td>
                <td class="right">{fmtDuration(request.latency_ms)}</td>
              </tr>
            {:else}
              <tr><td colspan="5" class="empty-state">No recent requests.</td></tr>
            {/each}
          </tbody>
        </table>

        <h4>Incoming HTTP headers</h4>
        {#if detail.header_samples.length}
          <p class="muted small">
            Distinct header snapshots seen from this client. Credential headers (authorization, api keys, cookies,
            tokens) are never captured.
          </p>
          {#each detail.header_samples as sample, index (index)}
            <details class="group" open={index === 0}>
              <summary>header sample {index + 1}</summary>
              <pre class="stage small">{prettyJson(sample)}</pre>
            </details>
          {/each}
        {:else}
          <div class="empty-state">No captured headers for this client.</div>
        {/if}
      </div>
    {:else}
      <div class="empty-state">{detailLoading ? "Loading…" : "No data."}</div>
    {/if}
  </div>
{/if}