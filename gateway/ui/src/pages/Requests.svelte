<script lang="ts">
  import { onMount } from "svelte";
  import type { Api, RequestSummary } from "../lib/api";
  import { go, goQuery, queryParam } from "../lib/router.svelte";
  import { fmtNumber, fmtTime, fmtDuration } from "../lib/format";
  import RequestDetail from "../components/RequestDetail.svelte";

  const TRANSFORMED = new Set(["pseudonymized", "masked", "stripped"]);
  const PAGE = 50;

  let { api, status }: { api: Api; status: (msg: string, isError?: boolean) => void } = $props();

  const COLUMNS = [
    { id: "time", label: "time" },
    { id: "request", label: "request" },
    { id: "model", label: "model" },
    { id: "provider", label: "provider" },
    { id: "client", label: "client" },
    { id: "session", label: "session" },
    { id: "status", label: "status" },
    { id: "tokens", label: "tokens" },
    { id: "latency", label: "latency" },
    { id: "changes", label: "changes" },
  ] as const;
  type ColumnId = (typeof COLUMNS)[number]["id"];

  let items = $state<RequestSummary[]>([]);
  let total = $state(0);
  let query = $state("");
  let auto = $state(true);
  let revealAll = $state(false);
  let onlyChanged = $state(false);
  let expanded = $state<Record<string, boolean>>({});
  let filters = $state<Record<string, string>>({});
  let clientFilter = $state("");
  let providerFilter = $state("");
  let statusFilter = $state("");
  let loading = $state(false);
  const inspectId = $derived(queryParam("id"));
  const hasMore = $derived(items.length > 0 && items.length < total);

  function columnText(item: RequestSummary, column: ColumnId): string {
    switch (column) {
      case "time":
        return fmtTime(item.created_at);
      case "request":
        return `${item.method || ""} ${item.path || ""}`.trim();
      case "model":
        return item.model || "";
      case "provider":
        return item.provider || "";
      case "client":
        return item.client_label || item.client_key || item.client_id || "";
      case "session":
        return item.session_id || "";
      case "status":
        return (item.status || "") + (item.blocked ? " blocked" : "");
      case "tokens":
        return String(item.total_tokens ?? "");
      case "latency":
        return String(item.latency_ms ?? "");
      case "changes":
        return [
          ...(item.changes || []).map((c) => [c.kind, c.action, c.before, c.after].filter(Boolean).join(" ")),
          ...(item.categories || []).map((c) => [c.kind, c.action].filter(Boolean).join(" ")),
        ].join(" ");
      default:
        return "";
    }
  }

  async function load(reset = true): Promise<void> {
    if (loading) return;
    loading = true;
    try {
      const params = new URLSearchParams();
      params.set("limit", String(PAGE));
      params.set("offset", String(reset ? 0 : items.length));
      if (query.trim()) params.set("q", query.trim());
      if (clientFilter.trim()) params.set("client_id", clientFilter.trim());
      if (providerFilter.trim()) params.set("provider", providerFilter.trim());
      if (statusFilter.trim()) params.set("status", statusFilter.trim());
      const data = await api.get<{ items: RequestSummary[]; total: number }>("/audit/requests?" + params);
      items = reset ? data.items || [] : [...items, ...(data.items || [])];
      total = data.total || 0;
      status("");
    } catch (error) {
      status((error as Error).message, true);
    } finally {
      loading = false;
    }
  }

  function resetFilters(): void {
    query = "";
    clientFilter = "";
    providerFilter = "";
    statusFilter = "";
    load(true);
  }

  onMount(() => {
    const session = queryParam("session");
    if (session) filters = { ...filters, session };
    const client = queryParam("client");
    if (client) clientFilter = client;
    const provider = queryParam("provider");
    if (provider) providerFilter = provider;
    load(true);
    // Refresh only the first page; once you page deeper the interval stays quiet
    // so it never fights your scroll or stacks requests.
    const timer = setInterval(() => {
      if (auto && !loading && items.length <= PAGE) load(true);
    }, 5000);
    return () => clearInterval(timer);
  });

  const filtered = $derived(
    items.filter(
      (item) =>
        (!onlyChanged || item.changes_count > 0 || (item.changes || []).length > 0) &&
        COLUMNS.every((column) => {
          const needle = (filters[column.id] || "").trim().toLowerCase();
          return !needle || columnText(item, column.id).toLowerCase().includes(needle);
        }),
    ),
  );

  const columns = COLUMNS;

  function open(id: string): void {
    goQuery("requests", { id });
  }

  function filterByClient(key: string): void {
    clientFilter = key;
    load(true);
  }
</script>

<div class="page">
  <div class="toolbar">
    <input
      class="wide"
      placeholder="search all four audit stages (full text)"
      bind:value={query}
      onkeydown={(e) => e.key === "Enter" && load(true)}
    />
    <input
      placeholder="client id"
      bind:value={clientFilter}
      onkeydown={(e) => e.key === "Enter" && load(true)}
    />
    <input
      placeholder="provider"
      bind:value={providerFilter}
      onkeydown={(e) => e.key === "Enter" && load(true)}
    />
    <select bind:value={statusFilter} onchange={() => load(true)}>
      <option value="">any status</option>
      <option value="pending">pending</option>
      <option value="completed">completed</option>
      <option value="blocked">blocked</option>
      <option value="error">error</option>
      <option value="upstream_error">upstream_error</option>
      <option value="client_disconnected">client_disconnected</option>
    </select>
    <button class="primary" onclick={() => load(true)} disabled={loading}>{loading ? "Loading…" : "Refresh"}</button>
    <label class="check"><input type="checkbox" bind:checked={auto} /> auto 5s</label>
    <label class="check"><input type="checkbox" bind:checked={revealAll} /> reveal values</label>
    <label class="check"><input type="checkbox" bind:checked={onlyChanged} /> only changed</label>
    <button class="ghost" onclick={resetFilters}>Clear</button>
    <div class="spacer"></div>
    <span class="muted">{filtered.length} of {items.length} loaded · {fmtNumber(total)} total</span>
  </div>

  <p class="muted small">
    Loaded {items.length} of {fmtNumber(total)} requests — the list pages 50 at a time so large audits stay fast. Each
    line maps a category to its original value (red) and the obfuscated value (green); values stay hidden until you
    reveal them. Search and the tool filters run server-side; the per-column boxes filter the rows already loaded.
    Click any row to inspect all four stages.
  </p>

  <div class="table-scroll">
    <table class="grid">
      <thead>
        <tr>
          {#each columns as column (column.id)}<th>{column.label}</th>{/each}
          <th></th>
        </tr>
        <tr class="filters-row">
          {#each columns as column (column.id)}
            <th>
              <input placeholder="filter" bind:value={filters[column.id]} />
            </th>
          {/each}
          <th></th>
        </tr>
      </thead>
      <tbody>
        {#each filtered as item (item.id)}
          {@const changes = item.changes || []}
          {@const isOpen = expanded[item.id]}
          {@const shown = isOpen ? changes : changes.slice(0, 6)}
          {@const hidden = changes.length - shown.length}
          <tr class="clickable" onclick={() => open(item.id)}>
            <td class="mono">{fmtTime(item.created_at)}</td>
            <td class="mono wrap">{columnText(item, "request")}</td>
            <td>{item.model || ""}</td>
            <td>{item.provider || ""}</td>
            <td class="mono">
              {#if item.client_key}
                <button
                  class="link"
                  title={item.client_key}
                  onclick={(e) => {
                    e.stopPropagation();
                    filterByClient(item.client_key);
                  }}>{item.client_label || item.client_key.slice(0, 12)}</button
                >
              {:else}
                <span class="muted">—</span>
              {/if}
            </td>
            <td class="mono">{columnText(item, "session")}</td>
            <td class="act">{item.status}{item.blocked ? " (blocked)" : ""}</td>
            <td class="right">{fmtNumber(item.total_tokens)}</td>
            <td class="right">{fmtDuration(item.latency_ms)}</td>
            <td class="wrap">
              <div class="changes-cell">
                {#each shown as change, index (index)}
                  <div class="map-row" title={change.preview || undefined}>
                    <span class="map-kind">{change.kind}</span>
                    <span class="map-before" class:blur={!revealAll}>{change.before ?? "…"}</span>
                    <span class="map-arrow">→</span>
                    <span class="map-after" class:blur={!revealAll}>{change.after ?? "(removed)"}</span>
                  </div>
                {/each}
                {#if hidden > 0}
                  <button
                    class="subtle"
                    onclick={(e) => {
                      e.stopPropagation();
                      expanded = { ...expanded, [item.id]: true };
                    }}>+{hidden} more</button
                  >
                {/if}
                {#if isOpen && changes.length > 6}
                  <button
                    class="subtle"
                    onclick={(e) => {
                      e.stopPropagation();
                      expanded = { ...expanded, [item.id]: false };
                    }}>show less</button
                  >
                {/if}
                {#if item.changes_truncated}
                  <button
                    class="subtle"
                    onclick={(e) => {
                      e.stopPropagation();
                      open(item.id);
                    }}>view all {item.changes_count}</button
                  >
                {/if}
                {#if !changes.length}
                  <span class="muted">
                    {item.categories?.length
                      ? `No rewrites · ${item.categories.reduce((sum, cat) => sum + cat.count, 0)} detected`
                      : "No changes"}
                  </span>
                {/if}
              </div>
              {#if item.categories?.length}
                <div class="cat-row">
                  {#each item.categories as cat (cat.kind + cat.action)}
                    <button
                      class="cat"
                      class:transformed={TRANSFORMED.has(cat.action)}
                      class:flagged={!TRANSFORMED.has(cat.action)}
                      title={`${cat.action} × ${cat.count} — click to filter`}
                      onclick={(e) => {
                        e.stopPropagation();
                        filters = { ...filters, changes: cat.kind };
                      }}>{cat.kind}{cat.count > 1 ? `×${cat.count}` : ""}</button
                    >
                  {/each}
                </div>
              {/if}
            </td>
          </tr>
        {:else}
          <tr><td colspan={columns.length + 1} class="empty-state">No requests match.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>

  {#if hasMore}
    <div class="row end">
      <button class="ghost" onclick={() => load(false)} disabled={loading}>
        {loading ? "Loading…" : `Load more (${fmtNumber(total - items.length)} remaining)`}
      </button>
    </div>
  {/if}
</div>

{#if inspectId}
  <RequestDetail {api} id={inspectId} {status} onClose={() => go("requests")} />
{/if}