<script lang="ts">
  import { onMount } from "svelte";
  import type { Api, RequestSummary } from "../lib/api";
  import { go, goQuery, queryParam } from "../lib/router.svelte";
  import { fmtNumber, fmtTime, fmtDuration } from "../lib/format";
  import RequestDetail from "../components/RequestDetail.svelte";

  const TRANSFORMED = new Set(["pseudonymized", "masked", "stripped"]);

  let { api, status }: { api: Api; status: (msg: string, isError?: boolean) => void } = $props();

  const COLUMNS = [
    { id: "time", label: "time" },
    { id: "request", label: "request" },
    { id: "model", label: "model" },
    { id: "provider", label: "provider" },
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
  const inspectId = $derived(queryParam("id"));

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

  async function load(): Promise<void> {
    try {
      const params = new URLSearchParams({ limit: "300" });
      if (query.trim()) params.set("q", query.trim());
      const data = await api.get<{ items: RequestSummary[]; total: number }>("/audit/requests?" + params);
      items = data.items || [];
      total = data.total || 0;
      status("");
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  onMount(() => {
    const session = queryParam("session");
    if (session) filters = { ...filters, session };
    load();
    const timer = setInterval(() => {
      if (auto) load();
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

  let columns = COLUMNS;

  function open(id: string): void {
    goQuery("requests", { id });
  }
</script>

<div class="page">
  <div class="toolbar">
    <input
      class="wide"
      placeholder="search all four audit stages (full text)"
      bind:value={query}
      onkeydown={(e) => e.key === "Enter" && load()}
    />
    <button class="primary" onclick={load}>Refresh</button>
    <label class="check"><input type="checkbox" bind:checked={auto} /> auto 5s</label>
    <label class="check"><input type="checkbox" bind:checked={revealAll} /> reveal values</label>
    <label class="check"><input type="checkbox" bind:checked={onlyChanged} /> only changed</label>
    <button class="ghost" onclick={() => (filters = {})}>Clear filters</button>
    <div class="spacer"></div>
    <span class="muted">{filtered.length} of {items.length} · {fmtNumber(total)} total</span>
  </div>

  <p class="muted small">
    Each line maps a category to its original value (red) and the obfuscated value (green); values stay hidden
    until you reveal them. Category badges below list every detection, including ones that were only flagged.
    Filter the changes column to narrow by category or value. Click any row to inspect all four stages.
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
</div>

{#if inspectId}
  <RequestDetail {api} id={inspectId} {status} onClose={() => go("requests")} />
{/if}