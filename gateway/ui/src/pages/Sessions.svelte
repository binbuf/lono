<script lang="ts">
  import { onMount } from "svelte";
  import type { Api, Session } from "../lib/api";
  import { goQuery } from "../lib/router.svelte";
  import { fmtAgo, fmtCost, fmtNumber } from "../lib/format";

  let { api, status }: { api: Api; status: (msg: string, isError?: boolean) => void } = $props();

  let items = $state<Session[]>([]);
  let search = $state("");

  async function load(): Promise<void> {
    try {
      items = (await api.get<{ items: Session[] }>("/audit/sessions?limit=500")).items;
      status("");
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  const filtered = $derived(
    items.filter((item) => !search.trim() || item.session_id.toLowerCase().includes(search.trim().toLowerCase())),
  );

  onMount(load);
</script>

<div class="page">
  <div class="toolbar">
    <input placeholder="filter sessions" bind:value={search} />
    <button class="primary" onclick={load}>Refresh</button>
    <div class="spacer"></div>
    <span class="muted">{filtered.length} sessions</span>
  </div>

  <div class="table-scroll">
    <table class="grid">
      <thead><tr><th>session</th><th class="right">requests</th><th class="right">tokens</th><th class="right">cost</th><th>last seen</th><th></th></tr></thead>
      <tbody>
        {#each filtered as session (session.session_id)}
          <tr>
            <td class="mono">{session.session_id}</td>
            <td class="right">{fmtNumber(session.requests)}</td>
            <td class="right">{fmtNumber(session.total_tokens)}</td>
            <td class="right">{fmtCost(session.cost_usd)}</td>
            <td class="muted">{fmtAgo(session.last_seen)}</td>
            <td class="right">
              <button class="link" onclick={() => goQuery("requests", { session: session.session_id })}>view requests</button>
            </td>
          </tr>
        {:else}
          <tr><td colspan="6" class="empty-state">No sessions yet.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>