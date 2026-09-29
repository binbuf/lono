<script lang="ts">
  import { onMount } from "svelte";
  import type { Api, Mapping } from "../lib/api";
  import { fmtTime } from "../lib/format";

  let { api, status }: { api: Api; status: (msg: string, isError?: boolean) => void } = $props();

  let items = $state<Mapping[]>([]);
  let reveal = $state(false);
  let scope = $state("");
  let search = $state("");

  async function load(): Promise<void> {
    try {
      const params = scope ? `?scope=${encodeURIComponent(scope)}` : "";
      items = (await api.get<{ items: Mapping[] }>("/audit/mappings" + params)).items;
      status("");
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  const filtered = $derived(
    items.filter((item) => {
      const needle = search.trim().toLowerCase();
      return !needle || item.original.toLowerCase().includes(needle) || item.pseudonym.toLowerCase().includes(needle);
    }),
  );

  onMount(load);
</script>

<div class="page">
  <div class="toolbar">
    <input placeholder="scope (session:… or global)" bind:value={scope} onkeydown={(e) => e.key === "Enter" && load()} />
    <button class="primary" onclick={load}>Load scope</button>
    <input placeholder="search" bind:value={search} />
    <label class="check"><input type="checkbox" bind:checked={reveal} /> reveal originals</label>
    <div class="spacer"></div>
    <span class="muted">{filtered.length} mappings</span>
  </div>

  <div class="table-scroll">
    <table class="grid">
      <thead><tr><th>scope</th><th>type</th><th>original</th><th>pseudonym</th><th>created</th></tr></thead>
      <tbody>
        {#each filtered as item (item.scope + item.entity_type + item.pseudonym)}
          <tr>
            <td class="mono">{item.scope}</td>
            <td>{item.entity_type}</td>
            <td class="mono wrap" class:blur={!reveal}>{item.original}</td>
            <td class="mono wrap">{item.pseudonym}</td>
            <td class="muted">{fmtTime(item.created_at)}</td>
          </tr>
        {:else}
          <tr><td colspan="5" class="empty-state">No mappings.</td></tr>
        {/each}
      </tbody>
    </table>
  </div>
</div>