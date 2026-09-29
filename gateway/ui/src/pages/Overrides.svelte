<script lang="ts">
  import { onMount } from "svelte";
  import type { Api, Override } from "../lib/api";
  import { fmtAgo, fmtTime } from "../lib/format";

  let { api, status }: { api: Api; status: (msg: string, isError?: boolean) => void } = $props();

  let items = $state<Override[]>([]);
  let kind = $state<"category" | "value">("category");
  let category = $state("");
  let value = $state("");
  let minutes = $state(60);
  let permanent = $state(false);
  let note = $state("");

  async function load(): Promise<void> {
    try {
      items = (await api.get<{ items: Override[] }>("/audit/overrides")).items;
      status("");
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  async function create(): Promise<void> {
    if (!category.trim()) {
      status("a category is required", true);
      return;
    }
    try {
      await api.post("/audit/overrides", {
        kind,
        category: category.trim(),
        value: kind === "value" ? value : undefined,
        minutes: permanent ? undefined : minutes,
        permanent,
        note,
      });
      status("override created");
      category = "";
      value = "";
      note = "";
      await load();
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  async function revoke(id: number): Promise<void> {
    try {
      await api.del(`/audit/overrides/${id}`);
      status("override revoked");
      await load();
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  onMount(load);
</script>

<div class="page">
  <div class="card">
    <h4>Allow-through override</h4>
    <div class="form-row">
      <label>Kind
        <select bind:value={kind}><option value="category">category</option><option value="value">exact value</option></select>
      </label>
      <label class="grow">Category / detector<input placeholder="EMAIL_ADDRESS or pii.regex:EMAIL_ADDRESS" bind:value={category} /></label>
      {#if kind === "value"}<label class="grow">Value<input bind:value={value} /></label>{/if}
      <label>Minutes<input type="number" bind:value={minutes} disabled={permanent} /></label>
      <label class="check inline"><input type="checkbox" bind:checked={permanent} /> permanent</label>
    </div>
    <label>Note<input bind:value={note} /></label>
    <div class="row end"><button class="primary" onclick={create}>Create override</button></div>
  </div>

  <div class="card">
    <h4>Overrides ({items.length})</h4>
    {#if items.length}
      <table class="grid">
        <thead><tr><th>kind</th><th>category</th><th>value</th><th>status</th><th>created</th><th></th></tr></thead>
        <tbody>
          {#each items as item (item.id)}
            <tr class:inactive={!item.active}>
              <td>{item.kind}</td>
              <td class="mono">{item.category}</td>
              <td class="mono wrap">{item.value_display ?? "—"}</td>
              <td>
                {#if item.active}<span class="pill good">active</span>{:else}<span class="pill muted">inactive</span>{/if}
                {#if item.expires_at}<div class="muted small">expires {fmtAgo(item.expires_at)}</div>{/if}
              </td>
              <td class="muted">{fmtTime(item.created_at)}</td>
              <td class="right"><button class="danger small" onclick={() => revoke(item.id)}>Revoke</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <div class="empty-state">No overrides.</div>
    {/if}
  </div>
</div>