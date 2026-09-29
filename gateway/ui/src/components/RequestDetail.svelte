<script lang="ts">
  import { onMount } from "svelte";
  import type { Api, RequestDetail, ToolEvent } from "../lib/api";
  import { fmtCost, fmtDuration, fmtTime, fmtNumber, prettyJson } from "../lib/format";

  let {
    api,
    id,
    onClose,
    status,
  }: {
    api: Api;
    id: string;
    onClose: () => void;
    status: (msg: string, isError?: boolean) => void;
  } = $props();

  let record = $state<RequestDetail | null>(null);
  let tools = $state<ToolEvent[]>([]);
  let tab = $state<"timeline" | "original" | "sanitized" | "raw" | "final">("timeline");
  let reveal = $state(false);

  async function load(): Promise<void> {
    try {
      record = await api.get<RequestDetail>(`/audit/requests/${id}`);
      const toolData = await api.get<{ items: ToolEvent[] }>(`/audit/tools?request_id=${id}&limit=200`);
      tools = toolData.items;
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  async function remove(): Promise<void> {
    if (!confirm("Delete this request record and its tool events?")) return;
    try {
      await api.del(`/audit/requests/${id}`);
      status("request deleted");
      onClose();
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  onMount(load);

  const changed = $derived((record?.findings ?? []).filter((f) => f.action === "pseudonymized" || f.action === "masked" || f.action === "stripped"));

  function stage(value: unknown): string {
    return prettyJson(value) || "(empty)";
  }
</script>

<div class="drawer-backdrop" onclick={onClose} role="presentation"></div>
<div class="drawer">
  <header class="drawer-head">
    <div>
      <strong>{record?.method} {record?.path}</strong>
      <div class="muted mono small">{id}</div>
    </div>
    <div class="spacer"></div>
    <button class="ghost small" onclick={() => (reveal = !reveal)}>{reveal ? "hide values" : "reveal values"}</button>
    <button class="danger small" onclick={remove}>Delete</button>
    <button class="ghost small" onclick={onClose}>✕</button>
  </header>

  {#if record}
    <div class="meta-grid">
      <span><b>time</b>{fmtTime(record.created_at)}</span>
      <span><b>status</b>{record.status}{record.blocked ? " (blocked)" : ""}</span>
      <span><b>model</b>{record.model ?? "—"}</span>
      <span><b>provider</b>{record.provider ?? "—"}</span>
      <span><b>shape</b>{record.api_shape}</span>
      <span><b>mode</b>{record.mode}</span>
      <span><b>session</b><span class="mono">{record.session_id ?? "—"}</span></span>
      <span><b>latency</b>{fmtDuration(record.latency_ms)}</span>
      <span><b>tokens</b>{fmtNumber(record.total_tokens)} ({fmtNumber(record.prompt_tokens)} in / {fmtNumber(record.completion_tokens)} out)</span>
      <span><b>cost</b>{fmtCost(record.cost_usd)}</span>
      {#if record.error}<span class="err"><b>error</b>{record.error}</span>{/if}
    </div>

    <nav class="subtabs">
      <button class={tab === "timeline" ? "active" : ""} onclick={() => (tab = "timeline")}>
        Changes ({changed.length})
      </button>
      <button class={tab === "original" ? "active" : ""} onclick={() => (tab = "original")}>Original</button>
      <button class={tab === "sanitized" ? "active" : ""} onclick={() => (tab = "sanitized")}>Sanitized</button>
      <button class={tab === "raw" ? "active" : ""} onclick={() => (tab = "raw")}>Raw response</button>
      <button class={tab === "final" ? "active" : ""} onclick={() => (tab = "final")}>Final response</button>
    </nav>

    <div class="drawer-body">
      {#if tab === "timeline"}
        {#if changed.length}
          <ol class="timeline">
            {#each changed as finding, index (index)}
              <li>
                <div class="tl-head">
                  <span class="pill">{finding.detector}</span>
                  <span class="pill kind">{finding.kind}</span>
                  <span class="pill act">{finding.action}</span>
                  <span class="muted">score {finding.score.toFixed(2)}</span>
                </div>
                <div class="tl-change">
                  <span class="before" class:blur={!reveal}>{finding.before ?? finding.preview ?? "…"}</span>
                  <span class="arrow">→</span>
                  <span class="after" class:blur={!reveal}>{finding.replacement ?? "(removed)"}</span>
                </div>
              </li>
            {/each}
          </ol>
        {:else}
          <div class="empty-state">No text was changed for this request.</div>
        {/if}
      {:else}
        <pre class="stage">{stage(
          tab === "original" ? record.request_original : tab === "sanitized" ? record.request_sanitized : tab === "raw" ? record.response_raw : record.response_final,
        )}</pre>
      {/if}

      {#if tools.length}
        <h4>Tool activity</h4>
        <table class="grid compact">
          <thead>
            <tr><th>time</th><th>tool</th><th>kind</th><th>command / args</th></tr>
          </thead>
          <tbody>
            {#each tools as tool (tool.id)}
              <tr>
                <td class="mono">{fmtTime(tool.created_at)}</td>
                <td>{tool.tool_name ?? "—"}</td>
                <td>{tool.source}/{tool.kind}</td>
                <td class="mono wrap">
                  {#if tool.is_command}<span class="cmd">{tool.command}</span>{:else}{tool.command ?? tool.arguments ?? tool.preview ?? ""}{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}

      {#if record.client_meta && Object.keys(record.client_meta).length}
        <h4>Client</h4>
        <pre class="stage small">{prettyJson(record.client_meta)}</pre>
      {/if}
    </div>
  {:else}
    <div class="empty-state">Loading…</div>
  {/if}
</div>