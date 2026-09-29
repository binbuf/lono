<script lang="ts">
  import { onMount } from "svelte";
  import type { Api, McpEvent, ToolEvent, ToolStats } from "../lib/api";
  import { goQuery } from "../lib/router.svelte";
  import { fmtAgo, fmtNumber, fmtTime, fmtDuration, color } from "../lib/format";
  import Chart from "../components/Chart.svelte";
  import Stat from "../components/Stat.svelte";
  import { barConfig, doughnutConfig } from "../lib/charts";

  let { api, status }: { api: Api; status: (msg: string, isError?: boolean) => void } = $props();

  let tab = $state<"tools" | "mcp">("tools");
  let hours = $state(24);
  let query = $state("");
  let sessionFilter = $state("");
  let onlyCommands = $state(false);
  let errorsOnly = $state(false);
  let tools = $state<ToolEvent[]>([]);
  let mcp = $state<McpEvent[]>([]);
  let stats = $state<ToolStats | null>(null);
  let loading = $state(false);

  async function load(): Promise<void> {
    loading = true;
    try {
      const common = `q=${encodeURIComponent(query)}&session_id=${encodeURIComponent(sessionFilter)}&limit=300`;
      const [toolData, mcpData, statData] = await Promise.all([
        api.get<{ items: ToolEvent[] }>(`/audit/tools?${common}${onlyCommands ? "&only_commands=true" : ""}`),
        api.get<{ items: McpEvent[] }>(`/audit/mcp?${common}${errorsOnly ? "&errors_only=true" : ""}`),
        api.get<ToolStats>(`/audit/tools/stats?hours=${hours}`),
      ]);
      tools = toolData.items;
      mcp = mcpData.items;
      stats = statData;
      status("");
    } catch (error) {
      status((error as Error).message, true);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    load();
    const timer = setInterval(load, 10000);
    return () => clearInterval(timer);
  });
</script>

<div class="page">
  <div class="toolbar">
    <div class="seg">
      <button class={tab === "tools" ? "active" : ""} onclick={() => (tab = "tools")}>Tool calls</button>
      <button class={tab === "mcp" ? "active" : ""} onclick={() => (tab = "mcp")}>MCP traffic</button>
    </div>
    <input placeholder="search tool / command / params" bind:value={query} onkeydown={(e) => e.key === "Enter" && load()} />
    <input placeholder="session filter" bind:value={sessionFilter} onkeydown={(e) => e.key === "Enter" && load()} />
    {#if tab === "tools"}
      <label class="check"><input type="checkbox" bind:checked={onlyCommands} onchange={load} /> only commands</label>
    {:else}
      <label class="check"><input type="checkbox" bind:checked={errorsOnly} onchange={load} /> errors only</label>
    {/if}
    <button class="primary" onclick={load} disabled={loading}>{loading ? "Loading…" : "Refresh"}</button>
  </div>

  {#if stats}
    <div class="stat-grid">
      <Stat label="Tool events" value={fmtNumber(stats.events)} sub="in window" tone="info" />
      <Stat label="Commands" value={fmtNumber(stats.commands)} sub="shell / exec calls" />
      <Stat label="Distinct tools" value={fmtNumber(stats.tools)} sub="seen in window" />
      <Stat label="MCP calls" value={fmtNumber(stats.mcp_calls)} sub={`${fmtNumber(stats.mcp_errors)} errors`} tone={stats.mcp_errors ? "warn" : "good"} />
    </div>

    <div class="charts">
      <div class="card">
        <h4>Top tools</h4>
        {#if stats.by_tool.length}
          <Chart config={barConfig(stats.by_tool.map((t) => t.name), stats.by_tool.map((t) => t.count), true, "#35d07f")} height={220} />
        {:else}
          <div class="empty-state">No tool activity yet</div>
        {/if}
      </div>
      <div class="card">
        <h4>MCP by server</h4>
        {#if stats.mcp_by_server.length}
          <Chart config={doughnutConfig(stats.mcp_by_server.map((s) => s.name), stats.mcp_by_server.map((s) => s.count))} height={220} />
        {:else}
          <div class="empty-state">No MCP traffic yet</div>
        {/if}
      </div>
    </div>
  {/if}

  {#if tab === "tools"}
    <div class="table-scroll">
      <table class="grid">
        <thead>
          <tr>
            <th>time</th>
            <th>tool</th>
            <th>source</th>
            <th>kind</th>
            <th>command / arguments</th>
            <th>result preview</th>
            <th>task</th>
          </tr>
        </thead>
        <tbody>
          {#each tools as tool (tool.id)}
            {@const index = stats?.by_tool.findIndex((t) => t.name === tool.tool_name) ?? 0}
            <tr>
              <td class="mono">{fmtTime(tool.created_at)}</td>
              <td>
                {#if tool.is_command}<span class="dot" style="background:{color(Math.max(0, index))}"></span>{/if}
                <b>{tool.tool_name ?? "—"}</b>
              </td>
              <td>{tool.source}</td>
              <td>{tool.kind}</td>
              <td class="mono wrap">
                {#if tool.is_command}<span class="cmd">{tool.command}</span>{:else}{tool.command ?? tool.arguments ?? ""}{/if}
              </td>
              <td class="wrap muted">{tool.preview ?? ""}</td>
              <td>
                {#if tool.request_id}
                  <button class="link mono" onclick={() => goQuery("requests", { id: tool.request_id! })}>
                    {tool.request_id.slice(0, 8)}
                  </button>
                  <div class="muted small">{tool.request_model ?? ""} · {fmtAgo(tool.request_created_at)}</div>
                {/if}
              </td>
            </tr>
          {:else}
            <tr><td colspan="7" class="empty-state">No tool events match.</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  {:else}
    <div class="table-scroll">
      <table class="grid">
        <thead>
          <tr>
            <th>time</th>
            <th>server</th>
            <th>direction</th>
            <th>method</th>
            <th>params</th>
            <th>result</th>
            <th>latency</th>
            <th>task</th>
          </tr>
        </thead>
        <tbody>
          {#each mcp as event (event.id)}
            <tr class:row-error={event.is_error}>
              <td class="mono">{fmtTime(event.created_at)}</td>
              <td><b>{event.server ?? "—"}</b></td>
              <td>{event.direction}</td>
              <td class="mono">{event.method ?? event.kind}</td>
              <td class="mono wrap">{event.params ?? ""}</td>
              <td class="wrap muted">{event.result_preview ?? ""}</td>
              <td class="right">{fmtDuration(event.latency_ms)}</td>
              <td>
                {#if event.request_id}
                  <button class="link mono" onclick={() => goQuery("requests", { id: event.request_id! })}>
                    {event.request_id.slice(0, 8)}
                  </button>
                {/if}
              </td>
            </tr>
          {:else}
            <tr><td colspan="8" class="empty-state">No MCP traffic match. Configure servers under Providers.</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>