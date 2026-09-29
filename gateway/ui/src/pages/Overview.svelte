<script lang="ts">
  import { onMount } from "svelte";
  import type { Api, Dashboard } from "../lib/api";
  import Chart from "../components/Chart.svelte";
  import Stat from "../components/Stat.svelte";
  import { barConfig, doughnutConfig, lineConfig } from "../lib/charts";
  import { fmtClock, fmtCost, fmtDuration, fmtNumber } from "../lib/format";

  let { api, status }: { api: Api; status: (msg: string, isError?: boolean) => void } = $props();

  const WINDOWS = [
    { label: "1h", hours: 1 },
    { label: "6h", hours: 6 },
    { label: "24h", hours: 24 },
    { label: "7d", hours: 168 },
    { label: "30d", hours: 720 },
  ];

  let hours = $state(24);
  let data = $state<Dashboard | null>(null);
  let loading = $state(false);
  let auto = $state(true);

  async function load(): Promise<void> {
    loading = true;
    try {
      data = await api.get<Dashboard>(`/audit/dashboard?hours=${hours}`);
      status("");
    } catch (error) {
      status((error as Error).message, true);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    load();
    const timer = setInterval(() => {
      if (auto) load();
    }, 10000);
    return () => clearInterval(timer);
  });

  $effect(() => {
    hours;
    load();
  });

  const labels = $derived((data?.timeseries ?? []).map((bucket) => fmtClock(bucket.t)));
  const latencyLabels = $derived((data?.latency_series ?? []).map((point) => fmtClock(point.t)));
  const total = $derived(data?.totals);
  const all = $derived((data?.all_time ?? {}) as Record<string, number>);
  const tools = $derived(data?.tools);
</script>

<div class="page">
  <div class="toolbar">
    <div class="seg">
      {#each WINDOWS as window (window.hours)}
        <button class={window.hours === hours ? "active" : ""} onclick={() => (hours = window.hours)}>
          {window.label}
        </button>
      {/each}
    </div>
    <button class="primary" onclick={load} disabled={loading}>{loading ? "Loading…" : "Refresh"}</button>
    <label class="check"><input type="checkbox" bind:checked={auto} /> auto 10s</label>
    <div class="spacer"></div>
    {#if data}<span class="muted">since {new Date(data.window.since).toLocaleString()}</span>{/if}
  </div>

  <div class="stat-grid">
    <Stat label="Requests" value={fmtNumber(total?.requests)} sub={`${fmtNumber(all.requests)} all time`} />
    <Stat
      label="Blocked"
      value={fmtNumber(total?.blocked)}
      sub={`${(100 * (total?.blocked_rate ?? 0)).toFixed(1)}% of requests`}
      tone={(total?.blocked_rate ?? 0) > 0.1 ? "err" : total?.blocked ? "warn" : "good"}
    />
    <Stat label="Findings" value={fmtNumber(total?.findings)} sub="detections in window" tone="info" />
    <Stat
      label="Tokens"
      value={fmtNumber(total?.tokens)}
      sub={`${fmtNumber(total?.prompt_tokens)} in · ${fmtNumber(total?.completion_tokens)} out`}
    />
    <Stat label="Cost" value={fmtCost(total?.cost_usd)} sub={`${fmtCost(all.cost_usd)} all time`} tone="good" />
    <Stat
      label="Latency p95"
      value={fmtDuration(data?.latency.p95)}
      sub={`avg ${fmtDuration(data?.latency.avg)} · p99 ${fmtDuration(data?.latency.p99)}`}
    />
    <Stat label="Errors" value={fmtNumber(total?.errors)} sub="upstream / gateway" tone={total?.errors ? "err" : "good"} />
    <Stat label="Sessions" value={fmtNumber(all.sessions)} sub={`${fmtNumber(all.mappings)} mappings`} />
    <Stat label="Tool events" value={fmtNumber(tools?.events)} sub={`${fmtNumber(tools?.commands)} commands`} tone="info" />
    <Stat
      label="MCP calls"
      value={fmtNumber(tools?.mcp_calls)}
      sub={`${fmtNumber(tools?.mcp_errors)} errors`}
      tone={tools?.mcp_errors ? "warn" : "good"}
    />
  </div>

  <div class="charts">
    <div class="card span-2">
      <h4>Traffic <span class="hint">requests · blocked · findings per hour</span></h4>
      {#if data}
        <Chart
          config={lineConfig(labels, [
            { name: "requests", values: data.timeseries.map((b) => b.requests), color: "#4da3ff" },
            { name: "blocked", values: data.timeseries.map((b) => b.blocked), color: "#ff5c5c" },
            { name: "findings", values: data.timeseries.map((b) => b.findings), color: "#7c5cff" },
          ])}
          height={220}
        />
      {/if}
    </div>

    <div class="card">
      <h4>Tokens &amp; cost <span class="hint">per hour</span></h4>
      {#if data}
        <Chart
          config={lineConfig(labels, [
            { name: "tokens", values: data.timeseries.map((b) => b.tokens), color: "#35d07f" },
            { name: "cost ×1000", values: data.timeseries.map((b) => Math.round(b.cost_usd * 1000)), color: "#f0b429" },
          ])}
          height={200}
        />
      {/if}
    </div>

    <div class="card">
      <h4>Latency <span class="hint">avg · max ms per hour</span></h4>
      {#if data && data.latency_series.length}
        <Chart
          config={lineConfig(latencyLabels, [
            { name: "avg", values: data.latency_series.map((p) => p.avg_ms), color: "#39c0ed" },
            { name: "max", values: data.latency_series.map((p) => p.max_ms), color: "#ff5c5c" },
          ])}
          height={200}
        />
      {:else}
        <div class="empty-state">No latency data yet</div>
      {/if}
    </div>

    <div class="card">
      <h4>Findings by action</h4>
      {#if data && data.by_action.length}
        <Chart config={doughnutConfig(data.by_action.map((a) => a.name), data.by_action.map((a) => a.count))} height={210} />
      {:else}
        <div class="empty-state">No data yet</div>
      {/if}
    </div>

    <div class="card">
      <h4>Top finding categories</h4>
      {#if data && data.by_kind.length}
        <Chart
          config={barConfig(
            data.by_kind.slice(0, 10).map((k) => k.name),
            data.by_kind.slice(0, 10).map((k) => k.count),
            true,
            "#7c5cff",
          )}
          height={230}
        />
      {:else}
        <div class="empty-state">No data yet</div>
      {/if}
    </div>

    <div class="card">
      <h4>Detectors <span class="hint">hits</span></h4>
      {#if data && data.by_detector.length}
        <Chart
          config={barConfig(data.by_detector.map((d) => d.name), data.by_detector.map((d) => d.count), true, "#4da3ff")}
          height={230}
        />
      {:else}
        <div class="empty-state">No data yet</div>
      {/if}
    </div>

    <div class="card">
      <h4>Top tools <span class="hint">calls in window</span></h4>
      {#if tools && tools.by_tool.length}
        <Chart
          config={barConfig(tools.by_tool.map((t) => t.name), tools.by_tool.map((t) => t.count), true, "#35d07f")}
          height={230}
        />
      {:else}
        <div class="empty-state">No tool activity yet</div>
      {/if}
    </div>

    <div class="card">
      <h4>Models <span class="hint">requests · tokens · cost</span></h4>
      <table class="grid">
        <thead>
          <tr><th>model</th><th class="right">reqs</th><th class="right">tokens</th><th class="right">cost</th></tr>
        </thead>
        <tbody>
          {#each data?.by_model ?? [] as model (model.model)}
            <tr>
              <td>{model.model}</td>
              <td class="right">{fmtNumber(model.requests)}</td>
              <td class="right">{fmtNumber(model.tokens)}</td>
              <td class="right">{fmtCost(model.cost_usd)}</td>
            </tr>
          {:else}
            <tr><td colspan="4" class="empty-state">No data yet</td></tr>
          {/each}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h4>Providers <span class="hint">upstream routing</span></h4>
      <table class="grid">
        <thead>
          <tr><th>provider</th><th class="right">reqs</th><th class="right">tokens</th><th class="right">cost</th></tr>
        </thead>
        <tbody>
          {#each data?.by_provider ?? [] as provider (provider.provider)}
            <tr>
              <td>{provider.provider}</td>
              <td class="right">{fmtNumber(provider.requests)}</td>
              <td class="right">{fmtNumber(provider.tokens)}</td>
              <td class="right">{fmtCost(provider.cost_usd)}</td>
            </tr>
          {:else}
            <tr><td colspan="4" class="empty-state">No data yet</td></tr>
          {/each}
        </tbody>
      </table>
    </div>

    <div class="card">
      <h4>Busiest sessions</h4>
      <table class="grid">
        <thead>
          <tr><th>session</th><th class="right">reqs</th><th class="right">findings</th><th class="right">tokens</th></tr>
        </thead>
        <tbody>
          {#each data?.top_sessions ?? [] as session (session.session_id)}
            <tr>
              <td class="mono">{session.session_id}</td>
              <td class="right">{fmtNumber(session.requests)}</td>
              <td class="right">{fmtNumber(session.findings)}</td>
              <td class="right">{fmtNumber(session.tokens)}</td>
            </tr>
          {:else}
            <tr><td colspan="4" class="empty-state">No data yet</td></tr>
          {/each}
        </tbody>
      </table>
    </div>
  </div>
</div>