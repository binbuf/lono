<script lang="ts">
  import { onMount } from "svelte";
  import type { Api, ConfigSnapshot, Upstream } from "../lib/api";

  let {
    api,
    status,
    onRefreshServer,
  }: { api: Api; status: (msg: string, isError?: boolean) => void; onRefreshServer?: () => void } = $props();

  let config = $state<ConfigSnapshot | null>(null);
  let upstreams = $state<Upstream[]>([]);
  let servers = $state<{ name: string; url: string; enabled: boolean; headers?: Record<string, string> }[]>([]);
  let saving = $state(false);

  function toForm(list: Upstream[]): Upstream[] {
    return list.map((u) => ({ ...u, models: u.models ?? [], path_prefixes: u.path_prefixes ?? [] }));
  }

  async function load(): Promise<void> {
    try {
      config = await api.get<ConfigSnapshot>("/audit/config");
      upstreams = toForm((config.upstreams as Upstream[]) ?? []);
      const mcp = config.mcp as ConfigSnapshot["mcp"];
      servers = (mcp?.servers ?? []).map((s) => ({ name: s.name, url: s.url, enabled: s.enabled, headers: s.headers }));
      status("");
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  async function saveUpstreams(): Promise<void> {
    saving = true;
    try {
      const cleaned = upstreams
        .filter((u) => u.name && u.base_url)
        .map((u) => ({
          name: u.name,
          base_url: u.base_url,
          enabled: u.enabled,
          description: u.description ?? "",
          timeout_s: Number(u.timeout_s) || 900,
          models: splitList(u.models),
          path_prefixes: splitList(u.path_prefixes),
        }));
      const def = cleaned.find((u) => u.name === "default");
      const rest = cleaned.filter((u) => u.name !== "default");
      await api.patch("/audit/config", { upstream: def, upstreams: rest });
      status("upstreams saved");
      await load();
      onRefreshServer?.();
    } catch (error) {
      status((error as Error).message, true);
    } finally {
      saving = false;
    }
  }

  async function saveServers(): Promise<void> {
    saving = true;
    try {
      const payload = servers
        .filter((s) => s.name && s.url)
        .map((s) => ({ name: s.name, url: s.url, enabled: s.enabled, headers: s.headers ?? {} }));
      await api.patch("/audit/config", { mcp: { servers: payload } });
      status("MCP servers saved");
      await load();
    } catch (error) {
      status((error as Error).message, true);
    } finally {
      saving = false;
    }
  }

  function splitList(value: unknown): string[] {
    if (Array.isArray(value)) return value;
    return String(value ?? "")
      .split(",")
      .map((part) => part.trim())
      .filter(Boolean);
  }

  function addUpstream(): void {
    upstreams = [
      ...upstreams,
      {
        name: `provider-${upstreams.length + 1}`,
        base_url: "https://api.example.com/v1",
        enabled: true,
        description: "",
        models: [],
        path_prefixes: [],
        timeout_s: 900,
      },
    ];
  }

  function removeUpstream(index: number): void {
    upstreams = upstreams.filter((_, i) => i !== index);
  }

  function addServer(): void {
    servers = [...servers, { name: `server-${servers.length + 1}`, url: "http://mcp-server:3000", enabled: true, headers: {} }];
  }

  onMount(load);
</script>

<div class="page">
  <p class="muted">
    Lono can forward to several provider proxies at once. A request is routed by the <code>x-lono-upstream</code>
    header, then the first matching model glob, then a URL path prefix, then the default. All proxies run concurrently.
  </p>

  <div class="card">
    <div class="card-head">
      <h4>Provider proxies</h4>
      <div class="spacer"></div>
      <button class="ghost small" onclick={addUpstream}>+ Add upstream</button>
      <button class="primary" onclick={saveUpstreams} disabled={saving}>Save upstreams</button>
    </div>
    {#each upstreams as upstream, index (index)}
      <div class="route-row">
        <label>name<input bind:value={upstream.name} disabled={upstream.name === "default"} /></label>
        <label class="grow">base url<input bind:value={upstream.base_url} /></label>
        <label class="grow">model globs<input placeholder="gpt-*, claude-*" value={splitList(upstream.models).join(", ")} oninput={(e) => (upstream.models = splitList(e.currentTarget.value))} /></label>
        <label>path prefixes<input placeholder="/v1/realtime" value={splitList(upstream.path_prefixes).join(", ")} oninput={(e) => (upstream.path_prefixes = splitList(e.currentTarget.value))} /></label>
        <label class="check inline"><input type="checkbox" bind:checked={upstream.enabled} /> enabled</label>
        {#if upstream.name !== "default"}
          <button class="danger small" onclick={() => removeUpstream(index)}>✕</button>
        {/if}
      </div>
    {/each}
  </div>

  <div class="card">
    <div class="card-head">
      <h4>MCP servers</h4>
      <span class="muted small">proxied + audited under /v1/mcp/{name}</span>
      <div class="spacer"></div>
      <button class="ghost small" onclick={addServer}>+ Add server</button>
      <button class="primary" onclick={saveServers} disabled={saving}>Save servers</button>
    </div>
    {#each servers as server, index (index)}
      <div class="route-row">
        <label>name<input bind:value={server.name} /></label>
        <label class="grow">url<input bind:value={server.url} /></label>
        <label class="check inline"><input type="checkbox" bind:checked={server.enabled} /> enabled</label>
        <button class="danger small" onclick={() => (servers = servers.filter((_, i) => i !== index))}>✕</button>
      </div>
    {:else}
      <div class="empty-state">No MCP servers configured. Add one to audit MCP traffic.</div>
    {/each}
  </div>
</div>