<script lang="ts">
  import { onMount } from "svelte";
  import { Api, getServerInfo } from "./lib/api";
  import { auth, clearKey, validateKey } from "./lib/auth.svelte";
  import { go, router } from "./lib/router.svelte";
  import Login from "./pages/Login.svelte";
  import Overview from "./pages/Overview.svelte";
  import Requests from "./pages/Requests.svelte";
  import Tools from "./pages/Tools.svelte";
  import Substitutions from "./pages/Substitutions.svelte";
  import Providers from "./pages/Providers.svelte";
  import ConfigPage from "./pages/Config.svelte";
  import Overrides from "./pages/Overrides.svelte";
  import Mappings from "./pages/Mappings.svelte";
  import Sessions from "./pages/Sessions.svelte";

  const NAV = [
    { id: "overview", label: "Overview", icon: "▤" },
    { id: "requests", label: "Requests", icon: "⇄" },
    { id: "tools", label: "Tools & MCP", icon: "⌘" },
    { id: "substitutions", label: "Substitutions", icon: "⇋" },
    { id: "providers", label: "Providers", icon: "☁" },
    { id: "config", label: "Configuration", icon: "⚙" },
    { id: "overrides", label: "Overrides", icon: "⊘" },
    { id: "mappings", label: "Mappings", icon: "↔" },
    { id: "sessions", label: "Sessions", icon: "☰" },
  ];

  const views: Record<string, any> = {
    overview: Overview,
    requests: Requests,
    tools: Tools,
    substitutions: Substitutions,
    providers: Providers,
    config: ConfigPage,
    overrides: Overrides,
    mappings: Mappings,
    sessions: Sessions,
  };

  let server = $state({ mode: "…", version: "" });
  let toast = $state({ msg: "", error: false });
  let timer: ReturnType<typeof setTimeout> | undefined;

  const api = $derived(new Api(auth.key));
  const active = $derived(router.path.split("?")[0]);
  const Page = $derived(views[active] ?? Overview);

  function status(msg: string, isError = false): void {
    toast = { msg, error: isError };
    if (timer) clearTimeout(timer);
    timer = setTimeout(() => (toast = { msg: "", error: false }), 5000);
  }

  async function refreshServer(): Promise<void> {
    server = await getServerInfo();
  }

  function signOut(): void {
    clearKey();
    go("overview");
  }

  onMount(async () => {
    await refreshServer();
    if (auth.key) await validateKey();
  });
</script>

{#if auth.status !== "valid"}
  <Login {status} />
{:else}
  <div class="layout">
    <aside class="sidebar">
      <div class="brand">
        <span class="logo"></span>
        <div>
          <strong>Lono</strong>
          <small>Console</small>
        </div>
      </div>
      <nav>
        {#each NAV as item (item.id)}
          <button class={active === item.id ? "active" : ""} onclick={() => go(item.id)}>
            <span class="icon">{item.icon}</span>
            {item.label}
          </button>
        {/each}
      </nav>
      <div class="sidebar-foot">
        <span class="badge mode">{server.mode}</span>
        {#if server.version}<span class="muted">v{server.version}</span>{/if}
        <button class="ghost small" onclick={signOut}>Sign out</button>
      </div>
    </aside>

    <div class="content">
      <header class="topbar">
        <h1>{NAV.find((n) => n.id === active)?.label ?? "Overview"}</h1>
        <div class="spacer"></div>
        <a class="muted" href="http://127.0.0.1:3000" target="_blank" rel="noreferrer">Langfuse ↗</a>
      </header>
      <main>
        <Page {api} {status} {server} onRefreshServer={refreshServer} />
      </main>
    </div>
  </div>
{/if}

{#if toast.msg}
  <div class="toast" class:err={toast.error}>{toast.msg}</div>
{/if}