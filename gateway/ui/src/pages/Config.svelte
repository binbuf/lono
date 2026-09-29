<script lang="ts">
  import { onMount } from "svelte";
  import type { Api, ConfigSnapshot } from "../lib/api";
  import { prettyJson } from "../lib/format";

  let {
    api,
    status,
    onRefreshServer,
  }: { api: Api; status: (msg: string, isError?: boolean) => void; onRefreshServer?: () => void } = $props();

  let snapshot = $state<ConfigSnapshot | null>(null);
  let draft = $state<Record<string, any>>({});
  let saving = $state(false);
  let showRaw = $state(false);

  async function load(): Promise<void> {
    try {
      snapshot = await api.get<ConfigSnapshot>("/audit/config");
      draft = structuredClone($state.snapshot(snapshot)) as Record<string, any>;
      status("");
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  async function save(): Promise<void> {
    saving = true;
    try {
      const patch = {
        mode: draft.mode,
        fail_closed: draft.fail_closed,
        allow_client_mode_override: draft.allow_client_mode_override,
        inspect_tools: draft.inspect_tools,
        detectors: draft.detectors,
        output_scan: draft.output_scan,
        pseudonymization: { stable_across_sessions: draft.pseudonymization?.stable_across_sessions },
        overrides: draft.overrides,
        audit: {
          enabled: draft.audit?.enabled,
          capture_original: draft.audit?.capture_original,
          retention_days: Number(draft.audit?.retention_days) || 0,
          max_payload_bytes: Number(draft.audit?.max_payload_bytes) || 0,
        },
      };
      await api.patch("/audit/config", patch);
      status("configuration saved");
      await load();
      onRefreshServer?.();
    } catch (error) {
      status((error as Error).message, true);
    } finally {
      saving = false;
    }
  }

  onMount(load);
</script>

<div class="page">
  <div class="toolbar">
    <button class="primary" onclick={save} disabled={saving || !snapshot}>{saving ? "Saving…" : "Save changes"}</button>
    <button class="ghost" onclick={load}>Reload</button>
    <div class="spacer"></div>
    <button class="ghost small" onclick={() => (showRaw = !showRaw)}>{showRaw ? "hide" : "show"} raw config</button>
  </div>
  <p class="muted small">
    Changes apply live and persist to <code>runtime_config.json</code>. Secrets, auth keys and media credentials are
    never exposed or editable here.
  </p>

  {#if snapshot}
    <div class="config-grid">
      <section class="card">
        <h4>General</h4>
        <label class="field">Mode
          <select bind:value={draft.mode}>
            <option value="observe">observe — log only</option>
            <option value="sanitize">sanitize — mask &amp; pseudonymize</option>
            <option value="enforce">enforce — block policy violations</option>
          </select>
        </label>
        <label class="check"><input type="checkbox" bind:checked={draft.fail_closed} /> fail closed when a detector is unavailable</label>
        <label class="check"><input type="checkbox" bind:checked={draft.allow_client_mode_override} /> allow client mode override header</label>
        <label class="check"><input type="checkbox" bind:checked={draft.inspect_tools} /> inspect tool descriptions</label>
        <label class="check"><input type="checkbox" bind:checked={draft.pseudonymization.stable_across_sessions} /> stable pseudonyms across sessions</label>
      </section>

      <section class="card">
        <h4>Secrets</h4>
        <label class="check"><input type="checkbox" bind:checked={draft.detectors.secrets.enabled} /> enabled</label>
        <label class="field">Action
          <select bind:value={draft.detectors.secrets.action}>
            <option value="mask">mask</option><option value="flag">flag</option><option value="block">block</option>
          </select>
        </label>
        <label class="check"><input type="checkbox" bind:checked={draft.detectors.secrets.entropy} /> entropy heuristic</label>
        <label class="field">Entropy action
          <select bind:value={draft.detectors.secrets.entropy_action}>
            <option value="flag">flag</option><option value="mask">mask</option>
          </select>
        </label>
        <label class="field">Entropy threshold<input type="number" step="0.1" bind:value={draft.detectors.secrets.entropy_threshold} /></label>
        <label class="field">Entropy min length<input type="number" bind:value={draft.detectors.secrets.entropy_min_length} /></label>
        <fieldset class="group">
          <legend>Key material</legend>
          <label class="check"><input type="checkbox" bind:checked={draft.detectors.secrets.key_material.enabled} /> enabled</label>
          <label class="field">Action
            <select bind:value={draft.detectors.secrets.key_material.action}>
              <option value="mask">mask</option><option value="flag">flag</option><option value="block">block</option>
            </select>
          </label>
          <label class="check"><input type="checkbox" bind:checked={draft.detectors.secrets.key_material.private_keys} /> private keys (PEM/OpenSSH/encrypted)</label>
          <label class="check"><input type="checkbox" bind:checked={draft.detectors.secrets.key_material.public_keys} /> SSH public keys</label>
          <label class="check"><input type="checkbox" bind:checked={draft.detectors.secrets.key_material.gpg} /> OpenPGP (GPG) blocks</label>
          <label class="check"><input type="checkbox" bind:checked={draft.detectors.secrets.key_material.putty} /> PuTTY .ppk files</label>
        </fieldset>
      </section>

      <section class="card">
        <h4>PII</h4>
        <label class="check"><input type="checkbox" bind:checked={draft.detectors.pii.enabled} /> enabled</label>
        <label class="field">Engine
          <select bind:value={draft.detectors.pii.engine}>
            <option value="auto">auto</option><option value="presidio">presidio</option><option value="regex">regex</option>
          </select>
        </label>
        <label class="field">Default action<input bind:value={draft.detectors.pii.default_action} /></label>
        <label class="field">Score threshold<input type="number" step="0.05" bind:value={draft.detectors.pii.score_threshold} /></label>
        <label class="check"><input type="checkbox" bind:checked={draft.detectors.pii.filter_technical} /> filter technical name false positives</label>
        <details class="actions-editor">
          <summary>Entity actions ({Object.keys(draft.detectors.pii.actions ?? {}).length})</summary>
          {#each Object.entries(draft.detectors.pii.actions ?? {}) as [entity, action] (entity)}
            <label class="field entity-row">
              <span class="mono">{entity}</span>
              <select bind:value={draft.detectors.pii.actions[entity]}>
                <option value="pseudonymize">pseudonymize</option>
                <option value="mask">mask</option>
                <option value="flag">flag</option>
              </select>
            </label>
          {/each}
        </details>
      </section>

      <section class="card">
        <h4>Injection</h4>
        <label class="check"><input type="checkbox" bind:checked={draft.detectors.injection.enabled} /> enabled</label>
        <label class="field">Action
          <select bind:value={draft.detectors.injection.action}><option value="flag">flag</option><option value="block">block</option></select>
        </label>
        <label class="field">Flag threshold<input type="number" step="0.05" bind:value={draft.detectors.injection.flag_threshold} /></label>
        <label class="field">Block threshold<input type="number" step="0.05" bind:value={draft.detectors.injection.block_threshold} /></label>
      </section>

      <section class="card">
        <h4>URLs</h4>
        <label class="check"><input type="checkbox" bind:checked={draft.detectors.urls.enabled} /> enabled</label>
        <label class="field">Action
          <select bind:value={draft.detectors.urls.action}><option value="flag">flag</option><option value="block">block</option></select>
        </label>
        <label class="field">Block threshold<input type="number" step="0.05" bind:value={draft.detectors.urls.block_threshold} /></label>
      </section>

      <section class="card">
        <h4>Output scan</h4>
        <label class="check"><input type="checkbox" bind:checked={draft.output_scan.enabled} /> enabled</label>
        <label class="check"><input type="checkbox" bind:checked={draft.output_scan.secrets} /> secrets</label>
        <label class="check"><input type="checkbox" bind:checked={draft.output_scan.injection} /> injection</label>
        <label class="check"><input type="checkbox" bind:checked={draft.output_scan.pii} /> PII</label>
        <label class="check"><input type="checkbox" bind:checked={draft.output_scan.watchlist} /> watchlist</label>
        <label class="field">Action
          <select bind:value={draft.output_scan.action}><option value="flag">flag</option><option value="mask">mask</option></select>
        </label>
      </section>

      <section class="card">
        <h4>Overrides</h4>
        <label class="check"><input type="checkbox" bind:checked={draft.overrides.enabled} /> enabled</label>
        <label class="field">Default max minutes<input type="number" bind:value={draft.overrides.default_max_minutes} /></label>
        <label class="field">Cache seconds<input type="number" step="0.5" bind:value={draft.overrides.cache_seconds} /></label>
        <label class="check"><input type="checkbox" bind:checked={draft.overrides.allow_permanent} /> allow permanent overrides</label>
      </section>

      <section class="card">
        <h4>Audit</h4>
        <label class="check"><input type="checkbox" bind:checked={draft.audit.enabled} /> enabled</label>
        <label class="check"><input type="checkbox" bind:checked={draft.audit.capture_original} /> capture original payloads</label>
        <label class="field">Retention days (0 = forever)<input type="number" bind:value={draft.audit.retention_days} /></label>
        <label class="field">Max payload bytes<input type="number" bind:value={draft.audit.max_payload_bytes} /></label>
      </section>
    </div>

    {#if showRaw}
      <div class="card">
        <h4>Raw configuration (redacted)</h4>
        <pre class="stage">{prettyJson(snapshot)}</pre>
      </div>
    {/if}
  {:else}
    <div class="empty-state">Loading configuration…</div>
  {/if}
</div>