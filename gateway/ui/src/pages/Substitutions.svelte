<script lang="ts">
  import { onMount } from "svelte";
  import type { Api, SecretRule, Substitution } from "../lib/api";

  let { api, status }: { api: Api; status: (msg: string, isError?: boolean) => void } = $props();

  let items = $state<Substitution[]>([]);
  let saving = $state(false);
  let draft = $state<Substitution>({
    id: "",
    pattern: "",
    replacement: "",
    match: "substring",
    case_sensitive: false,
    category: "SUBSTITUTION",
    enabled: true,
    note: "",
  });

  let rules = $state<SecretRule[]>([]);
  let ruleSaving = $state(false);
  let ruleEnvText = $state("");
  let ruleDraft = $state<SecretRule>({
    id: "",
    kind: "CUSTOM_SECRET",
    enabled: true,
    action: "mask",
    match: "regex",
    pattern: "",
    env_names: [],
    case_sensitive: true,
    note: "",
  });

  const SECRET_PRESETS: { label: string; match: SecretRule["match"]; kind: string; pattern?: string; env_names?: string[] }[] = [
    { label: "RunPod API key", match: "regex", kind: "RUNPOD_API_KEY", pattern: "\\brpa_[A-Za-z0-9]{20,}\\b" },
    { label: "Hugging Face token", match: "regex", kind: "HUGGINGFACE_TOKEN", pattern: "\\bhf_[A-Za-z0-9]{30,}\\b" },
    { label: "Groq API key", match: "regex", kind: "GROQ_API_KEY", pattern: "\\bgsk_[A-Za-z0-9]{40,}\\b" },
    { label: "Perplexity key", match: "regex", kind: "PERPLEXITY_API_KEY", pattern: "\\bpplx-[A-Za-z0-9]{40,}\\b" },
    { label: "OpenRouter key", match: "regex", kind: "OPENROUTER_API_KEY", pattern: "\\bsk-or-v1-[a-f0-9]{64}\\b" },
    { label: "Replicate token", match: "regex", kind: "REPLICATE_API_TOKEN", pattern: "\\br8_[A-Za-z0-9]{30,}\\b" },
    { label: "Slack webhook", match: "regex", kind: "SLACK_WEBHOOK", pattern: "https://hooks\\.slack\\.com/services/[A-Za-z0-9/]+" },
    { label: "Env var value", match: "env", kind: "ENV_SECRET", env_names: ["RUNPOD_API_KEY", "HF_TOKEN", "GITHUB_TOKEN"] },
  ];

  const PRESETS = [
    { label: "GitHub username", pattern: "github.com/youruser", replacement: "github.com/user" },
    { label: "Windows home path", pattern: "C:\\Users\\yourname", replacement: "/home/user" },
    { label: "macOS home path", pattern: "/Users/yourname", replacement: "/home/user" },
    { label: "Linux home path", pattern: "/home/yourname", replacement: "/home/user" },
    { label: "Email alias", pattern: "you@company.com", replacement: "user@example.com" },
  ];

  async function load(): Promise<void> {
    try {
      items = (await api.get<{ items: Substitution[] }>("/audit/substitutions")).items;
      rules = (await api.get<{ items: SecretRule[] }>("/audit/secret-rules")).items;
      status("");
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  async function create(): Promise<void> {
    if (!draft.pattern) {
      status("a pattern is required", true);
      return;
    }
    saving = true;
    try {
      await api.post("/audit/substitutions", { ...draft, id: undefined });
      status("substitution added");
      draft = { ...draft, pattern: "", replacement: "", note: "" };
      await load();
    } catch (error) {
      status((error as Error).message, true);
    } finally {
      saving = false;
    }
  }

  async function remove(id: string): Promise<void> {
    if (!confirm("Delete this substitution?")) return;
    try {
      await api.del(`/audit/substitutions/${id}`);
      status("substitution deleted");
      await load();
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  function applyPreset(preset: (typeof PRESETS)[number]): void {
    draft.pattern = preset.pattern;
    draft.replacement = preset.replacement;
    draft.match = "substring";
  }

  function applySecretPreset(preset: (typeof SECRET_PRESETS)[number]): void {
    ruleDraft.match = preset.match;
    ruleDraft.kind = preset.kind;
    ruleDraft.pattern = preset.pattern ?? "";
    ruleDraft.action = "mask";
    ruleEnvText = (preset.env_names ?? []).join(", ");
  }

  async function createRule(): Promise<void> {
    const isEnv = ruleDraft.match === "env";
    if (!isEnv && !ruleDraft.pattern) {
      status("a pattern is required", true);
      return;
    }
    if (isEnv && !ruleEnvText.trim()) {
      status("at least one env var name is required", true);
      return;
    }
    ruleSaving = true;
    try {
      await api.post("/audit/secret-rules", {
        ...ruleDraft,
        id: undefined,
        env_names: isEnv ? ruleEnvText.split(/[,\s]+/).filter(Boolean) : [],
        pattern: isEnv ? "" : ruleDraft.pattern,
      });
      status("detection rule added");
      ruleDraft = { ...ruleDraft, pattern: "", note: "" };
      ruleEnvText = "";
      await load();
    } catch (error) {
      status((error as Error).message, true);
    } finally {
      ruleSaving = false;
    }
  }

  async function removeRule(id: string): Promise<void> {
    if (!confirm("Delete this detection rule?")) return;
    try {
      await api.del(`/audit/secret-rules/${id}`);
      status("detection rule deleted");
      await load();
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  onMount(load);
</script>

<div class="page narrow">
  <p class="muted">
    Swap exact keywords for chosen values before they reach a provider — GitHub usernames, home directory paths,
    hostnames — and rehydrate them on the way back. Substitutions are reversible and persisted.
  </p>

  <div class="card">
    <h4>New substitution</h4>
    <div class="presets">
      {#each PRESETS as preset (preset.label)}
        <button class="ghost small" onclick={() => applyPreset(preset)}>{preset.label}</button>
      {/each}
    </div>
    <div class="form-row">
      <label>Pattern<input placeholder="C:\\Users\\youruser" bind:value={draft.pattern} /></label>
      <label>Replacement<input placeholder="/home/user" bind:value={draft.replacement} /></label>
    </div>
    <div class="form-row">
      <label>
        Match
        <select bind:value={draft.match}>
          <option value="substring">substring</option>
          <option value="word">whole word</option>
          <option value="regex">regex</option>
        </select>
      </label>
      <label>Category<input placeholder="SUBSTITUTION" bind:value={draft.category} /></label>
      <label class="check inline"><input type="checkbox" bind:checked={draft.case_sensitive} /> case sensitive</label>
    </div>
    <label>Note<input placeholder="why this exists" bind:value={draft.note} /></label>
    <div class="row end">
      <button class="primary" onclick={create} disabled={saving}>{saving ? "Saving…" : "Add substitution"}</button>
    </div>
  </div>

  <div class="card">
    <h4>Active substitutions ({items.length})</h4>
    {#if items.length}
      <table class="grid">
        <thead>
          <tr><th>pattern</th><th>replacement</th><th>match</th><th>category</th><th></th></tr>
        </thead>
        <tbody>
          {#each items as item (item.id)}
            <tr>
              <td class="mono wrap">{item.pattern}</td>
              <td class="mono wrap">{item.replacement}</td>
              <td>{item.match}{item.case_sensitive ? " · cs" : ""}</td>
              <td>{item.category}</td>
              <td class="right"><button class="danger small" onclick={() => remove(item.id)}>Delete</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <div class="empty-state">No substitutions configured.</div>
    {/if}
  </div>

  <div class="card">
    <h4>Secret detection rules</h4>
    <p class="muted small">
      Detectors ship with high-confidence patterns for popular providers. Add your own exact keys,
      environment-variable names, or regex patterns here — matched values are masked before egress.
      Override the action per rule when you need to flag or block instead.
    </p>
    <div class="presets">
      {#each SECRET_PRESETS as preset (preset.label)}
        <button class="ghost small" onclick={() => applySecretPreset(preset)}>{preset.label}</button>
      {/each}
    </div>
    <div class="form-row">
      <label>Category<input placeholder="CUSTOM_SECRET" bind:value={ruleDraft.kind} /></label>
      <label>
        Match
        <select bind:value={ruleDraft.match}>
          <option value="regex">regex</option>
          <option value="word">whole word</option>
          <option value="substring">substring</option>
          <option value="env">env var name(s)</option>
        </select>
      </label>
      <label>
        Action
        <select bind:value={ruleDraft.action}>
          <option value={null}>detector default</option>
          <option value="mask">mask</option>
          <option value="flag">flag</option>
          <option value="block">block</option>
        </select>
      </label>
    </div>
    {#if ruleDraft.match === "env"}
      <label
        >Env var names (comma separated)<input placeholder="RUNPOD_API_KEY, HF_TOKEN" bind:value={ruleEnvText} /></label
      >
    {:else}
      <label>Pattern<input placeholder={"\\bkey_[A-Za-z0-9]{20,}\\b"} bind:value={ruleDraft.pattern} /></label>
    {/if}
    <div class="form-row">
      <label class="check inline"><input type="checkbox" bind:checked={ruleDraft.case_sensitive} /> case sensitive</label>
      <label class="grow">Note<input placeholder="why this exists" bind:value={ruleDraft.note} /></label>
    </div>
    <div class="row end">
      <button class="primary" onclick={createRule} disabled={ruleSaving}
        >{ruleSaving ? "Saving…" : "Add detection rule"}</button
      >
    </div>

    {#if rules.length}
      <table class="grid compact">
        <thead>
          <tr><th>category</th><th>match</th><th>pattern / env var</th><th>action</th><th></th></tr>
        </thead>
        <tbody>
          {#each rules as rule (rule.id)}
            <tr>
              <td><span class="pill kind">{rule.kind}</span></td>
              <td>{rule.match}</td>
              <td class="mono wrap">{rule.match === "env" ? rule.env_names.join(", ") : rule.pattern}</td>
              <td>{rule.action ?? "default"}</td>
              <td class="right"><button class="danger small" onclick={() => removeRule(rule.id)}>Delete</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    {:else}
      <div class="empty-state">No custom detection rules configured.</div>
    {/if}
  </div>
</div>