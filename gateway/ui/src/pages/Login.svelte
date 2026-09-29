<script lang="ts">
  import { auth, saveKey, validateKey } from "../lib/auth.svelte";

  let { status }: { status: (msg: string, isError?: boolean) => void } = $props();

  let draft = $state(auth.key);
  let busy = $state(false);
  let error = $state("");

  async function submit(): Promise<void> {
    if (!draft.trim()) {
      error = "Enter the admin key";
      return;
    }
    saveKey(draft);
    busy = true;
    error = "";
    const ok = await validateKey();
    busy = false;
    if (!ok) {
      error = auth.error || "Invalid admin key";
    } else {
      status("Signed in");
    }
  }
</script>

<div class="login">
  <form class="login-card" onsubmit={(e) => (e.preventDefault(), submit())}>
    <div class="brand large">
      <span class="logo"></span>
      <div>
        <strong>Lono</strong>
        <small>AI security &amp; audit console</small>
      </div>
    </div>

    <p class="muted">
      The console is a management surface for the gateway. Sign in with
      <code>LONO_ADMIN_KEY</code> from your <code>.env</code>. The key is stored only in this browser.
    </p>

    <label for="key">Admin key</label>
    <input
      id="key"
      type="password"
      autocomplete="off"
      placeholder="LONO_ADMIN_KEY"
      bind:value={draft}
      disabled={busy}
    />

    {#if error}<div class="error-banner">{error}</div>{/if}

    <button class="primary wide" type="submit" disabled={busy}>
      {busy ? "Checking…" : "Sign in"}
    </button>
  </form>
</div>