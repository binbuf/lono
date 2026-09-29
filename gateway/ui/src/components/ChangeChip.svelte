<script lang="ts">
  let {
    kind,
    before,
    after,
    action,
    reveal = false,
    onclick,
  }: {
    kind: string;
    before: string | null;
    after: string | null;
    action?: string;
    reveal?: boolean;
    onclick?: () => void;
  } = $props();

  const blocked = $derived(action === "blocked");
</script>

<button class="chip" class:blocked onclick={onclick} title={`${kind}${action ? ` · ${action}` : ""}`}>
  <span class="chip-kind">{kind}</span>
  <span class="chip-before" class:blur={!reveal}>{before ?? "…"}</span>
  <span class="chip-arrow">→</span>
  <span class="chip-after" class:blur={!reveal}>{after ?? ""}</span>
</button>