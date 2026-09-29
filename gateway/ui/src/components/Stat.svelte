<script lang="ts">
  let {
    label,
    value,
    sub,
    tone,
  }: { label: string; value: string; sub?: string; tone?: "good" | "warn" | "err" | "info" } = $props();
</script>

<div class="stat" class:good={tone === "good"} class:warn={tone === "warn"} class:err={tone === "err"} class:info={tone === "info"}>
  <div class="label">{label}</div>
  <div class="value">{value}</div>
  {#if sub}<div class="sub">{sub}</div>{/if}
</div>