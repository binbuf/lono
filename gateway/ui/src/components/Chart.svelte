<script lang="ts">
  import { onMount } from "svelte";
  import { Chart, type ChartConfiguration } from "chart.js/auto";

  let { config, height = 240 }: { config: ChartConfiguration; height?: number } = $props();

  let canvas: HTMLCanvasElement;
  let chart: Chart | undefined;

  onMount(() => {
    chart = new Chart(canvas, config);
    return () => chart?.destroy();
  });

  $effect(() => {
    const next = config;
    if (!chart) return;
    chart.data = next.data;
    if (next.options) chart.options = next.options;
    chart.update("none");
  });
</script>

<div class="chart-wrap" style="height:{height}px">
  <canvas bind:this={canvas}></canvas>
</div>