import type { ChartConfiguration, ChartDataset } from "chart.js/auto";
import { color } from "./format";

const GRID = "rgba(255,255,255,0.07)";
const TEXT = "#9fb0c3";

function base(showLegend = false): ChartConfiguration["options"] {
  return {
    responsive: true,
    maintainAspectRatio: false,
    interaction: { mode: "index", intersect: false },
    plugins: {
      legend: {
        display: showLegend,
        labels: { color: TEXT, boxWidth: 12, boxHeight: 12, usePointStyle: true },
      },
      tooltip: {
        backgroundColor: "rgba(15,20,28,0.95)",
        borderColor: "rgba(255,255,255,0.1)",
        borderWidth: 1,
        padding: 10,
      },
    },
    scales: {
      x: {
        grid: { color: GRID },
        ticks: { color: TEXT, maxRotation: 0, autoSkip: true, maxTicksLimit: 10 },
      },
      y: {
        grid: { color: GRID },
        ticks: { color: TEXT },
        beginAtZero: true,
      },
    },
  };
}

export interface Series {
  name: string;
  color?: string;
  values: number[];
}

export function lineConfig(labels: string[], series: Series[], fill = true): ChartConfiguration {
  const datasets: ChartDataset[] = series.map((s, i) => ({
    label: s.name,
    data: s.values,
    borderColor: s.color || color(i),
    backgroundColor: (s.color || color(i)) + "22",
    fill,
    borderWidth: 2,
    pointRadius: 0,
    pointHoverRadius: 4,
    tension: 0.32,
  }));
  return { type: "line", data: { labels, datasets }, options: base(series.length > 1) };
}

export function barConfig(labels: string[], values: number[], horizontal = false, tone?: string): ChartConfiguration {
  return {
    type: "bar",
    data: {
      labels,
      datasets: [
        {
          label: "count",
          data: values,
          backgroundColor: tone || color(0),
          borderRadius: 4,
          maxBarThickness: 26,
        },
      ],
    },
    options: {
      ...base(false),
      indexAxis: horizontal ? ("y" as const) : ("x" as const),
      plugins: { legend: { display: false } },
    },
  };
}

export function doughnutConfig(labels: string[], values: number[]): ChartConfiguration {
  const options: Record<string, unknown> = {
    responsive: true,
    maintainAspectRatio: false,
    cutout: "62%",
    plugins: {
      legend: { position: "right", labels: { color: TEXT, boxWidth: 10, usePointStyle: true } },
    },
  };
  return {
    type: "doughnut",
    data: {
      labels,
      datasets: [
        {
          data: values,
          backgroundColor: labels.map((_, i) => color(i)),
          borderColor: "#0e131b",
          borderWidth: 2,
        },
      ],
    },
    options,
  } as ChartConfiguration;
}