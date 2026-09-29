<script lang="ts">
  import { onMount, tick } from "svelte";
  import type { Api, Finding, RequestDetail, ToolEvent } from "../lib/api";
  import { fmtCost, fmtDuration, fmtTime, fmtNumber, prettyJson } from "../lib/format";
  import { goQuery } from "../lib/router.svelte";

  let {
    api,
    id,
    onClose,
    status,
  }: {
    api: Api;
    id: string;
    onClose: () => void;
    status: (msg: string, isError?: boolean) => void;
  } = $props();

  const TRANSFORMED = new Set(["pseudonymized", "masked", "stripped"]);

  let record = $state<RequestDetail | null>(null);
  let tools = $state<ToolEvent[]>([]);
  let tab = $state<"values" | "detections" | "original" | "sanitized" | "raw" | "final">("values");
  let reveal = $state(false);

  async function load(): Promise<void> {
    try {
      record = await api.get<RequestDetail>(`/audit/requests/${id}`);
      const all = record.findings ?? [];
      // Surface detections immediately when nothing was actually rewritten.
      if (!all.some((f) => TRANSFORMED.has(f.action)) && all.length) tab = "detections";
      const toolData = await api.get<{ items: ToolEvent[] }>(`/audit/tools?request_id=${id}&limit=200`);
      tools = toolData.items;
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  async function remove(): Promise<void> {
    if (!confirm("Delete this request record and its tool events?")) return;
    try {
      await api.del(`/audit/requests/${id}`);
      status("request deleted");
      onClose();
    } catch (error) {
      status((error as Error).message, true);
    }
  }

  onMount(load);

  const findings = $derived(record?.findings ?? []);
  const changed = $derived(findings.filter((f) => TRANSFORMED.has(f.action)));

  function replacementText(finding: Finding): string {
    if (finding.replacement) return finding.replacement;
    if (TRANSFORMED.has(finding.action)) return "(removed)";
    return "(not modified)";
  }

  function stage(value: unknown): string {
    return prettyJson(value) || "(empty)";
  }

  // ------------------------------------------------------------- dedupe

  interface Counted<T> {
    item: T;
    count: number;
  }

  function dedupe<T>(items: T[], key: (item: T) => string): Counted<T>[] {
    const seen = new Map<string, Counted<T>>();
    for (const item of items) {
      const id = key(item);
      const existing = seen.get(id);
      if (existing) existing.count += 1;
      else seen.set(id, { item, count: 1 });
    }
    return [...seen.values()];
  }

  const changedUnique = $derived(
    dedupe(changed, (f) => `${f.kind}\u0000${f.before ?? ""}\u0000${f.replacement ?? ""}`),
  );
  const findingsUnique = $derived(
    dedupe(findings, (f) => `${f.kind}\u0000${f.detector}\u0000${f.action}\u0000${f.before ?? ""}\u0000${f.replacement ?? ""}`),
  );

  // ------------------------------------------------------------- diffing

  type DiffKind = "equal" | "del" | "ins";
  interface DiffSeg {
    text: string;
    kind: DiffKind;
  }
  interface DiffRow {
    segments: DiffSeg[];
    region: number;
  }

  let diffRows = $state<DiffRow[]>([]);
  let regionCount = $state(0);
  let changeIndex = $state(0);

  function tokenize(text: string): string[] {
    return text.match(/[A-Za-z0-9_-]+|\s+|[^\sA-Za-z0-9_-]/g) ?? [];
  }

  function lcsDiff(a: string[], b: string[]): DiffSeg[] {
    const n = a.length;
    const m = b.length;
    const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
    for (let i = n - 1; i >= 0; i--) {
      for (let j = m - 1; j >= 0; j--) {
        dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
      }
    }
    const segs: DiffSeg[] = [];
    const push = (text: string, kind: DiffKind) => {
      if (!text) return;
      const last = segs[segs.length - 1];
      if (last && last.kind === kind) last.text += text;
      else segs.push({ text, kind });
    };
    let i = 0;
    let j = 0;
    while (i < n && j < m) {
      if (a[i] === b[j]) push(a[i++], "equal");
      else if (dp[i + 1][j] >= dp[i][j + 1]) push(a[i++], "del");
      else push(b[j++], "ins");
    }
    while (i < n) push(a[i++], "del");
    while (j < m) push(b[j++], "ins");
    return segs;
  }

  function diffSegments(before: string, after: string): DiffSeg[] {
    // Trim the shared prefix/suffix so only the changed middle is LCS-diffed.
    let start = 0;
    while (start < before.length && start < after.length && before[start] === after[start]) start++;
    let endBefore = before.length;
    let endAfter = after.length;
    while (endBefore > start && endAfter > start && before[endBefore - 1] === after[endAfter - 1]) {
      endBefore--;
      endAfter--;
    }
    const segs: DiffSeg[] = [];
    const push = (text: string, kind: DiffKind) => {
      if (!text) return;
      const last = segs[segs.length - 1];
      if (last && last.kind === kind) last.text += text;
      else segs.push({ text, kind });
    };
    push(before.slice(0, start), "equal");
    const midBefore = tokenize(before.slice(start, endBefore));
    const midAfter = tokenize(after.slice(start, endAfter));
    if (midBefore.length * midAfter.length > 1_000_000) {
      push(before.slice(start, endBefore), "del");
      push(after.slice(start, endAfter), "ins");
    } else {
      for (const seg of lcsDiff(midBefore, midAfter)) push(seg.text, seg.kind);
    }
    push(before.slice(endBefore), "equal");
    return segs;
  }

  function buildDiff(): void {
    if (!record) return;
    const before = prettyJson(record.request_original);
    const after = prettyJson(record.request_sanitized);
    if (!before || !after) {
      diffRows = [];
      regionCount = 0;
      return;
    }
    const a = before.split("\n");
    const b = after.split("\n");
    const total = Math.max(a.length, b.length);
    const rows: DiffRow[] = [];
    let regions = 0;
    for (let i = 0; i < total; i++) {
      const la = a[i] ?? "";
      const lb = b[i] ?? "";
      if (la === lb) rows.push({ segments: [{ text: la, kind: "equal" }], region: -1 });
      else rows.push({ segments: diffSegments(la, lb), region: regions++ });
    }
    diffRows = rows;
    regionCount = regions;
    changeIndex = 0;
  }

  function escapeHtml(text: string): string {
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  }

  const diffHtml = $derived.by(() => {
    const parts: string[] = [];
    for (const row of diffRows) {
      if (row.region < 0) {
        parts.push(escapeHtml(row.segments[0]?.text ?? "") + "\n");
        continue;
      }
      const current = row.region === changeIndex ? " current" : "";
      parts.push(`<span class="diff-region${current}" id="diff-region-${row.region}">`);
      for (const seg of row.segments) {
        if (seg.kind === "equal") parts.push(escapeHtml(seg.text));
        else if (seg.kind === "del") parts.push(`<span class="del">${escapeHtml(seg.text)}</span>`);
        else parts.push(`<span class="ins">${escapeHtml(seg.text)}</span>`);
      }
      parts.push("</span>\n");
    }
    return parts.join("");
  });

  async function goChange(delta: number): Promise<void> {
    if (!regionCount) return;
    changeIndex = (changeIndex + delta + regionCount) % regionCount;
    await tick();
    document.getElementById(`diff-region-${changeIndex}`)?.scrollIntoView({ behavior: "smooth", block: "center" });
  }

  $effect(() => {
    if (tab === "sanitized" && record) buildDiff();
  });
</script>

<div class="drawer-backdrop" onclick={onClose} role="presentation"></div>
<div class="drawer">
  <header class="drawer-head">
    <div>
      <strong>{record?.method} {record?.path}</strong>
      <div class="muted mono small">{id}</div>
    </div>
    <div class="spacer"></div>
    <button class="ghost small" onclick={() => (reveal = !reveal)}>{reveal ? "hide values" : "reveal values"}</button>
    <button class="danger small" onclick={remove}>Delete</button>
    <button class="ghost small" onclick={onClose}>✕</button>
  </header>

  {#if record}
    <div class="meta-grid">
      <span><b>time</b>{fmtTime(record.created_at)}</span>
      <span><b>status</b>{record.status}{record.blocked ? " (blocked)" : ""}</span>
      <span><b>model</b>{record.model ?? "—"}</span>
      <span><b>provider</b>{record.provider ?? "—"}</span>
      <span><b>shape</b>{record.api_shape}</span>
      <span><b>mode</b>{record.mode}</span>
      <span><b>session</b><span class="mono">{record.session_id ?? "—"}</span></span>
      <span>
        <b>client</b>
        {#if record.client_key}
          <button
            class="link mono"
            title={record.client_key}
            onclick={() => record && goQuery("requests", { client: record.client_key })}
          >{record.client_label || record.client_key.slice(0, 14)}</button>
        {:else}
          <span class="muted">—</span>
        {/if}
      </span>
      <span><b>latency</b>{fmtDuration(record.latency_ms)}</span>
      <span><b>tokens</b>{fmtNumber(record.total_tokens)} ({fmtNumber(record.prompt_tokens)} in / {fmtNumber(record.completion_tokens)} out)</span>
      <span><b>cost</b>{fmtCost(record.cost_usd)}</span>
      {#if record.error}<span class="err"><b>error</b>{record.error}</span>{/if}
    </div>

    <nav class="subtabs">
      <button class={tab === "values" ? "active" : ""} onclick={() => (tab = "values")}>
        Values ({changedUnique.length})
      </button>
      <button class={tab === "detections" ? "active" : ""} onclick={() => (tab = "detections")}>
        Detections ({findingsUnique.length})
      </button>
      <button class={tab === "original" ? "active" : ""} onclick={() => (tab = "original")}>Original</button>
      <button class={tab === "sanitized" ? "active" : ""} onclick={() => (tab = "sanitized")}>Sanitized</button>
      <button class={tab === "raw" ? "active" : ""} onclick={() => (tab = "raw")}>Raw response</button>
      <button class={tab === "final" ? "active" : ""} onclick={() => (tab = "final")}>Final response</button>
    </nav>

    <div class="drawer-body">
      {#if tab === "values"}
        {#if changedUnique.length}
          <div class="values-bar">
            <span class="muted small">
              {changedUnique.length} unique value{changedUnique.length === 1 ? "" : "s"}
              {changed.length !== changedUnique.length ? `(${changed.length} occurrences)` : ""}
              <b class="val-detected-text">detected</b> in the request and
              <b class="val-replaced-text">replaced</b> before it reached the provider. Sensitive values stay hidden
              until revealed.
            </span>
            <button class="small" onclick={() => (reveal = !reveal)}>
              {reveal ? "Hide sensitive values" : "Reveal sensitive values"}
            </button>
          </div>
          <table class="grid compact values-table">
            <thead>
              <tr>
                <th>category</th>
                <th>detected value</th>
                <th>replaced with</th>
              </tr>
            </thead>
            <tbody>
              {#each changedUnique as entry, index (index)}
                <tr>
                  <td>
                    <span class="pill kind">{entry.item.kind}</span>
                    {#if entry.count > 1}<span class="count-badge">×{entry.count}</span>{/if}
                    <div class="muted small">{entry.item.detector} · {entry.item.action}</div>
                  </td>
                  <td class="val val-detected">
                    <button
                      class="val-btn"
                      title={reveal ? "click to hide sensitive value" : "click to reveal sensitive value"}
                      onclick={() => (reveal = !reveal)}
                    >
                      <span class:blur={!reveal}>{entry.item.before ?? "—"}</span>
                    </button>
                  </td>
                  <td class="val val-replaced"><span>{replacementText(entry.item)}</span></td>
                </tr>
              {/each}
            </tbody>
          </table>
        {:else}
          <div class="empty-state">No values were rewritten for this request.</div>
        {/if}
      {:else if tab === "detections"}
        {#if findingsUnique.length}
          <p class="muted small">
            Unique detections for this request, including spans that were only flagged or observed and left unchanged.
            Detected values stay hidden until revealed.
          </p>
          <table class="grid compact values-table">
            <thead>
              <tr>
                <th>category</th>
                <th>detector</th>
                <th>action</th>
                <th>detected value</th>
                <th>replaced with</th>
              </tr>
            </thead>
            <tbody>
              {#each findingsUnique as entry, index (index)}
                <tr>
                  <td>
                    <span class="pill kind">{entry.item.kind}</span>
                    {#if entry.count > 1}<span class="count-badge">×{entry.count}</span>{/if}
                  </td>
                  <td class="muted">{entry.item.detector}</td>
                  <td><span class="pill act">{entry.item.action}</span></td>
                  <td class="val val-detected">
                    <button
                      class="val-btn"
                      title={reveal ? "click to hide sensitive value" : "click to reveal sensitive value"}
                      onclick={() => (reveal = !reveal)}
                    >
                      <span class:blur={!reveal}>{entry.item.before ?? "—"}</span>
                    </button>
                  </td>
                  <td class="val val-replaced"><span>{replacementText(entry.item)}</span></td>
                </tr>
              {/each}
            </tbody>
          </table>
        {:else}
          <div class="empty-state">No detections for this request.</div>
        {/if}
      {:else if tab === "sanitized"}
        {#if record.has_original && regionCount > 0}
          <div class="diff-bar">
            <span class="muted small">
              <b class="del-text">struck-through</b> text is what the client sent; the
              <b class="ins-text">green</b> text is what the provider received.
            </span>
            <div class="spacer"></div>
            <button class="small" onclick={() => goChange(-1)} disabled={regionCount === 0}>‹ prev</button>
            <span class="muted small mono">{regionCount ? changeIndex + 1 : 0} / {regionCount}</span>
            <button class="small" onclick={() => goChange(1)} disabled={regionCount === 0}>next ›</button>
          </div>
          <pre class="stage diff">{@html diffHtml}</pre>
        {:else}
          <p class="muted small">
            {record.has_original ? "No inline changes to show." : "Original request was not captured — cannot diff."}
          </p>
          <pre class="stage">{stage(record.request_sanitized)}</pre>
        {/if}
      {:else}
        <pre class="stage">{stage(
          tab === "original" ? record.request_original : tab === "raw" ? record.response_raw : record.response_final,
        )}</pre>
      {/if}

      {#if tools.length}
        <h4>Tool activity</h4>
        <table class="grid compact">
          <thead>
            <tr><th>time</th><th>tool</th><th>kind</th><th>command / args</th></tr>
          </thead>
          <tbody>
            {#each tools as tool (tool.id)}
              <tr>
                <td class="mono">{fmtTime(tool.created_at)}</td>
                <td>{tool.tool_name ?? "—"}</td>
                <td>{tool.source}/{tool.kind}</td>
                <td class="mono wrap">
                  {#if tool.is_command}<span class="cmd">{tool.command}</span>{:else}{tool.command ?? tool.arguments ?? tool.preview ?? ""}{/if}
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      {/if}

      {#if record.client_meta && Object.keys(record.client_meta).length}
        <h4>Incoming HTTP</h4>
        <p class="muted small">
          Headers captured from the client's request. Credential headers are never stored.
        </p>
        <table class="grid compact">
          <thead><tr><th>header</th><th>value</th></tr></thead>
          <tbody>
            {#each Object.entries(record.client_meta) as [key, value] (key)}
              <tr><td class="mono">{key}</td><td class="mono wrap">{value}</td></tr>
            {/each}
          </tbody>
        </table>
      {/if}
    </div>
  {:else}
    <div class="empty-state">Loading…</div>
  {/if}
</div>