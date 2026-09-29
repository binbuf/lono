import type { Finding } from "./api";

export function pretty(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") {
    try {
      return JSON.stringify(JSON.parse(value), null, 2);
    } catch {
      return value;
    }
  }
  return JSON.stringify(value, null, 2);
}

export function fmtTime(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export function fmtClock(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (isNaN(d.getTime())) return iso;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

export function fmtNumber(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (Math.abs(value) >= 1_000_000) return (value / 1_000_000).toFixed(2) + "M";
  if (Math.abs(value) >= 1_000) return (value / 1_000).toFixed(1) + "k";
  return String(value);
}

export function fmtCost(value: number | null | undefined): string {
  if (value === null || value === undefined) return "—";
  if (value === 0) return "$0";
  if (value < 0.01) return "$" + value.toFixed(4);
  return "$" + value.toFixed(2);
}

export function fmtDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return "—";
  if (ms < 1000) return ms + " ms";
  return (ms / 1000).toFixed(2) + " s";
}

export function parseJsonish(value: unknown): unknown {
  if (value === null || value === undefined) return null;
  if (typeof value === "object") return value;
  if (typeof value !== "string" || !value.trim()) return null;
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

export function textFromContent(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  const parts: string[] = [];
  for (const part of content) {
    if (typeof part === "string") {
      parts.push(part);
      continue;
    }
    if (!part || typeof part !== "object") continue;
    const p = part as Record<string, unknown>;
    if (p.type === "text" && typeof p.text === "string") parts.push(p.text);
    else if (p.type === "thinking" && typeof p.thinking === "string") parts.push(p.thinking);
    else if (p.type === "tool_use") parts.push(`[tool ${p.name}(${JSON.stringify(p.input)})]`);
    else if (p.type === "tool_result") {
      const inner = textFromContent(p.content);
      if (inner) parts.push(inner);
    }
  }
  return parts.join("\n");
}

export interface Message {
  role: string;
  text: string;
}

export function extractRequestMessages(payloadText: unknown): Message[] {
  const payload = parseJsonish(payloadText) as Record<string, unknown> | null;
  const out: Message[] = [];
  if (!payload) return out;
  if (typeof payload.system === "string" && payload.system) out.push({ role: "system", text: payload.system });
  else if (Array.isArray(payload.system)) {
    const t = textFromContent(payload.system);
    if (t) out.push({ role: "system", text: t });
  }
  for (const raw of (payload.messages as unknown[]) || []) {
    if (!raw || typeof raw !== "object") continue;
    const m = raw as Record<string, unknown>;
    let text = textFromContent(m.content);
    const calls = ((m.tool_calls as unknown[]) || [])
      .map((tc) => {
        const fn = ((tc as Record<string, unknown>)?.function as Record<string, unknown>) || {};
        return `[tool ${fn.name || ""}(${fn.arguments || ""})]`;
      })
      .join("\n");
    if (calls) text = [text, calls].filter(Boolean).join("\n");
    out.push({ role: (m.role as string) || "?", text });
  }
  if (!out.length && typeof payload.prompt === "string" && payload.prompt) out.push({ role: "prompt", text: payload.prompt });
  if (!out.length && typeof payload.input === "string" && payload.input) out.push({ role: "input", text: payload.input });
  return out;
}

function extractResponseObject(payloadText: unknown): { text: string; thinking: string; tool: string } {
  const payload = parseJsonish(payloadText) as Record<string, unknown> | null;
  if (!payload) return { text: "", thinking: "", tool: "" };
  const choices = (payload.choices as unknown[]) || [];
  const choice = choices[0] as Record<string, unknown> | undefined;
  if (choice) {
    const message = (choice.message as Record<string, unknown>) || {};
    const text = textFromContent(message.content) || (typeof choice.text === "string" ? choice.text : "");
    const thinking = (message.reasoning_content as string) || (message.reasoning as string) || "";
    const tool = ((message.tool_calls as unknown[]) || [])
      .map((tc) => {
        const fn = ((tc as Record<string, unknown>)?.function as Record<string, unknown>) || {};
        return `[tool ${fn.name || ""}(${fn.arguments || ""})]`;
      })
      .join("\n");
    return { text, thinking, tool };
  }
  if (Array.isArray(payload.content)) {
    const textParts: string[] = [];
    const thinkParts: string[] = [];
    const toolParts: string[] = [];
    for (const raw of payload.content) {
      if (!raw || typeof raw !== "object") continue;
      const b = raw as Record<string, unknown>;
      if (b.type === "text" && typeof b.text === "string") textParts.push(b.text);
      else if (b.type === "thinking" && typeof b.thinking === "string") thinkParts.push(b.thinking);
      else if (b.type === "tool_use") toolParts.push(`[tool ${b.name}(${JSON.stringify(b.input)})]`);
    }
    return { text: textParts.join("\n"), thinking: thinkParts.join("\n"), tool: toolParts.join("\n") };
  }
  return { text: "", thinking: "", tool: "" };
}

export function extractStreamDetails(rawText: unknown): { text: string; thinking: string; tool: string } {
  const text: string[] = [];
  const thinking: string[] = [];
  const toolMap = new Map<number, string>();
  const toolOrder: number[] = [];
  for (const line of String(rawText || "").split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed === "[DONE]") continue;
    let frame: Record<string, unknown>;
    try {
      frame = JSON.parse(trimmed);
    } catch {
      continue;
    }
    if (frame.type === "content_block_delta" && frame.delta) {
      const d = frame.delta as Record<string, unknown>;
      if (d.type === "text_delta" && typeof d.text === "string") text.push(d.text);
      else if (d.type === "thinking_delta" && typeof d.thinking === "string") thinking.push(d.thinking);
      else if (d.type === "input_json_delta" && typeof d.partial_json === "string") {
        const key = (frame.index as number) ?? 0;
        if (!toolMap.has(key)) {
          toolMap.set(key, "");
          toolOrder.push(key);
        }
        toolMap.set(key, toolMap.get(key)! + d.partial_json);
      }
      continue;
    }
    for (const ch of (frame.choices as Record<string, unknown>[]) || []) {
      const d = (ch.delta as Record<string, unknown>) || {};
      if (typeof d.content === "string") text.push(d.content);
      if (typeof d.reasoning_content === "string") thinking.push(d.reasoning_content);
      else if (typeof d.reasoning === "string") thinking.push(d.reasoning);
      for (const tc of (d.tool_calls as Record<string, unknown>[]) || []) {
        const key = (tc.index as number) ?? 0;
        if (!toolMap.has(key)) {
          toolMap.set(key, "");
          toolOrder.push(key);
        }
        const fn = (tc.function as Record<string, unknown>) || {};
        toolMap.set(key, toolMap.get(key)! + ((fn.arguments as string) || ""));
      }
    }
  }
  return { text: text.join(""), thinking: thinking.join(""), tool: toolOrder.map((k) => toolMap.get(k)).join("\n") };
}

export function extractResponseSummary(finalText: unknown, rawText: unknown): { text: string; thinking: string; tool: string } {
  const assembled = extractResponseObject(finalText);
  let { text, thinking, tool } = assembled;
  if (rawText && (!text || !thinking || !tool)) {
    const streamed = extractStreamDetails(rawText);
    if (!text) text = streamed.text;
    if (!thinking) thinking = streamed.thinking;
    if (!tool) tool = streamed.tool;
  }
  return { text, thinking, tool };
}

export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export interface Offender {
  kind: string;
  action: string;
  before: string | null;
  after: string | null;
  preview: string;
}

export function buildNeedleRegex(offenders: Offender[]): RegExp | null {
  const needles = [...new Set(offenders.map((o) => o.before).filter((v): v is string => !!v && v.length >= 2))].sort(
    (a, b) => b.length - a.length,
  );
  if (!needles.length) return null;
  return new RegExp("(?<![A-Za-z0-9])(" + needles.map(escapeRegExp).join("|") + ")(?![A-Za-z0-9])", "g");
}

export function offendersFromFindings(findings: Finding[] | null | undefined): Offender[] {
  const transformed = (findings || []).filter((f) => ["pseudonymized", "masked", "stripped"].includes(f.action));
  const offenders: Offender[] = [];
  const seen = new Set<string>();
  for (const f of transformed) {
    const key = [f.kind, f.before || "", f.replacement || ""].join("\u0000");
    if (seen.has(key)) continue;
    seen.add(key);
    offenders.push({
      kind: f.kind,
      action: f.action,
      before: f.before || null,
      after: f.replacement || null,
      preview: f.preview || "",
    });
  }
  return offenders;
}