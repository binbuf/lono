export interface Change {
  kind: string;
  action: string;
  before: string | null;
  after: string | null;
  preview: string | null;
}

export interface FindingCategory {
  kind: string;
  action: string;
  count: number;
}

export interface RequestSummary {
  id: string;
  session_id: string | null;
  project: string | null;
  mode: string;
  api_shape: string;
  method: string;
  path: string;
  model: string | null;
  provider: string | null;
  stream: number;
  status: string;
  http_status: number | null;
  blocked: number;
  error: string | null;
  created_at: string;
  completed_at: string | null;
  latency_ms: number | null;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  total_tokens: number | null;
  cost_usd: number | null;
  changes: Change[];
  changes_count: number;
  changes_truncated: boolean;
  categories: FindingCategory[];
}

export interface Finding {
  detector: string;
  kind: string;
  start: number;
  end: number;
  score: number;
  action: string;
  preview: string;
  before?: string | null;
  replacement?: string | null;
}

export interface RequestDetail extends Omit<RequestSummary, "changes" | "changes_count" | "changes_truncated"> {
  findings: Finding[] | null;
  request_original: unknown;
  request_sanitized: unknown;
  response_raw: unknown;
  response_final: unknown;
  has_original: boolean;
  client_meta?: Record<string, string> | null;
  media?: unknown;
}

export interface Bucket {
  t: string;
  requests: number;
  blocked: number;
  findings: number;
  tokens: number;
  cost_usd: number;
}

export interface Dashboard {
  window: { hours: number; since: string; until: string };
  totals: {
    requests: number;
    blocked: number;
    findings: number;
    tokens: number;
    prompt_tokens: number;
    completion_tokens: number;
    cost_usd: number;
    errors: number;
    blocked_rate: number;
  };
  timeseries: Bucket[];
  by_status: { status: string; count: number }[];
  by_mode: { mode: string; count: number }[];
  by_model: { model: string; requests: number; tokens: number; cost_usd: number }[];
  by_provider: { provider: string; requests: number; tokens: number; cost_usd: number }[];
  by_shape: { api_shape: string; count: number }[];
  by_path: { path: string; requests: number; findings: number; tokens: number }[];
  by_http_status: { http_status: number; count: number }[];
  latency_series: { t: string; avg_ms: number; max_ms: number }[];
  by_kind: { name: string; count: number }[];
  by_action: { name: string; count: number }[];
  by_detector: { name: string; count: number }[];
  latency: {
    count: number;
    avg: number | null;
    p50: number | null;
    p95: number | null;
    p99: number | null;
    max: number | null;
  };
  top_sessions: { session_id: string; requests: number; findings: number; tokens: number }[];
  tools: ToolStats;
  all_time?: Record<string, number | string | null>;
}

export interface Stats {
  requests: number;
  blocked: number;
  findings: number;
  tokens: number;
  cost_usd: number;
  sessions: number;
  mappings: number;
  media: number;
  media_bytes: number;
  first_request: string | null;
  last_request: string | null;
}

export interface Mapping {
  scope: string;
  entity_type: string;
  original: string;
  pseudonym: string;
  created_at: string;
}

export interface Override {
  id: number;
  kind: string;
  category: string;
  value_display: string | null;
  note: string | null;
  created_at: string;
  expires_at: string | null;
  active: boolean;
}

export interface Substitution {
  id: string;
  pattern: string;
  replacement: string;
  match: "word" | "substring" | "regex";
  case_sensitive: boolean;
  category: string;
  enabled: boolean;
  note: string;
}

export interface Upstream {
  name: string;
  base_url: string;
  enabled: boolean;
  description: string;
  models: string[];
  path_prefixes: string[];
  timeout_s: number;
}

export interface UpstreamList {
  active: string[];
  default: string;
  items: Upstream[];
}

export interface ToolEvent {
  id: number;
  request_id: string | null;
  session_id: string | null;
  project: string | null;
  created_at: string;
  source: string;
  tool_name: string | null;
  call_id: string | null;
  kind: string;
  command: string | null;
  arguments: string | null;
  preview: string | null;
  is_command: number;
  request_model: string | null;
  request_path: string | null;
  request_status: string | null;
  request_created_at: string | null;
}

export interface McpEvent {
  id: number;
  request_id: string | null;
  session_id: string | null;
  server: string | null;
  created_at: string;
  method: string | null;
  direction: string;
  kind: string;
  params: string | null;
  result_preview: string | null;
  is_error: number;
  latency_ms: number | null;
  request_status: string | null;
}

export interface ToolStats {
  events: number;
  commands: number;
  tools: number;
  by_tool: { name: string; count: number; commands: number }[];
  top_commands: { command: string; tool_name: string; created_at: string; request_id: string }[];
  mcp_calls: number;
  mcp_errors: number;
  mcp_by_server: { name: string; count: number }[];
  mcp_by_method: { name: string; count: number }[];
}

export interface Session {
  session_id: string;
  requests: number;
  last_seen: string;
  total_tokens: number;
  cost_usd: number;
}

export interface ConfigSnapshot {
  mode: string;
  fail_closed: boolean;
  allow_client_mode_override: boolean;
  inspect_tools: boolean;
  detectors: Record<string, unknown>;
  output_scan: Record<string, unknown>;
  pseudonymization: Record<string, unknown>;
  overrides: Record<string, unknown>;
  audit: Record<string, unknown>;
  watchlist: Record<string, unknown>;
  substitutions: Record<string, unknown>;
  upstreams: Upstream[];
  mcp: {
    enabled: boolean;
    timeout_s: number;
    servers: { name: string; url: string; enabled: boolean; headers?: Record<string, string> }[];
  };
  tools: Record<string, unknown>;
  [key: string]: unknown;
}

export class ApiError extends Error {}

export class Api {
  key: string;
  constructor(key: string) {
    this.key = key;
  }

  private async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const res = await fetch(path, {
      ...options,
      headers: {
        Authorization: "Bearer " + this.key,
        "Content-Type": "application/json",
        ...(options.headers || {}),
      },
    });
    if (res.status === 401) throw new ApiError("Unauthorized — check the admin key");
    if (!res.ok) {
      let detail = res.statusText;
      try {
        const body = await res.json();
        detail = body.detail || detail;
        if (Array.isArray(detail)) detail = detail.map((d) => d.msg || JSON.stringify(d)).join("; ");
      } catch {
        /* ignore */
      }
      throw new ApiError(String(detail));
    }
    if (res.status === 204) return null as T;
    return (await res.json()) as T;
  }

  get<T>(path: string): Promise<T> {
    return this.request<T>(path);
  }

  post<T>(path: string, body?: unknown): Promise<T> {
    return this.request<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });
  }

  patch<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>(path, { method: "PATCH", body: JSON.stringify(body) });
  }

  del<T>(path: string): Promise<T> {
    return this.request<T>(path, { method: "DELETE" });
  }
}

export async function getServerInfo(): Promise<{ mode: string; version: string }> {
  try {
    const info = await (await fetch("/")).json();
    return { mode: info.mode || "unknown", version: info.version || "" };
  } catch {
    return { mode: "unknown", version: "" };
  }
}

export function qs(params: Record<string, string | number | boolean | undefined | null>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "" || value === false) continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}