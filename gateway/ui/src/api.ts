export interface Change {
  kind: string;
  action: string;
  before: string | null;
  after: string | null;
  preview: string | null;
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
  error: string | null;
  client_meta?: Record<string, string> | null;
}

export interface Bucket {
  t: string;
  requests: number;
  blocked: number;
  findings: number;
  tokens: number;
  cost_usd: number;
}

export interface NameCount {
  name?: string;
  count?: number;
  status?: string;
  mode?: string;
  model?: string;
  requests?: number;
  tokens?: number;
  cost_usd?: number;
  session_id?: string;
  findings?: number;
}

export interface Dashboard {
  window: { hours: number; since: string; until: string };
  totals: {
    requests: number;
    blocked: number;
    findings: number;
    tokens: number;
    cost_usd: number;
    errors: number;
    blocked_rate: number;
  };
  timeseries: Bucket[];
  by_status: NameCount[];
  by_mode: NameCount[];
  by_model: NameCount[];
  by_kind: { name: string; count: number }[];
  by_action: { name: string; count: number }[];
  by_detector: { name: string; count: number }[];
  latency: { count: number; avg: number | null; p50: number | null; p95: number | null; p99: number | null; max: number | null };
  top_sessions: NameCount[];
  all_time?: Record<string, number | string | null>;
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
        detail = (await res.json()).detail || detail;
      } catch {
        /* ignore */
      }
      throw new ApiError(detail);
    }
    if (res.status === 204) return null as T;
    return (await res.json()) as T;
  }

  get<T>(path: string): Promise<T> {
    return this.request<T>(path);
  }

  post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>(path, { method: "POST", body: JSON.stringify(body) });
  }

  del<T>(path: string): Promise<T> {
    return this.request<T>(path, { method: "DELETE" });
  }
}

export async function getMode(): Promise<string> {
  try {
    const info = await (await fetch("/")).json();
    return info.mode || "unknown";
  } catch {
    return "unknown";
  }
}