"""SQLite-backed audit store with full-text search over all four stages."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from lono_gateway.models import utc_now

logger = logging.getLogger(__name__)

_BEGIN_FIELDS = {
    "id",
    "session_id",
    "project",
    "mode",
    "api_shape",
    "method",
    "path",
    "model",
    "provider",
    "client_id",
    "stream",
    "status",
    "created_at",
    "request_original",
    "request_sanitized",
    "findings_json",
    "findings_count",
    "client_meta_json",
    "media_json",
}

_COMPLETE_FIELDS = {
    "status",
    "http_status",
    "blocked",
    "error",
    "completed_at",
    "latency_ms",
    "model",
    "provider",
    "prompt_tokens",
    "completion_tokens",
    "total_tokens",
    "cost_usd",
    "response_raw",
    "response_final",
    "findings_json",
    "findings_count",
    "media_json",
}

_SUMMARY_COLUMNS = (
    "id, session_id, project, mode, api_shape, method, path, model, provider, client_id, stream, status, "
    "http_status, blocked, error, created_at, completed_at, latency_ms, prompt_tokens, "
    "completion_tokens, total_tokens, cost_usd, findings_count, findings_json, "
    "COALESCE(client_id, 'legacy-' || COALESCE(session_id, 'unknown')) AS client_key"
)

# Older records predate the ``client_id`` column; group them by session so the
# console still shows something useful. New requests always carry a real id.
_CLIENT_KEY = "COALESCE(r.client_id, 'legacy-' || COALESCE(r.session_id, 'unknown'))"
_LEGACY_PREFIX = "legacy-"


def _client_key_condition(key: str) -> tuple[str, list[Any]]:
    """WHERE fragment selecting the rows that belong to a client key."""
    if key.startswith(_LEGACY_PREFIX):
        return "r.client_id IS NULL AND r.session_id = ?", [key[len(_LEGACY_PREFIX) :]]
    return "r.client_id = ?", [key]

# Actions that actually rewrote text; everything else (flag/observed/allow) is noise
# for the console's "what changed" view.
_TRANSFORMED_ACTIONS = {"pseudonymized", "masked", "stripped"}
_MAX_CHANGES = 200

_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    id TEXT PRIMARY KEY,
    session_id TEXT,
    project TEXT,
    mode TEXT NOT NULL,
    api_shape TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    model TEXT,
    provider TEXT,
    client_id TEXT,
    stream INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    http_status INTEGER,
    blocked INTEGER NOT NULL DEFAULT 0,
    error TEXT,
    created_at TEXT NOT NULL,
    completed_at TEXT,
    latency_ms INTEGER,
    prompt_tokens INTEGER,
    completion_tokens INTEGER,
    total_tokens INTEGER,
    cost_usd REAL,
    findings_count INTEGER NOT NULL DEFAULT 0,
    findings_json TEXT,
    request_original TEXT,
    request_sanitized TEXT,
    response_raw TEXT,
    response_final TEXT,
    media_json TEXT,
    client_meta_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_requests_created ON requests(created_at);
CREATE INDEX IF NOT EXISTS idx_requests_session ON requests(session_id);
CREATE INDEX IF NOT EXISTS idx_requests_model ON requests(model);
CREATE INDEX IF NOT EXISTS idx_requests_status ON requests(status);

CREATE TABLE IF NOT EXISTS mappings (
    scope TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    original_key TEXT NOT NULL,
    original TEXT NOT NULL,
    pseudonym TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (scope, entity_type, original_key)
);
CREATE INDEX IF NOT EXISTS idx_mappings_pseudonym ON mappings(scope, pseudonym);

CREATE TABLE IF NOT EXISTS media (
    sha256 TEXT PRIMARY KEY,
    mime TEXT,
    size INTEGER,
    backend TEXT,
    object_path TEXT,
    kind TEXT,
    created_at TEXT NOT NULL,
    first_request_id TEXT
);

CREATE TABLE IF NOT EXISTS overrides (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,
    category TEXT NOT NULL,
    value_key TEXT,
    value_display TEXT,
    note TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_overrides_active ON overrides(kind, category, revoked);

CREATE TABLE IF NOT EXISTS tool_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT,
    session_id TEXT,
    project TEXT,
    created_at TEXT NOT NULL,
    source TEXT,
    tool_name TEXT,
    call_id TEXT,
    kind TEXT,
    command TEXT,
    arguments TEXT,
    preview TEXT,
    is_command INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_tool_events_request ON tool_events(request_id);
CREATE INDEX IF NOT EXISTS idx_tool_events_session ON tool_events(session_id);
CREATE INDEX IF NOT EXISTS idx_tool_events_tool ON tool_events(tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_events_created ON tool_events(created_at);

CREATE TABLE IF NOT EXISTS mcp_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT,
    session_id TEXT,
    project TEXT,
    created_at TEXT NOT NULL,
    server TEXT,
    method TEXT,
    direction TEXT,
    kind TEXT,
    params TEXT,
    result_preview TEXT,
    is_error INTEGER NOT NULL DEFAULT 0,
    latency_ms INTEGER,
    raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_mcp_events_request ON mcp_events(request_id);
CREATE INDEX IF NOT EXISTS idx_mcp_events_server ON mcp_events(server);
CREATE INDEX IF NOT EXISTS idx_mcp_events_created ON mcp_events(created_at);

CREATE VIRTUAL TABLE IF NOT EXISTS requests_fts USING fts5(
    request_original,
    request_sanitized,
    response_raw,
    response_final,
    content='requests',
    content_rowid='rowid',
    tokenize='unicode61'
);

CREATE TRIGGER IF NOT EXISTS requests_fts_ai AFTER INSERT ON requests BEGIN
    INSERT INTO requests_fts(rowid, request_original, request_sanitized, response_raw, response_final)
    VALUES (new.rowid, new.request_original, new.request_sanitized, new.response_raw, new.response_final);
END;
CREATE TRIGGER IF NOT EXISTS requests_fts_ad AFTER DELETE ON requests BEGIN
    INSERT INTO requests_fts(requests_fts, rowid, request_original, request_sanitized, response_raw, response_final)
    VALUES ('delete', old.rowid, old.request_original, old.request_sanitized, old.response_raw, old.response_final);
END;
CREATE TRIGGER IF NOT EXISTS requests_fts_au AFTER UPDATE ON requests BEGIN
    INSERT INTO requests_fts(requests_fts, rowid, request_original, request_sanitized, response_raw, response_final)
    VALUES ('delete', old.rowid, old.request_original, old.request_sanitized, old.response_raw, old.response_final);
    INSERT INTO requests_fts(rowid, request_original, request_sanitized, response_raw, response_final)
    VALUES (new.rowid, new.request_original, new.request_sanitized, new.response_raw, new.response_final);
END;
"""

_JSON_COLUMNS = {"findings_json", "media_json", "client_meta_json"}


def _fts_query(raw: str) -> str:
    terms = [term for term in raw.replace('"', " ").split() if term]
    if not terms:
        return ""
    return " AND ".join(f'"{term}"' for term in terms)


def _parse_findings(findings_json: str | None) -> list[dict[str, Any]]:
    if not findings_json:
        return []
    try:
        data = json.loads(findings_json)
    except (ValueError, TypeError):
        return []
    return [item for item in data if isinstance(item, dict)] if isinstance(data, list) else []


def _change_before(finding: dict[str, Any], reverse: dict[str, str]) -> str | None:
    # New records persist the original span directly. Older records only stored
    # a replacement, so fall back to the session's pseudonym mapping.
    stored = finding.get("before")
    if stored:
        return stored
    if finding.get("action") != "pseudonymized":
        return None
    replacement = finding.get("replacement")
    return reverse.get(replacement) if replacement else None


def _summarize_changes(
    findings: list[dict[str, Any]], reverse: dict[str, str]
) -> tuple[list[dict[str, Any]], int]:
    """Reduce findings to deduped, bounded before/after changes for the log list."""
    changes: list[dict[str, Any]] = []
    seen: set[tuple] = set()
    total = 0
    for finding in findings:
        if finding.get("action") not in _TRANSFORMED_ACTIONS:
            continue
        total += 1
        before = _change_before(finding, reverse)
        after = finding.get("replacement")
        key = (finding.get("kind"), before, after)
        if key in seen:
            continue
        seen.add(key)
        if len(changes) < _MAX_CHANGES:
            changes.append(
                {
                    "kind": finding.get("kind") or "",
                    "action": finding.get("action"),
                    "before": before,
                    "after": after,
                    "preview": finding.get("preview") or "",
                }
            )
    return changes, total


def _summarize_categories(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Distinct finding categories (kind + action) with counts for the log list.

    Unlike ``changes`` this keeps every detected span, including observed or
    flagged ones that never rewrote text, so the console can surface the
    category type for a request without opening it.
    """
    buckets: dict[tuple[str, str], int] = {}
    for finding in findings:
        kind = str(finding.get("kind") or "").strip()
        if not kind:
            continue
        action = str(finding.get("action") or "").strip()
        buckets[(kind, action)] = buckets.get((kind, action), 0) + 1
    return [
        {"kind": kind, "action": action, "count": count}
        for (kind, action), count in sorted(buckets.items(), key=lambda kv: (-kv[1], kv[0][0]))
    ]


class AuditStore:
    def __init__(self, path: str, retention_days: int = 0) -> None:
        self.path = Path(path)
        self.retention_days = retention_days
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._init_schema()

    def _init_schema(self) -> None:
        with self._lock:
            self._conn.executescript(_SCHEMA)
            # Databases created before the column existed need it added; the
            # FTS triggers rewrite on UPDATE so we intentionally do not backfill
            # (legacy rows are grouped by session at query time instead).
            columns = {row["name"] for row in self._conn.execute("PRAGMA table_info(requests)")}
            if "client_id" not in columns:
                self._conn.execute("ALTER TABLE requests ADD COLUMN client_id TEXT")
            self._conn.execute("CREATE INDEX IF NOT EXISTS idx_requests_client ON requests(client_id)")
            self._conn.commit()

    def _execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        with self._lock:
            cursor = self._conn.execute(sql, params)
            self._conn.commit()
            return cursor

    # ------------------------------------------------------------- lifecycle

    def begin_request(self, **fields: Any) -> None:
        payload = {key: value for key, value in fields.items() if key in _BEGIN_FIELDS}
        payload.setdefault("created_at", utc_now())
        payload.setdefault("status", "pending")
        columns = ", ".join(payload)
        placeholders = ", ".join("?" for _ in payload)
        self._execute(
            f"INSERT INTO requests ({columns}) VALUES ({placeholders})", tuple(payload.values())
        )

    def complete_request(self, request_id: str, **fields: Any) -> None:
        payload = {key: value for key, value in fields.items() if key in _COMPLETE_FIELDS}
        payload.setdefault("completed_at", utc_now())
        if not payload:
            return
        assignments = ", ".join(f"{key} = ?" for key in payload)
        self._execute(
            f"UPDATE requests SET {assignments} WHERE id = ?",
            (*payload.values(), request_id),
        )

    # ---------------------------------------------------------------- queries

    def get_request(self, request_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM requests WHERE id = ?", (request_id,)).fetchone()
        if row is None:
            return None
        record = dict(row)
        for column in _JSON_COLUMNS:
            if record.get(column):
                try:
                    record[column.removesuffix("_json")] = json.loads(record[column])
                except (ValueError, TypeError):
                    record[column.removesuffix("_json")] = None
        record["has_original"] = bool(record.get("request_original"))
        findings = record.get("findings")
        if isinstance(findings, list) and findings:
            reverse = self._reverse_for_session(record.get("session_id"))
            for finding in findings:
                if isinstance(finding, dict):
                    finding["before"] = _change_before(finding, reverse)
        return record

    def _reverse_for_session(self, session_id: str | None) -> dict[str, str]:
        scopes = ["global"]
        if session_id:
            scopes.insert(0, f"session:{session_id}")
        return self.reverse_mappings(scopes)

    def list_requests(
        self,
        *,
        query: str | None = None,
        session_id: str | None = None,
        client_id: str | None = None,
        model: str | None = None,
        provider: str | None = None,
        path: str | None = None,
        status: str | None = None,
        mode: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        conditions: list[str] = []
        params: list[Any] = []
        if query:
            match = _fts_query(query)
            if match:
                conditions.append("r.rowid IN (SELECT rowid FROM requests_fts WHERE requests_fts MATCH ?)")
                params.append(match)
        if session_id:
            conditions.append("r.session_id = ?")
            params.append(session_id)
        if client_id:
            condition, client_params = _client_key_condition(client_id)
            conditions.append(condition)
            params.extend(client_params)
        if model:
            conditions.append("r.model = ?")
            params.append(model)
        if provider:
            conditions.append("r.provider = ?")
            params.append(provider)
        if path:
            conditions.append("r.path = ?")
            params.append(path)
        if status:
            conditions.append("r.status = ?")
            params.append(status)
        if mode:
            conditions.append("r.mode = ?")
            params.append(mode)
        if since:
            conditions.append("r.created_at >= ?")
            params.append(since)
        if until:
            conditions.append("r.created_at <= ?")
            params.append(until)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        limit = max(1, min(limit, 500))
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) AS count FROM requests r {where}", tuple(params)
            ).fetchone()["count"]
            rows = self._conn.execute(
                f"SELECT {_SUMMARY_COLUMNS} FROM requests r {where} "
                "ORDER BY r.created_at DESC LIMIT ? OFFSET ?",
                (*params, limit, max(0, offset)),
            ).fetchall()
        reverse_by_session = {
            row["session_id"]: self._reverse_for_session(row["session_id"])
            for row in rows
            if row["session_id"]
        }
        items: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            findings = _parse_findings(item.pop("findings_json", None))
            changes, changed_total = _summarize_changes(findings, reverse_by_session.get(item["session_id"], {}))
            item["changes"] = changes
            item["changes_count"] = changed_total
            item["changes_truncated"] = changed_total > len(changes)
            item["categories"] = _summarize_categories(findings)
            items.append(item)
        return {"total": total, "limit": limit, "offset": max(0, offset), "items": items}

    def list_sessions(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT session_id, COUNT(*) AS requests, MAX(created_at) AS last_seen, "
                "SUM(COALESCE(total_tokens, 0)) AS total_tokens, SUM(COALESCE(cost_usd, 0)) AS cost_usd "
                "FROM requests WHERE session_id IS NOT NULL "
                "GROUP BY session_id ORDER BY last_seen DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_clients(
        self,
        *,
        query: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Aggregate connecting clients (anonymous fingerprints) over requests."""
        conditions: list[str] = []
        params: list[Any] = []
        if since:
            conditions.append("r.created_at >= ?")
            params.append(since)
        if until:
            conditions.append("r.created_at <= ?")
            params.append(until)
        if query:
            needle = f"%{query}%"
            conditions.append(
                f"({_CLIENT_KEY} LIKE ? OR COALESCE(json_extract(r.client_meta_json, '$.\"user-agent\"'), '') LIKE ? "
                "OR COALESCE(r.project, '') LIKE ?)"
            )
            params.extend([needle, needle, needle])
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        limit = max(1, min(limit, 500))
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) AS count FROM (SELECT {_CLIENT_KEY} AS key FROM requests r {where} "
                "GROUP BY key)",
                tuple(params),
            ).fetchone()["count"]
            rows = self._conn.execute(
                f"SELECT {_CLIENT_KEY} AS client_id, COUNT(*) AS requests, "
                "COUNT(DISTINCT r.session_id) AS sessions, "
                "SUM(CASE WHEN r.status IN ('error','upstream_error') THEN 1 ELSE 0 END) AS errors, "
                "SUM(COALESCE(r.blocked, 0)) AS blocked, "
                "SUM(COALESCE(r.total_tokens, 0)) AS tokens, "
                "SUM(COALESCE(r.cost_usd, 0)) AS cost_usd, "
                "AVG(r.latency_ms) AS avg_latency_ms, "
                "MIN(r.created_at) AS first_seen, MAX(r.created_at) AS last_seen, "
                "MAX(json_extract(r.client_meta_json, '$.\"user-agent\"')) AS user_agent, "
                "MAX(COALESCE(json_extract(r.client_meta_json, '$.\"x-lono-client\"'), "
                "json_extract(r.client_meta_json, '$.\"client\"'), r.project)) AS label, "
                "MAX(r.provider) AS provider "
                f"FROM requests r {where} GROUP BY {_CLIENT_KEY} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
                (*params, limit, max(0, offset)),
            ).fetchall()
        items = [dict(row) for row in rows]
        for item in items:
            item["avg_latency_ms"] = int(item["avg_latency_ms"]) if item["avg_latency_ms"] is not None else None
        return {"total": total, "limit": limit, "offset": max(0, offset), "items": items}

    def client_detail(self, key: str, *, hours: int = 24) -> dict[str, Any] | None:
        """One client: lifetime totals plus recent breakdowns and header samples."""
        condition, params = _client_key_condition(key)
        hours = max(1, min(int(hours), 24 * 30))
        since = (datetime.now(UTC) - timedelta(hours=hours)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        with self._lock:
            summary = self._conn.execute(
                f"SELECT {_CLIENT_KEY} AS client_id, COUNT(*) AS requests, "
                "COUNT(DISTINCT r.session_id) AS sessions, "
                "SUM(CASE WHEN r.status IN ('error','upstream_error') THEN 1 ELSE 0 END) AS errors, "
                "SUM(COALESCE(r.blocked, 0)) AS blocked, "
                "SUM(COALESCE(r.total_tokens, 0)) AS tokens, "
                "SUM(COALESCE(r.cost_usd, 0)) AS cost_usd, "
                "AVG(r.latency_ms) AS avg_latency_ms, "
                "MIN(r.created_at) AS first_seen, MAX(r.created_at) AS last_seen, "
                "MAX(json_extract(r.client_meta_json, '$.\"user-agent\"')) AS user_agent, "
                "MAX(COALESCE(json_extract(r.client_meta_json, '$.\"x-lono-client\"'), "
                "json_extract(r.client_meta_json, '$.\"client\"'), r.project)) AS label "
                f"FROM requests r WHERE {condition} GROUP BY {_CLIENT_KEY}",
                tuple(params),
            ).fetchone()
            if summary is None:
                return None
            by_model = [
                dict(row)
                for row in self._conn.execute(
                    "SELECT COALESCE(r.model, '(unknown)') AS model, COUNT(*) AS requests, "
                    "SUM(COALESCE(r.total_tokens, 0)) AS tokens FROM requests r "
                    f"WHERE {condition} GROUP BY model ORDER BY requests DESC LIMIT 10",
                    tuple(params),
                ).fetchall()
            ]
            by_path = [
                dict(row)
                for row in self._conn.execute(
                    "SELECT r.path, COUNT(*) AS requests, "
                    "SUM(CASE WHEN r.status IN ('error','upstream_error') THEN 1 ELSE 0 END) AS errors "
                    f"FROM requests r WHERE {condition} GROUP BY r.path ORDER BY requests DESC LIMIT 10",
                    tuple(params),
                ).fetchall()
            ]
            by_status = [
                dict(row)
                for row in self._conn.execute(
                    "SELECT r.status, COUNT(*) AS count FROM requests r "
                    f"WHERE {condition} GROUP BY r.status ORDER BY count DESC",
                    tuple(params),
                ).fetchall()
            ]
            by_provider = [
                dict(row)
                for row in self._conn.execute(
                    "SELECT COALESCE(r.provider, '(default)') AS provider, COUNT(*) AS requests "
                    f"FROM requests r WHERE {condition} GROUP BY provider ORDER BY requests DESC LIMIT 10",
                    tuple(params),
                ).fetchall()
            ]
            headers = [
                dict(row)
                for row in self._conn.execute(
                    "SELECT DISTINCT r.client_meta_json FROM requests r "
                    f"WHERE {condition} AND r.client_meta_json IS NOT NULL AND r.client_meta_json != '{{}}' "
                    "ORDER BY r.created_at DESC LIMIT 10",
                    tuple(params),
                ).fetchall()
            ]
            recent_window = self._conn.execute(
                "SELECT COUNT(*) AS count FROM requests r "
                f"WHERE {condition} AND r.created_at >= ?",
                (*params, since),
            ).fetchone()["count"]
        detail = dict(summary)
        detail["avg_latency_ms"] = int(detail["avg_latency_ms"]) if detail["avg_latency_ms"] is not None else None
        detail["window"] = {"hours": hours, "since": since, "requests": recent_window}
        detail["by_model"] = by_model
        detail["by_path"] = by_path
        detail["by_status"] = by_status
        detail["by_provider"] = by_provider
        samples: list[dict[str, Any]] = []
        seen: set[str] = set()
        for row in headers:
            raw = row.get("client_meta_json")
            if not raw or raw in seen:
                continue
            seen.add(raw)
            try:
                parsed = json.loads(raw)
            except (ValueError, TypeError):
                continue
            if isinstance(parsed, dict) and parsed:
                samples.append(parsed)
        detail["header_samples"] = samples[:8]
        return detail

    def stats(self) -> dict[str, Any]:
        with self._lock:
            totals = self._conn.execute(
                "SELECT COUNT(*) AS requests, SUM(COALESCE(blocked, 0)) AS blocked, "
                "SUM(COALESCE(findings_count, 0)) AS findings, SUM(COALESCE(total_tokens, 0)) AS tokens, "
                "SUM(COALESCE(cost_usd, 0)) AS cost_usd, "
                "MIN(created_at) AS first_request, MAX(created_at) AS last_request FROM requests"
            ).fetchone()
            sessions = self._conn.execute("SELECT COUNT(DISTINCT session_id) AS sessions FROM requests").fetchone()
            mappings = self._conn.execute("SELECT COUNT(*) AS mappings FROM mappings").fetchone()
            media = self._conn.execute(
                "SELECT COUNT(*) AS media, SUM(COALESCE(size, 0)) AS media_bytes FROM media"
            ).fetchone()
        return {**dict(totals), **dict(sessions), **dict(mappings), **dict(media)}

    def dashboard(self, hours: int = 24) -> dict[str, Any]:
        """Aggregates for the console dashboard over a trailing time window."""
        hours = max(1, min(int(hours), 24 * 30))
        now = datetime.now(UTC)
        since = (now - timedelta(hours=hours)).isoformat(timespec="milliseconds").replace("+00:00", "Z")

        with self._lock:
            totals = self._conn.execute(
                "SELECT COUNT(*) AS requests, SUM(COALESCE(blocked,0)) AS blocked, "
                "SUM(COALESCE(findings_count,0)) AS findings, "
                "SUM(COALESCE(total_tokens,0)) AS tokens, SUM(COALESCE(cost_usd,0)) AS cost_usd, "
                "SUM(COALESCE(prompt_tokens,0)) AS prompt_tokens, "
                "SUM(COALESCE(completion_tokens,0)) AS completion_tokens, "
                "SUM(CASE WHEN status IN ('error','upstream_error') THEN 1 ELSE 0 END) AS errors "
                "FROM requests WHERE created_at >= ?",
                (since,),
            ).fetchone()
            rows = self._conn.execute(
                "SELECT substr(created_at,1,13) || ':00:00Z' AS bucket, COUNT(*) AS requests, "
                "SUM(COALESCE(blocked,0)) AS blocked, SUM(COALESCE(findings_count,0)) AS findings, "
                "SUM(COALESCE(total_tokens,0)) AS tokens, SUM(COALESCE(cost_usd,0)) AS cost_usd "
                "FROM requests WHERE created_at >= ? GROUP BY bucket ORDER BY bucket",
                (since,),
            ).fetchall()
            by_status = self._conn.execute(
                "SELECT status, COUNT(*) AS count FROM requests WHERE created_at >= ? "
                "GROUP BY status ORDER BY count DESC",
                (since,),
            ).fetchall()
            by_mode = self._conn.execute(
                "SELECT mode, COUNT(*) AS count FROM requests WHERE created_at >= ? GROUP BY mode",
                (since,),
            ).fetchall()
            by_model = self._conn.execute(
                "SELECT COALESCE(model,'(unknown)') AS model, COUNT(*) AS requests, "
                "SUM(COALESCE(total_tokens,0)) AS tokens, SUM(COALESCE(cost_usd,0)) AS cost_usd "
                "FROM requests WHERE created_at >= ? GROUP BY model ORDER BY requests DESC LIMIT 12",
                (since,),
            ).fetchall()
            latencies = self._conn.execute(
                "SELECT latency_ms FROM requests WHERE created_at >= ? AND latency_ms IS NOT NULL "
                "ORDER BY latency_ms",
                (since,),
            ).fetchall()
            finding_rows = self._conn.execute(
                "SELECT findings_json FROM requests WHERE created_at >= ? "
                "AND findings_json IS NOT NULL AND findings_json != '[]' LIMIT 20000",
                (since,),
            ).fetchall()
            top_sessions = self._conn.execute(
                "SELECT session_id, COUNT(*) AS requests, SUM(COALESCE(findings_count,0)) AS findings, "
                "SUM(COALESCE(total_tokens,0)) AS tokens FROM requests "
                "WHERE created_at >= ? AND session_id IS NOT NULL "
                "GROUP BY session_id ORDER BY requests DESC LIMIT 10",
                (since,),
            ).fetchall()
            by_provider = self._conn.execute(
                "SELECT COALESCE(provider,'(default)') AS provider, COUNT(*) AS requests, "
                "SUM(COALESCE(total_tokens,0)) AS tokens, SUM(COALESCE(cost_usd,0)) AS cost_usd "
                "FROM requests WHERE created_at >= ? GROUP BY provider ORDER BY requests DESC",
                (since,),
            ).fetchall()
            by_shape = self._conn.execute(
                "SELECT api_shape, COUNT(*) AS count FROM requests WHERE created_at >= ? "
                "GROUP BY api_shape ORDER BY count DESC",
                (since,),
            ).fetchall()
            by_path = self._conn.execute(
                "SELECT path, COUNT(*) AS requests, SUM(COALESCE(findings_count,0)) AS findings, "
                "SUM(COALESCE(total_tokens,0)) AS tokens FROM requests WHERE created_at >= ? "
                "GROUP BY path ORDER BY requests DESC LIMIT 12",
                (since,),
            ).fetchall()
            by_http_status = self._conn.execute(
                "SELECT http_status, COUNT(*) AS count FROM requests "
                "WHERE created_at >= ? AND http_status IS NOT NULL GROUP BY http_status ORDER BY count DESC",
                (since,),
            ).fetchall()
            latency_series = self._conn.execute(
                "SELECT substr(created_at,1,13) || ':00:00Z' AS bucket, "
                "AVG(latency_ms) AS avg_ms, MAX(latency_ms) AS max_ms FROM requests "
                "WHERE created_at >= ? AND latency_ms IS NOT NULL GROUP BY bucket ORDER BY bucket",
                (since,),
            ).fetchall()

        buckets = {row["bucket"]: dict(row) for row in rows}
        timeseries: list[dict[str, Any]] = []
        for offset in range(hours - 1, -1, -1):
            point = now - timedelta(hours=offset)
            key = point.isoformat(timespec="seconds").replace("+00:00", "Z")[:13] + ":00:00Z"
            entry = buckets.get(
                key,
                {"bucket": key, "requests": 0, "blocked": 0, "findings": 0, "tokens": 0, "cost_usd": 0.0},
            )
            timeseries.append(
                {
                    "t": entry["bucket"],
                    "requests": entry["requests"] or 0,
                    "blocked": entry["blocked"] or 0,
                    "findings": entry["findings"] or 0,
                    "tokens": entry["tokens"] or 0,
                    "cost_usd": entry["cost_usd"] or 0.0,
                }
            )

        kinds: dict[str, int] = {}
        actions: dict[str, int] = {}
        detectors: dict[str, int] = {}
        for row in finding_rows:
            for finding in _parse_findings(row["findings_json"]):
                kind = finding.get("kind") or "UNKNOWN"
                kinds[kind] = kinds.get(kind, 0) + 1
                action = finding.get("action") or "unknown"
                actions[action] = actions.get(action, 0) + 1
                detector = finding.get("detector") or "unknown"
                detectors[detector] = detectors.get(detector, 0) + 1

        def _top(mapping: dict[str, int], limit: int = 12) -> list[dict[str, Any]]:
            return [
                {"name": name, "count": count}
                for name, count in sorted(mapping.items(), key=lambda item: item[1], reverse=True)[:limit]
            ]

        latency_values = [row["latency_ms"] for row in latencies if row["latency_ms"] is not None]

        def _percentile(values: list[int], fraction: float) -> int | None:
            if not values:
                return None
            index = min(len(values) - 1, int(round(fraction * (len(values) - 1))))
            return int(values[index])

        until = now.isoformat(timespec="milliseconds").replace("+00:00", "Z")
        return {
            "window": {"hours": hours, "since": since, "until": until},
            "totals": {
                "requests": totals["requests"] or 0,
                "blocked": totals["blocked"] or 0,
                "findings": totals["findings"] or 0,
                "tokens": totals["tokens"] or 0,
                "prompt_tokens": totals["prompt_tokens"] or 0,
                "completion_tokens": totals["completion_tokens"] or 0,
                "cost_usd": totals["cost_usd"] or 0.0,
                "errors": totals["errors"] or 0,
                "blocked_rate": (totals["blocked"] or 0) / totals["requests"] if totals["requests"] else 0.0,
            },
            "timeseries": timeseries,
            "by_status": [dict(row) for row in by_status],
            "by_mode": [dict(row) for row in by_mode],
            "by_model": [dict(row) for row in by_model],
            "by_provider": [dict(row) for row in by_provider],
            "by_shape": [dict(row) for row in by_shape],
            "by_path": [dict(row) for row in by_path],
            "by_http_status": [dict(row) for row in by_http_status],
            "latency_series": [
                {"t": row["bucket"], "avg_ms": int(row["avg_ms"] or 0), "max_ms": int(row["max_ms"] or 0)}
                for row in latency_series
            ],
            "by_kind": _top(kinds),
            "by_action": _top(actions),
            "by_detector": _top(detectors),
            "latency": {
                "count": len(latency_values),
                "avg": int(sum(latency_values) / len(latency_values)) if latency_values else None,
                "p50": _percentile(latency_values, 0.5),
                "p95": _percentile(latency_values, 0.95),
                "p99": _percentile(latency_values, 0.99),
                "max": max(latency_values) if latency_values else None,
            },
            "top_sessions": [dict(row) for row in top_sessions],
            "tools": self.tool_stats(hours),
        }

    def prune(self, retention_days: int | None = None) -> int:
        days = self.retention_days if retention_days is None else retention_days
        if not days or days <= 0:
            return 0
        from datetime import datetime, timedelta

        cutoff = (datetime.now(UTC) - timedelta(days=days)).isoformat(timespec="milliseconds")
        with self._lock:
            cursor = self._conn.execute("DELETE FROM requests WHERE created_at < ?", (cutoff,))
            self._conn.commit()
            deleted = cursor.rowcount
        if deleted:
            logger.info("pruned %d audit records older than %d days", deleted, days)
        return deleted

    def delete_request(self, request_id: str) -> bool:
        with self._lock:
            cursor = self._conn.execute("DELETE FROM requests WHERE id = ?", (request_id,))
            self._conn.commit()
            return cursor.rowcount > 0

    # --------------------------------------------------------------- mappings

    def get_mapping(self, scope: str, entity_type: str, original_key: str) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(
                "SELECT * FROM mappings WHERE scope = ? AND entity_type = ? AND original_key = ?",
                (scope, entity_type, original_key),
            ).fetchone()

    def pseudonym_in_use(self, scope: str, pseudonym: str) -> bool:
        with self._lock:
            row = self._conn.execute(
                "SELECT 1 FROM mappings WHERE scope = ? AND pseudonym = ? LIMIT 1", (scope, pseudonym)
            ).fetchone()
        return row is not None

    def put_mapping(
        self, *, scope: str, entity_type: str, original_key: str, original: str, pseudonym: str
    ) -> None:
        self._execute(
            "INSERT INTO mappings (scope, entity_type, original_key, original, pseudonym, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(scope, entity_type, original_key) DO NOTHING",
            (scope, entity_type, original_key, original, pseudonym, utc_now()),
        )

    def reverse_mappings(self, scopes: list[str]) -> dict[str, str]:
        if not scopes:
            return {}
        placeholders = ", ".join("?" for _ in scopes)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT pseudonym, original FROM mappings WHERE scope IN ({placeholders})",
                tuple(scopes),
            ).fetchall()
        return {row["pseudonym"]: row["original"] for row in rows}

    def list_mappings(self, scope: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        with self._lock:
            if scope:
                rows = self._conn.execute(
                    "SELECT scope, entity_type, original, pseudonym, created_at FROM mappings "
                    "WHERE scope = ? ORDER BY created_at DESC LIMIT ?",
                    (scope, limit),
                ).fetchall()
            else:
                rows = self._conn.execute(
                    "SELECT scope, entity_type, original, pseudonym, created_at FROM mappings "
                    "ORDER BY created_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(row) for row in rows]

    # ------------------------------------------------------------------ media

    def record_media(self, ref: dict[str, Any], request_id: str | None) -> None:
        self._execute(
            "INSERT INTO media (sha256, mime, size, backend, object_path, kind, created_at, first_request_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(sha256) DO NOTHING",
            (
                ref.get("sha256"),
                ref.get("mime"),
                ref.get("size"),
                ref.get("backend"),
                ref.get("object"),
                ref.get("kind"),
                utc_now(),
                request_id,
            ),
        )

    def get_media(self, sha256: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM media WHERE sha256 = ?", (sha256,)).fetchone()
        return dict(row) if row else None

    # -------------------------------------------------------------- overrides

    def add_override(
        self,
        *,
        kind: str,
        category: str,
        value_key: str | None = None,
        value_display: str | None = None,
        note: str | None = None,
        expires_at: str | None = None,
    ) -> dict[str, Any]:
        cursor = self._execute(
            "INSERT INTO overrides (kind, category, value_key, value_display, note, created_at, expires_at, revoked) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, 0)",
            (kind, category, value_key, value_display, note, utc_now(), expires_at),
        )
        override = self.get_override(int(cursor.lastrowid))
        assert override is not None
        return override

    def get_override(self, override_id: int) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute("SELECT * FROM overrides WHERE id = ?", (override_id,)).fetchone()
        return dict(row) if row else None

    def list_overrides(self, include_expired: bool = True) -> list[dict[str, Any]]:
        conditions = ["revoked = 0"]
        params: list[Any] = []
        if not include_expired:
            conditions.append("(expires_at IS NULL OR expires_at > ?)")
            params.append(utc_now())
        where = " AND ".join(conditions)
        with self._lock:
            rows = self._conn.execute(
                f"SELECT * FROM overrides WHERE {where} ORDER BY created_at DESC", tuple(params)
            ).fetchall()
        now = utc_now()
        items = []
        for row in rows:
            record = dict(row)
            record["active"] = not record["revoked"] and (
                record["expires_at"] is None or record["expires_at"] > now
            )
            items.append(record)
        return items

    def revoke_override(self, override_id: int) -> bool:
        cursor = self._execute(
            "UPDATE overrides SET revoked = 1 WHERE id = ? AND revoked = 0", (override_id,)
        )
        return cursor.rowcount > 0

    def active_overrides(self) -> dict[str, Any]:
        now = utc_now()
        with self._lock:
            rows = self._conn.execute(
                "SELECT kind, category, value_key FROM overrides "
                "WHERE revoked = 0 AND (expires_at IS NULL OR expires_at > ?)",
                (now,),
            ).fetchall()
        categories: set[str] = set()
        values: dict[str, set[str]] = {}
        for row in rows:
            if row["kind"] == "category":
                categories.add(row["category"])
            elif row["value_key"]:
                values.setdefault(row["category"], set()).add(row["value_key"])
        return {"categories": categories, "values": values}

    def prune_overrides(self) -> int:
        cursor = self._execute(
            "DELETE FROM overrides WHERE revoked = 1 OR (expires_at IS NOT NULL AND expires_at <= ?)",
            (utc_now(),),
        )
        return cursor.rowcount

    # ----------------------------------------------------------------- tools

    def record_tool_events(self, events: list[dict[str, Any]]) -> int:
        if not events:
            return 0
        columns = (
            "request_id",
            "session_id",
            "project",
            "created_at",
            "source",
            "tool_name",
            "call_id",
            "kind",
            "command",
            "arguments",
            "preview",
            "is_command",
        )
        now = utc_now()
        rows = []
        for event in events:
            event = {**event}
            event.setdefault("created_at", now)
            event.setdefault("is_command", 0)
            rows.append(tuple(event.get(column) for column in columns))
        placeholders = ", ".join("?" for _ in columns)
        with self._lock:
            cursor = self._conn.executemany(
                f"INSERT INTO tool_events ({', '.join(columns)}) VALUES ({placeholders})", rows
            )
            self._conn.commit()
            return cursor.rowcount

    def list_tool_events(
        self,
        *,
        query: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        tool: str | None = None,
        only_commands: bool = False,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        conditions: list[str] = []
        params: list[Any] = []
        if query:
            conditions.append(
                "(t.tool_name LIKE ? OR t.command LIKE ? OR t.arguments LIKE ? OR t.preview LIKE ?)"
            )
            needle = f"%{query}%"
            params.extend([needle, needle, needle, needle])
        if session_id:
            conditions.append("t.session_id = ?")
            params.append(session_id)
        if request_id:
            conditions.append("t.request_id = ?")
            params.append(request_id)
        if tool:
            conditions.append("t.tool_name = ?")
            params.append(tool)
        if only_commands:
            conditions.append("t.is_command = 1")
        if since:
            conditions.append("t.created_at >= ?")
            params.append(since)
        if until:
            conditions.append("t.created_at <= ?")
            params.append(until)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        limit = max(1, min(limit, 1000))
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) AS count FROM tool_events t {where}", tuple(params)
            ).fetchone()["count"]
            rows = self._conn.execute(
                f"SELECT t.*, r.model AS request_model, r.path AS request_path, "
                "r.status AS request_status, r.created_at AS request_created_at, "
                "r.session_id AS request_session_id "
                f"FROM tool_events t LEFT JOIN requests r ON r.id = t.request_id {where} "
                "ORDER BY t.created_at DESC, t.id DESC LIMIT ? OFFSET ?",
                (*params, limit, max(0, offset)),
            ).fetchall()
        return {
            "total": total,
            "limit": limit,
            "offset": max(0, offset),
            "items": [dict(row) for row in rows],
        }

    # ------------------------------------------------------------------- mcp

    def record_mcp_events(self, events: list[dict[str, Any]]) -> int:
        if not events:
            return 0
        columns = (
            "request_id",
            "session_id",
            "project",
            "created_at",
            "server",
            "method",
            "direction",
            "kind",
            "params",
            "result_preview",
            "is_error",
            "latency_ms",
            "raw",
        )
        now = utc_now()
        rows = []
        for event in events:
            event = {**event}
            event.setdefault("created_at", now)
            event.setdefault("is_error", 0)
            rows.append(tuple(event.get(column) for column in columns))
        placeholders = ", ".join("?" for _ in columns)
        with self._lock:
            cursor = self._conn.executemany(
                f"INSERT INTO mcp_events ({', '.join(columns)}) VALUES ({placeholders})", rows
            )
            self._conn.commit()
            return cursor.rowcount

    def list_mcp_events(
        self,
        *,
        query: str | None = None,
        session_id: str | None = None,
        request_id: str | None = None,
        server: str | None = None,
        method: str | None = None,
        errors_only: bool = False,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
        offset: int = 0,
    ) -> dict[str, Any]:
        conditions: list[str] = []
        params: list[Any] = []
        if query:
            conditions.append("(m.method LIKE ? OR m.server LIKE ? OR m.params LIKE ? OR m.result_preview LIKE ?)")
            needle = f"%{query}%"
            params.extend([needle, needle, needle, needle])
        if session_id:
            conditions.append("m.session_id = ?")
            params.append(session_id)
        if request_id:
            conditions.append("m.request_id = ?")
            params.append(request_id)
        if server:
            conditions.append("m.server = ?")
            params.append(server)
        if method:
            conditions.append("m.method = ?")
            params.append(method)
        if errors_only:
            conditions.append("m.is_error = 1")
        if since:
            conditions.append("m.created_at >= ?")
            params.append(since)
        if until:
            conditions.append("m.created_at <= ?")
            params.append(until)
        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        limit = max(1, min(limit, 1000))
        with self._lock:
            total = self._conn.execute(
                f"SELECT COUNT(*) AS count FROM mcp_events m {where}", tuple(params)
            ).fetchone()["count"]
            rows = self._conn.execute(
                f"SELECT m.*, r.status AS request_status, r.created_at AS request_created_at "
                f"FROM mcp_events m LEFT JOIN requests r ON r.id = m.request_id {where} "
                "ORDER BY m.created_at DESC, m.id DESC LIMIT ? OFFSET ?",
                (*params, limit, max(0, offset)),
            ).fetchall()
        return {
            "total": total,
            "limit": limit,
            "offset": max(0, offset),
            "items": [dict(row) for row in rows],
        }

    def tool_stats(self, hours: int = 24) -> dict[str, Any]:
        hours = max(1, min(int(hours), 24 * 30))
        now = datetime.now(UTC)
        since = (now - timedelta(hours=hours)).isoformat(timespec="milliseconds").replace("+00:00", "Z")
        with self._lock:
            totals = self._conn.execute(
                "SELECT COUNT(*) AS events, SUM(CASE WHEN is_command = 1 THEN 1 ELSE 0 END) AS commands, "
                "COUNT(DISTINCT tool_name) AS tools FROM tool_events WHERE created_at >= ?",
                (since,),
            ).fetchone()
            by_tool = self._conn.execute(
                "SELECT COALESCE(tool_name, '(unknown)') AS name, COUNT(*) AS count, "
                "SUM(CASE WHEN is_command = 1 THEN 1 ELSE 0 END) AS commands "
                "FROM tool_events WHERE created_at >= ? GROUP BY tool_name ORDER BY count DESC LIMIT 20",
                (since,),
            ).fetchall()
            top_commands = self._conn.execute(
                "SELECT command, tool_name, created_at, request_id FROM tool_events "
                "WHERE created_at >= ? AND is_command = 1 AND command IS NOT NULL "
                "ORDER BY created_at DESC LIMIT 20",
                (since,),
            ).fetchall()
            mcp_totals = self._conn.execute(
                "SELECT COUNT(*) AS calls, SUM(CASE WHEN is_error = 1 THEN 1 ELSE 0 END) AS errors "
                "FROM mcp_events WHERE created_at >= ?",
                (since,),
            ).fetchone()
            mcp_by_server = self._conn.execute(
                "SELECT COALESCE(server, '(unknown)') AS name, COUNT(*) AS count "
                "FROM mcp_events WHERE created_at >= ? GROUP BY server ORDER BY count DESC LIMIT 20",
                (since,),
            ).fetchall()
            mcp_by_method = self._conn.execute(
                "SELECT COALESCE(method, '(unknown)') AS name, COUNT(*) AS count "
                "FROM mcp_events WHERE created_at >= ? GROUP BY method ORDER BY count DESC LIMIT 20",
                (since,),
            ).fetchall()
        return {
            "events": totals["events"] or 0,
            "commands": totals["commands"] or 0,
            "tools": totals["tools"] or 0,
            "by_tool": [dict(row) for row in by_tool],
            "top_commands": [dict(row) for row in top_commands],
            "mcp_calls": mcp_totals["calls"] or 0,
            "mcp_errors": mcp_totals["errors"] or 0,
            "mcp_by_server": [dict(row) for row in mcp_by_server],
            "mcp_by_method": [dict(row) for row in mcp_by_method],
        }

    def close(self) -> None:
        with self._lock:
            self._conn.close()