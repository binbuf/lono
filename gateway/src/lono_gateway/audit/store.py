"""SQLite-backed audit store with full-text search over all four stages."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from datetime import UTC
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
    "id, session_id, project, mode, api_shape, method, path, model, provider, stream, status, "
    "http_status, blocked, error, created_at, completed_at, latency_ms, prompt_tokens, "
    "completion_tokens, total_tokens, cost_usd, findings_count"
)

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
        return record

    def list_requests(
        self,
        *,
        query: str | None = None,
        session_id: str | None = None,
        model: str | None = None,
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
        if model:
            conditions.append("r.model = ?")
            params.append(model)
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
        return {"total": total, "limit": limit, "offset": max(0, offset), "items": [dict(r) for r in rows]}

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

    def close(self) -> None:
        with self._lock:
            self._conn.close()