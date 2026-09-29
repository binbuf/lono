"""MCP proxy endpoints: audited JSON-RPC forwarding to MCP servers.

  POST /v1/mcp/{server}   forward a JSON-RPC request
  POST /v1/mcp            forward using the x-lono-mcp-server header (or the
                          only configured server)
  GET  /v1/mcp/{server}   SSE passthrough (audited)

Every call is recorded as an audit request and its JSON-RPC messages are
persisted as ``mcp_events`` linked back to that request.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from lono_gateway.audit.tools import mcp_event

router = APIRouter()

_HOP_BY_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
}


def _session_identity(request: Request) -> tuple[str, str | None]:
    headers = request.headers
    session = headers.get("x-lono-session-id") or headers.get("x-session-id")
    if not session:
        authorization = headers.get("authorization") or headers.get("x-api-key") or ""
        digest = hashlib.sha256(authorization.encode("utf-8")).hexdigest()[:12]
        session = f"key-{digest}"
    return str(session), headers.get("x-lono-project")


def _forward_headers(request: Request, server_headers: dict[str, str]) -> dict[str, str]:
    headers = {
        key: value
        for key, value in request.headers.items()
        if key.lower() not in _HOP_BY_HOP and not key.lower().startswith("x-lono-")
    }
    headers.update(server_headers)
    headers.setdefault("content-type", "application/json")
    headers.setdefault("accept", "application/json, text/event-stream")
    return headers


def _resolve_server(request: Request, path_server: str | None) -> str | Response:
    state = request.app.state
    registry = state.mcp
    name = path_server or request.headers.get("x-lono-mcp-server") or registry.default_name()
    if not name or registry.get(name) is None:
        return JSONResponse(
            status_code=404,
            content={
                "error": {
                    "message": f"unknown MCP server: {name}",
                    "type": "lono_error",
                    "code": "unknown_mcp_server",
                }
            },
        )
    return name


def _record_request(state, request: Request, server: str, session: str, project: str | None, path: str) -> str:
    request_id = uuid.uuid4().hex
    if state.settings.audit.enabled:
        state.store.begin_request(
            id=request_id,
            session_id=session,
            project=project,
            mode=state.settings.mode,
            api_shape="mcp",
            method=request.method,
            path=path,
            provider=server,
            status="pending",
            request_sanitized=None,
            findings_json="[]",
            findings_count=0,
            client_meta_json=json.dumps(
                {"user-agent": request.headers.get("user-agent", ""), "mcp-server": server},
                ensure_ascii=False,
            ),
        )
    return request_id


def _record_mcp(state, message, *, server, direction, request_id, session, project, latency_ms=None) -> None:
    if not state.settings.audit.enabled:
        return
    if isinstance(message, list):
        state.store.record_mcp_events(
            [
                mcp_event(
                    item,
                    server=server,
                    direction=direction,
                    request_id=request_id,
                    session_id=session,
                    project=project,
                    latency_ms=latency_ms,
                    preview_chars=state.settings.tools.preview_chars,
                )
                for item in message
            ]
        )
    else:
        state.store.record_mcp_events(
            [
                mcp_event(
                    message,
                    server=server,
                    direction=direction,
                    request_id=request_id,
                    session_id=session,
                    project=project,
                    latency_ms=latency_ms,
                    preview_chars=state.settings.tools.preview_chars,
                )
            ]
        )


@router.post("/v1/mcp")
async def mcp_post_default(request: Request) -> Response:
    return await _handle(request, None)


@router.post("/v1/mcp/{server}")
async def mcp_post(request: Request, server: str) -> Response:
    return await _handle(request, server)


@router.get("/v1/mcp/{server}")
async def mcp_stream(request: Request, server: str) -> Response:
    return await _handle(request, server, force_stream=True)


async def _handle(request: Request, path_server: str | None, force_stream: bool = False) -> Response:
    state = request.app.state
    resolved = _resolve_server(request, path_server)
    if isinstance(resolved, Response):
        return resolved
    server_name = resolved
    server, client = state.mcp.get(server_name)  # type: ignore[misc]

    session, project = _session_identity(request)
    body = await request.body()
    request_id = _record_request(state, request, server_name, session, project, request.url.path)

    if body:
        try:
            _record_mcp(
                state,
                json.loads(body),
                server=server_name,
                direction="request",
                request_id=request_id,
                session=session,
                project=project,
            )
        except (ValueError, TypeError):
            pass

    started = time.perf_counter()
    try:
        upstream = await client.request(
            request.method,
            "",
            headers=_forward_headers(request, server.headers),
            content=body,
        )
    except httpx.HTTPError as exc:
        latency = int((time.perf_counter() - started) * 1000)
        _finish(state, request_id, "error", 502, latency, error=f"upstream: {exc.__class__.__name__}")
        return JSONResponse(
            status_code=502,
            headers={"x-lono-request-id": request_id},
            content={
                "error": {
                    "message": "MCP server unreachable",
                    "type": "lono_error",
                    "code": "mcp_upstream_error",
                }
            },
        )

    content_type = upstream.headers.get("content-type", "")
    headers = {key: value for key, value in upstream.headers.items() if key.lower() not in _HOP_BY_HOP}
    headers["x-lono-request-id"] = request_id

    if force_stream or "text/event-stream" in content_type:
        async def generate():
            captured: list[bytes] = []
            try:
                async for chunk in upstream.aiter_bytes():
                    captured.append(chunk)
                    yield chunk
            finally:
                await upstream.aclose()
                latency = int((time.perf_counter() - started) * 1000)
                raw = b"".join(captured).decode("utf-8", errors="replace")
                _record_stream_events(state, raw, server_name, request_id, session, project, latency)
                _finish(state, request_id, "completed", upstream.status_code, latency, response_raw=raw)

        return StreamingResponse(generate(), status_code=upstream.status_code, headers=headers)

    raw_bytes = await upstream.aread()
    await upstream.aclose()
    raw_text = raw_bytes.decode("utf-8", errors="replace")
    latency = int((time.perf_counter() - started) * 1000)

    try:
        parsed = json.loads(raw_text)
        _record_mcp(
            state,
            parsed,
            server=server_name,
            direction="response",
            request_id=request_id,
            session=session,
            project=project,
            latency_ms=latency,
        )
    except (ValueError, TypeError):
        pass

    status = "completed" if upstream.status_code < 400 else "upstream_error"
    _finish(
        state,
        request_id,
        status,
        upstream.status_code,
        latency,
        response_raw=raw_text,
        error=None if upstream.status_code < 400 else f"upstream status {upstream.status_code}",
    )
    return Response(
        content=raw_bytes,
        status_code=upstream.status_code,
        headers=headers,
        media_type=content_type or None,
    )


def _record_stream_events(
    state, raw: str, server: str, request_id: str, session: str, project: str | None, latency: int
) -> None:
    if not state.settings.audit.enabled:
        return
    events = []
    for line in raw.splitlines():
        line = line.strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload or payload == "[DONE]":
            continue
        try:
            events.append(
                mcp_event(
                    json.loads(payload),
                    server=server,
                    direction="response",
                    request_id=request_id,
                    session_id=session,
                    project=project,
                    latency_ms=latency,
                    preview_chars=state.settings.tools.preview_chars,
                )
            )
        except (ValueError, TypeError):
            continue
    if events:
        state.store.record_mcp_events(events)


def _finish(
    state,
    request_id: str,
    status: str,
    http_status: int | None,
    latency_ms: int,
    *,
    response_raw: str | None = None,
    error: str | None = None,
) -> None:
    if not state.settings.audit.enabled:
        return
    fields: dict = {
        "status": status,
        "http_status": http_status,
        "latency_ms": latency_ms,
        "error": error,
        "findings_json": "[]",
        "findings_count": 0,
    }
    if response_raw is not None:
        fields["response_raw"] = response_raw[: state.settings.audit.max_payload_bytes]
    state.store.complete_request(request_id, **fields)