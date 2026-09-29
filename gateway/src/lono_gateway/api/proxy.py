"""OpenAI-compatible proxy endpoints with security pipeline and audit capture.

Exposed endpoints:
  POST /v1/chat/completions   OpenAI chat (streaming and non-streaming)
  POST /v1/completions        OpenAI legacy completions
  POST /v1/embeddings         passthrough (audited)
  POST /v1/messages           Anthropic messages (streaming and non-streaming)
  POST /v1/responses          passthrough (audited)
  GET  /v1/models             passthrough
  ANY  /v1/{path}             passthrough (audited)
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from typing import Any

import httpx
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from lono_gateway.audit.media import externalize_media
from lono_gateway.audit.tools import extract_tool_events
from lono_gateway.models import Finding, RequestContext
from lono_gateway.pipeline.shapes import extract_usage
from lono_gateway.pipeline.streaming import StreamOutcome, StreamTranslator
from lono_gateway.rehydrator import mapping_scopes

logger = logging.getLogger(__name__)

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
}

_TRUNCATION_MARKER = "\n...[lono:audit payload truncated]"


def _response_headers(headers: httpx.Headers) -> dict[str, str]:
    return {key: value for key, value in headers.items() if key.lower() not in _HOP_BY_HOP}


def _cap_text(text: str, limit: int) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + _TRUNCATION_MARKER


def _error_body(message: str, request_id: str, code: str = "lono_error", kinds: list[str] | None = None) -> dict:
    body: dict[str, Any] = {
        "error": {
            "message": message,
            "type": "lono_policy_violation" if code == "blocked" else "lono_error",
            "code": code,
            "request_id": request_id,
        }
    }
    if kinds:
        body["error"]["detectors"] = kinds
    return body


def _findings_json(findings: list[Finding]) -> str:
    return json.dumps([finding.model_dump() for finding in findings], ensure_ascii=False)


def _parse_cost(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        return None


def _credential_fingerprint(request: Request) -> str:
    """A non-reversible fingerprint of the caller credential (never the raw key)."""
    credential = request.headers.get("authorization") or request.headers.get("x-api-key") or ""
    return hashlib.sha256(credential.encode("utf-8")).hexdigest()[:12]


def _session_identity(request: Request, payload: dict | None) -> tuple[str, str | None]:
    headers = request.headers
    metadata = payload.get("metadata") if isinstance(payload, dict) else None
    metadata = metadata if isinstance(metadata, dict) else {}
    project = headers.get("x-lono-project") or metadata.get("project")

    session = headers.get("x-lono-session-id") or headers.get("x-session-id")
    if not session and isinstance(payload, dict):
        session = metadata.get("session_id") or payload.get("user")
    if not session:
        session = f"key-{_credential_fingerprint(request)}"
    return str(session), project


def _client_id(request: Request) -> str:
    """Stable anonymous id for the connecting client.

    Derived from the credential, any explicit ``x-lono-client`` name and the
    user agent, so two workloads behind the same key but different harnesses
    stay distinct. Only the hash is stored.
    """
    credential = request.headers.get("authorization") or request.headers.get("x-api-key") or ""
    named = request.headers.get("x-lono-client", "")
    user_agent = request.headers.get("user-agent", "")
    material = "\x00".join((credential, named, user_agent))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


# Headers worth showing in the HTTP inspector. Anything credential-shaped is
# dropped even if it somehow matched, so keys/tokens/cookies never persist.
_SAFE_HEADER_NAMES = {
    "accept",
    "accept-encoding",
    "accept-language",
    "content-type",
    "host",
    "origin",
    "referer",
    "x-forwarded-for",
    "x-real-ip",
    "x-request-id",
}
_UNSAFE_HEADER_TOKENS = (
    "authorization",
    "auth",
    "cookie",
    "key",
    "token",
    "secret",
    "password",
    "credential",
    "signature",
)


_SAFE_HEADER_PREFIXES = ("x-lono-", "x-stainless-")


def _short_user_agent(value: str) -> str:
    """A compact label from the leading product token of a User-Agent."""
    token = value.strip().split(" ", 1)[0]
    name, separator, version = token.partition("/")
    if separator:
        return f"{name.replace('_', ' ')} {version}".strip()
    return token


def _client_meta(request: Request) -> dict[str, str]:
    meta: dict[str, str] = {}
    for key, value in request.headers.items():
        lowered = key.lower()
        if lowered == "x-lono-mode" or any(token in lowered for token in _UNSAFE_HEADER_TOKENS):
            continue
        if lowered == "user-agent" or lowered in _SAFE_HEADER_NAMES or lowered.startswith(_SAFE_HEADER_PREFIXES):
            meta[lowered] = value[:300]
            if len(meta) >= 24:
                break
    user_agent = request.headers.get("user-agent", "")
    short = _short_user_agent(user_agent)
    if short:
        meta["client"] = short
    if request.client and request.client.host:
        meta["client_host"] = request.client.host
    http_version = request.scope.get("http_version")
    if http_version:
        meta["http_version"] = http_version
    return meta


def _shape_for_path(path: str) -> str:
    if path == "/v1/chat/completions":
        return "openai.chat"
    if path == "/v1/completions":
        return "openai.completions"
    if path == "/v1/messages":
        return "anthropic.messages"
    if path == "/v1/responses":
        return "openai.responses"
    if path == "/v1/embeddings":
        return "passthrough"
    return "passthrough"


@router.post("/v1/chat/completions")
async def chat_completions(request: Request) -> Response:
    return await _handle(request)


@router.post("/v1/completions")
async def completions(request: Request) -> Response:
    return await _handle(request)


@router.post("/v1/messages")
async def anthropic_messages(request: Request) -> Response:
    return await _handle(request)


@router.post("/v1/embeddings")
async def embeddings(request: Request) -> Response:
    return await _handle(request)


@router.post("/v1/responses")
async def responses(request: Request) -> Response:
    return await _handle(request)


@router.get("/v1/models")
async def models(request: Request) -> Response:
    return await _handle(request)


@router.api_route(
    "/v1/{rest:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]
)
async def passthrough(request: Request, rest: str) -> Response:
    return await _handle(request)


async def _handle(request: Request) -> Response:
    state = request.app.state
    cfg = state.settings
    started = time.perf_counter()
    request_id = uuid.uuid4().hex
    path = request.url.path
    shape = _shape_for_path(path)

    body = await request.body()
    if len(body) > cfg.upstream.max_body_bytes:
        return JSONResponse(
            status_code=413,
            content=_error_body("Request body exceeds the configured Lono limit", request_id, "payload_too_large"),
        )

    payload: dict | None = None
    if body:
        try:
            parsed = json.loads(body)
            if isinstance(parsed, dict):
                payload = parsed
        except (ValueError, TypeError):
            payload = None

    stream_requested = bool(payload.get("stream")) if payload else False
    session_id, project = _session_identity(request, payload)
    client_id = _client_id(request)
    mode = cfg.mode
    if cfg.allow_client_mode_override:
        override = (request.headers.get("x-lono-mode") or "").strip().lower()
        if override in {"observe", "sanitize", "enforce"}:
            mode = override  # type: ignore[assignment]

    ctx = RequestContext(
        request_id=request_id,
        session_id=session_id,
        project=project,
        mode=mode,
        shape=shape,  # type: ignore[arg-type]
        path=path,
        stream=stream_requested,
        client_meta=_client_meta(request),
    )

    upstream = state.upstreams.select(
        path=path,
        model=(payload or {}).get("model") if isinstance(payload, dict) else None,
        headers=request.headers,
    )

    # 1. Audit the original exactly as it arrived (media externalized into CAS).
    original_audit, original_media = await externalize_media(payload, state.media, request_id)

    # 2. Security pipeline (in observe mode this leaves the payload untouched).
    findings: list[Finding] = []
    blocked = False
    block_kinds: list[str] = []
    if payload is not None:
        try:
            outcome = await state.pipeline.process_request(shape, payload, ctx)
        except Exception:  # noqa: BLE001 - fail closed on internal errors when configured
            logger.exception("security pipeline failed for %s", request_id)
            return JSONResponse(
                status_code=500,
                content=_error_body("Lono security pipeline failed", request_id, "pipeline_error"),
            )
        findings = list(outcome.findings)
        blocked = outcome.blocked
        block_kinds = outcome.block_kinds

    sanitized_audit, sanitized_media = await externalize_media(payload, state.media, request_id)
    media_refs = original_media + sanitized_media

    if cfg.audit.enabled:
        state.store.begin_request(
            id=request_id,
            session_id=ctx.session_id,
            project=ctx.project,
            mode=ctx.mode,
            api_shape=shape,
            method=request.method,
            path=path,
            model=(payload or {}).get("model"),
            provider=upstream.name,
            client_id=client_id,
            stream=1 if stream_requested else 0,
            status="pending",
            request_original=json.dumps(original_audit, ensure_ascii=False)
            if cfg.audit.capture_original
            else None,
            request_sanitized=json.dumps(sanitized_audit, ensure_ascii=False) if payload is not None else None,
            findings_json=_findings_json(findings),
            findings_count=len(findings),
            client_meta_json=json.dumps(ctx.client_meta, ensure_ascii=False),
            media_json=json.dumps(media_refs, ensure_ascii=False),
        )
        state.store.record_tool_events(
            extract_tool_events(
                original_audit,
                shape=shape,
                source="request",
                request_id=request_id,
                session_id=ctx.session_id,
                project=ctx.project,
                cfg=cfg.tools,
            )
        )

    if blocked:
        await _finish(
            state,
            request_id,
            started,
            status="blocked",
            http_status=403,
            blocked=True,
            findings=findings,
            error=f"blocked: {','.join(sorted(set(block_kinds)))}",
        )
        return JSONResponse(
            status_code=403,
            headers={"x-lono-request-id": request_id},
            content=_error_body(
                "Blocked by Lono security gateway: policy violation detected before provider egress",
                request_id,
                "blocked",
                sorted(set(block_kinds)),
            ),
        )

    # 3. Send the sanitized payload upstream.
    upstream_body = (
        json.dumps(payload, ensure_ascii=False).encode("utf-8")
        if payload is not None
        else body
    )
    headers = upstream.filter_headers(request.headers)
    upstream_path = path + (f"?{request.url.query}" if request.url.query else "")
    try:
        upstream_response = await upstream.send(
            request.method, upstream_path, headers=headers, content=upstream_body, stream=stream_requested
        )
    except httpx.HTTPError as exc:
        logger.warning("upstream error for %s: %s", request_id, exc.__class__.__name__)
        await _finish(
            state,
            request_id,
            started,
            status="error",
            http_status=502,
            findings=findings,
            error=f"upstream: {exc.__class__.__name__}",
        )
        return JSONResponse(
            status_code=502,
            headers={"x-lono-request-id": request_id},
            content=_error_body("Upstream provider unreachable", request_id, "upstream_error"),
        )

    content_type = upstream_response.headers.get("content-type", "")
    if stream_requested and "text/event-stream" in content_type:
        return await _stream(request, upstream_response, translator_shape=shape, ctx=ctx, findings=findings)

    return await _buffered(request, upstream_response, ctx, findings, started)


async def _buffered(
    request: Request,
    upstream_response: httpx.Response,
    ctx: RequestContext,
    request_findings: list[Finding],
    started: float,
) -> Response:
    state = request.app.state
    cfg = state.settings
    raw_bytes = await upstream_response.aread()
    await upstream_response.aclose()
    raw_text = raw_bytes.decode("utf-8", errors="replace")
    headers = _response_headers(upstream_response.headers)
    headers["x-lono-request-id"] = ctx.request_id
    content_type = upstream_response.headers.get("content-type", "")

    if upstream_response.status_code >= 400 or "application/json" not in content_type:
        await _finish(
            state,
            ctx.request_id,
            started,
            status="completed" if upstream_response.status_code < 400 else "upstream_error",
            http_status=upstream_response.status_code,
            findings=request_findings,
            response_raw=_cap_text(raw_text, cfg.audit.max_payload_bytes),
            error=None if upstream_response.status_code < 400 else f"upstream status {upstream_response.status_code}",
            model=None,
        )
        return Response(
            content=raw_bytes,
            status_code=upstream_response.status_code,
            headers=headers,
            media_type=content_type or None,
        )

    try:
        response_payload = json.loads(raw_text)
    except (ValueError, TypeError):
        response_payload = None

    findings = list(request_findings)
    final_text = raw_text
    model = None
    response_audit: Any = response_payload
    media_refs: list[dict] = []
    usage: dict = {}
    if isinstance(response_payload, dict) and ctx.shape in {"openai.chat", "openai.completions", "anthropic.messages"}:
        response_outcome = await state.pipeline.process_response(ctx.shape, response_payload, ctx)
        findings.extend(response_outcome.findings)
        final_text = json.dumps(response_payload, ensure_ascii=False)
        response_audit, media_refs = await externalize_media(response_payload, state.media, ctx.request_id)
        model = response_payload.get("model")
        usage = extract_usage(ctx.shape, response_payload)
    elif isinstance(response_payload, dict):
        response_audit, media_refs = await externalize_media(response_payload, state.media, ctx.request_id)
        model = response_payload.get("model")
        usage = extract_usage("passthrough", response_payload)

    if cfg.audit.enabled:
        state.store.record_tool_events(
            extract_tool_events(
                response_payload,
                shape=ctx.shape,
                source="response",
                request_id=ctx.request_id,
                session_id=ctx.session_id,
                project=ctx.project,
                cfg=cfg.tools,
            )
        )

    await _finish(
        state,
        ctx.request_id,
        started,
        status="completed",
        http_status=upstream_response.status_code,
        findings=findings,
        response_raw=_cap_text(raw_text, cfg.audit.max_payload_bytes),
        response_final=_cap_text(final_text, cfg.audit.max_payload_bytes),
        model=model,
        usage=usage,
        cost=_parse_cost(upstream_response.headers.get("x-litellm-response-cost")),
        media=media_refs,
        langfuse_payloads=(response_audit, final_text),
    )
    headers["content-type"] = "application/json"
    headers["x-lono-request-id"] = ctx.request_id
    return Response(
        content=final_text.encode("utf-8"),
        status_code=upstream_response.status_code,
        headers=headers,
        media_type="application/json",
    )


async def _stream(
    request: Request,
    upstream_response: httpx.Response,
    translator_shape: str,
    ctx: RequestContext,
    findings: list[Finding],
) -> Response:
    state = request.app.state
    cfg = state.settings
    mappings = state.store.reverse_mappings(
        mapping_scopes(
            ctx.session_id,
            cfg.pseudonymization.stable_across_sessions,
        )
    )
    translator = StreamTranslator(translator_shape, mappings)
    headers = _response_headers(upstream_response.headers)
    headers["x-lono-request-id"] = ctx.request_id
    media_type = upstream_response.headers.get("content-type", "text/event-stream").split(";")[0]

    async def generate():
        disconnected = False
        error: str | None = None
        outcome: StreamOutcome | None = None
        try:
            async for chunk in upstream_response.aiter_bytes():
                for out in translator.feed(chunk):
                    yield out
        except asyncio.CancelledError:
            disconnected = True
            raise
        except Exception as exc:  # noqa: BLE001 - stream errors are recorded, not hidden
            error = exc.__class__.__name__
            logger.warning("stream error for %s: %s", ctx.request_id, error)
        finally:
            try:
                extra, outcome = translator.flush()
            except Exception:  # noqa: BLE001
                extra, outcome = None, None
            if not disconnected and extra:
                try:
                    yield extra
                except Exception:  # noqa: BLE001 - client vanished mid-flush
                    disconnected = True
            await upstream_response.aclose()
            await _finish_stream(
                state, ctx, findings, translator, outcome, disconnected=disconnected, error=error
            )

    return StreamingResponse(
        generate(),
        status_code=upstream_response.status_code,
        media_type=media_type,
        headers=headers,
    )


async def _finish_stream(
    state,
    ctx: RequestContext,
    request_findings: list[Finding],
    translator: StreamTranslator,
    outcome: StreamOutcome | None,
    *,
    disconnected: bool,
    error: str | None,
) -> None:
    cfg = state.settings
    findings = list(request_findings)
    assembled = outcome.assembled if outcome else translator.assembled()
    raw_text = outcome.raw_text if outcome else ""
    usage = extract_usage(ctx.shape, assembled)
    if outcome and outcome.raw_truncated:
        raw_text = _cap_text(raw_text, cfg.audit.max_payload_bytes)
    final_text = json.dumps(assembled, ensure_ascii=False) if assembled else ""
    if cfg.output_scan.enabled and final_text:
        try:
            findings.extend(await state.pipeline.scan_text_findings(_stream_text(assembled), ctx))
        except Exception as exc:  # noqa: BLE001
            logger.warning("post-stream output scan failed: %s", exc.__class__.__name__)
    status = "client_disconnected" if disconnected else ("error" if error else "completed")
    if cfg.audit.enabled:
        state.store.record_tool_events(
            extract_tool_events(
                assembled,
                shape=ctx.shape,
                source="response",
                request_id=ctx.request_id,
                session_id=ctx.session_id,
                project=ctx.project,
                cfg=cfg.tools,
            )
        )
    await _finish(
        state,
        ctx.request_id,
        None,
        status=status,
        http_status=200,
        findings=findings,
        response_raw=_cap_text(raw_text, cfg.audit.max_payload_bytes),
        response_final=_cap_text(final_text, cfg.audit.max_payload_bytes),
        model=assembled.get("model") if isinstance(assembled, dict) else None,
        usage=usage,
        error=error,
        langfuse_payloads=(assembled, final_text),
    )


def _stream_text(assembled: dict) -> str:
    if not isinstance(assembled, dict):
        return ""
    parts: list[str] = []
    for choice in assembled.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if isinstance(message, dict) and isinstance(message.get("content"), str):
            parts.append(message["content"])
    content = assembled.get("content")
    if isinstance(content, list):
        for block in content:
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                parts.append(block["text"])
    return "\n".join(parts)


async def _finish(
    state,
    request_id: str,
    started: float | None,
    *,
    status: str,
    http_status: int | None,
    findings: list[Finding],
    blocked: bool = False,
    error: str | None = None,
    response_raw: str | None = None,
    response_final: str | None = None,
    model: str | None = None,
    usage: dict | None = None,
    cost: float | None = None,
    media: list[dict] | None = None,
    langfuse_payloads: tuple[Any, Any] | None = None,
) -> None:
    cfg = state.settings
    usage = usage or {}
    latency_ms = int((time.perf_counter() - started) * 1000) if started is not None else None
    if cfg.audit.enabled:
        fields: dict[str, Any] = {
            "status": status,
            "http_status": http_status,
            "blocked": 1 if blocked else 0,
            "error": error,
            "latency_ms": latency_ms,
            "findings_json": _findings_json(findings),
            "findings_count": len(findings),
        }
        if response_raw is not None:
            fields["response_raw"] = response_raw
        if response_final is not None:
            fields["response_final"] = response_final
        if model:
            fields["model"] = model
        for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
            if usage.get(key) is not None:
                fields[key] = usage[key]
        if cost is not None:
            fields["cost_usd"] = cost
        if media:
            fields["media_json"] = json.dumps(media, ensure_ascii=False)
        state.store.complete_request(request_id, **fields)

    tracer = state.tracer
    if tracer.enabled:
        record = state.store.get_request(request_id) if cfg.audit.enabled else None
        metadata = {
            "model": model,
            "status": status,
            "http_status": http_status,
            "latency_ms": latency_ms,
            "findings_count": len(findings),
            "blocked": blocked,
            "tokens": usage.get("total_tokens"),
            "cost_usd": cost,
            "error": error,
        }
        original = (record or {}).get("request_original")
        sanitized = (record or {}).get("request_sanitized")
        if langfuse_payloads is not None:
            response_raw_obj, response_final_obj = langfuse_payloads
        else:
            response_raw_obj = (record or {}).get("response_raw")
            response_final_obj = (record or {}).get("response_final")
        await tracer.trace_request(
            request_id=request_id,
            session_id=(record or {}).get("session_id") or "unknown",
            project=(record or {}).get("project"),
            mode=(record or {}).get("mode") or cfg.mode,
            model=model,
            shape=(record or {}).get("api_shape") or "passthrough",
            request_original=original,
            request_sanitized=sanitized,
            response_raw=response_raw_obj,
            response_final=response_final_obj,
            metadata=metadata,
        )