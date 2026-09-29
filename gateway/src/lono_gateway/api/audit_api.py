"""Audit search API (admin-key protected)."""

from __future__ import annotations

import re
import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, Any, Literal

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field, ValidationError

from lono_gateway.models import normalize_key
from lono_gateway.settings import SecretRule

router = APIRouter(prefix="/audit", tags=["audit"])


class OverrideRequest(BaseModel):
    kind: Literal["category", "value"]
    category: str = Field(min_length=1)
    value: str | None = None
    minutes: int | None = Field(default=None, ge=1, le=60 * 24 * 365)
    note: str | None = None
    permanent: bool = False


def require_admin(request: Request) -> None:
    cfg = request.app.state.settings
    authorization = request.headers.get("authorization", "")
    token = (
        authorization[7:].strip()
        if authorization.lower().startswith("bearer ")
        else request.headers.get("x-lono-admin-key", "")
    )
    if not cfg.auth.admin_key:
        if cfg.auth.allow_unauthenticated_audit:
            return
        raise HTTPException(
            status_code=503,
            detail="audit API disabled: set LONO_ADMIN_KEY (or auth.allow_unauthenticated_audit)",
        )
    if not token or not secrets.compare_digest(token, cfg.auth.admin_key):
        raise HTTPException(status_code=401, detail="invalid admin key", headers={"WWW-Authenticate": "Bearer"})


@router.get("/stats")
def stats(request: Request, _: None = Depends(require_admin)) -> dict[str, Any]:
    return request.app.state.store.stats()


@router.get("/dashboard")
def dashboard(
    request: Request,
    hours: int = Query(default=24, ge=1, le=24 * 30),
    _: None = Depends(require_admin),
) -> dict[str, Any]:
    """Aggregated metrics for the console dashboard (trailing window)."""
    data = request.app.state.store.dashboard(hours)
    data["all_time"] = request.app.state.store.stats()
    return data


@router.get("/requests")
def list_requests(
    request: Request,
    q: str | None = Query(default=None, description="Full-text query across original/sanitized/raw/final"),
    session_id: str | None = None,
    model: str | None = None,
    status: str | None = None,
    mode: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = Query(default=50, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    _: None = Depends(require_admin),
) -> dict[str, Any]:
    return request.app.state.store.list_requests(
        query=q,
        session_id=session_id,
        model=model,
        status=status,
        mode=mode,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )


@router.get("/requests/{request_id}")
def get_request(request: Request, request_id: str, _: None = Depends(require_admin)) -> dict[str, Any]:
    record = request.app.state.store.get_request(request_id)
    if record is None:
        raise HTTPException(status_code=404, detail="request not found")
    return record


@router.delete("/requests/{request_id}")
def delete_request(request: Request, request_id: str, _: None = Depends(require_admin)) -> dict[str, Any]:
    deleted = request.app.state.store.delete_request(request_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="request not found")
    return {"deleted": True, "id": request_id}


@router.get("/sessions")
def list_sessions(
    request: Request, limit: int = Query(default=100, ge=1, le=1000), _: None = Depends(require_admin)
) -> dict[str, Any]:
    return {"items": request.app.state.store.list_sessions(limit)}


@router.get("/mappings")
def list_mappings(
    request: Request,
    scope: str | None = None,
    limit: int = Query(default=500, ge=1, le=5000),
    _: None = Depends(require_admin),
) -> dict[str, Any]:
    return {"items": request.app.state.store.list_mappings(scope, limit)}


@router.get("/overrides")
def list_overrides(
    request: Request,
    include_expired: bool = True,
    _: None = Depends(require_admin),
) -> dict[str, Any]:
    return {"items": request.app.state.store.list_overrides(include_expired)}


@router.post("/overrides")
def create_override(
    request: Request, body: OverrideRequest, _: None = Depends(require_admin)
) -> dict[str, Any]:
    cfg = request.app.state.settings
    if not cfg.overrides.enabled:
        raise HTTPException(status_code=400, detail="overrides are disabled in security.yaml")
    if body.kind == "value" and not body.value:
        raise HTTPException(status_code=422, detail="value is required for a value override")
    if body.permanent and not cfg.overrides.allow_permanent:
        raise HTTPException(status_code=400, detail="permanent overrides are disabled")

    expires_at: str | None = None
    if not body.permanent:
        minutes = body.minutes or cfg.overrides.default_max_minutes
        if minutes and minutes > 0:
            expiry = datetime.now(UTC) + timedelta(minutes=minutes)
            expires_at = expiry.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    value_key = normalize_key(body.value) if body.value else None
    record = request.app.state.store.add_override(
        kind=body.kind,
        category=body.category,
        value_key=value_key,
        value_display=body.value,
        note=body.note,
        expires_at=expires_at,
    )
    request.app.state.pipeline.invalidate_overrides()
    return record


@router.delete("/overrides/{override_id}")
def revoke_override(request: Request, override_id: int, _: None = Depends(require_admin)) -> dict[str, Any]:
    revoked = request.app.state.store.revoke_override(override_id)
    request.app.state.pipeline.invalidate_overrides()
    if not revoked:
        raise HTTPException(status_code=404, detail="override not found or already revoked")
    return {"revoked": True, "id": override_id}


# ----------------------------------------------------------------- config


@router.get("/config")
def get_config(request: Request, _: None = Depends(require_admin)) -> dict[str, Any]:
    """The live, secret-redacted configuration."""
    return request.app.state.config_manager.snapshot()


@router.patch("/config")
def patch_config(
    request: Request, body: Annotated[dict[str, Any], Body()], _: None = Depends(require_admin)
) -> dict[str, Any]:
    if not isinstance(body, dict):
        raise HTTPException(status_code=422, detail="config patch must be an object")
    try:
        return request.app.state.config_manager.update(body)
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc


@router.get("/upstreams")
def list_upstreams(request: Request, _: None = Depends(require_admin)) -> dict[str, Any]:
    registry = request.app.state.upstreams
    cfg = request.app.state.settings
    return {
        "active": registry.names(),
        "default": cfg.upstream.name,
        "items": [upstream.model_dump(mode="json") for upstream in cfg.all_upstreams()],
    }


# ----------------------------------------------------------- substitutions


class SubstitutionRequest(BaseModel):
    id: str | None = None
    pattern: str = Field(min_length=1)
    replacement: str
    match: Literal["word", "substring", "regex"] = "substring"
    case_sensitive: bool = False
    category: str = "SUBSTITUTION"
    enabled: bool = True
    note: str = ""


@router.get("/substitutions")
def list_substitutions(request: Request, _: None = Depends(require_admin)) -> dict[str, Any]:
    return {"items": request.app.state.config_manager.list_substitutions()}


@router.post("/substitutions")
def create_substitution(
    request: Request, body: SubstitutionRequest, _: None = Depends(require_admin)
) -> dict[str, Any]:
    try:
        return request.app.state.config_manager.add_substitution(body.model_dump(exclude_none=True))
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc


@router.delete("/substitutions/{substitution_id}")
def delete_substitution(
    request: Request, substitution_id: str, _: None = Depends(require_admin)
) -> dict[str, Any]:
    if not request.app.state.config_manager.remove_substitution(substitution_id):
        raise HTTPException(status_code=404, detail="substitution not found")
    return {"deleted": True, "id": substitution_id}


# ------------------------------------------------------------ secret rules


class SecretRuleRequest(BaseModel):
    id: str | None = None
    kind: str = "CUSTOM_SECRET"
    enabled: bool = True
    action: Literal["mask", "flag", "block"] | None = None
    match: Literal["regex", "word", "substring", "env"] = "regex"
    pattern: str = ""
    env_names: list[str] = Field(default_factory=list)
    case_sensitive: bool = True
    note: str = ""


@router.get("/secret-rules")
def list_secret_rules(request: Request, _: None = Depends(require_admin)) -> dict[str, Any]:
    return {"items": request.app.state.config_manager.list_secret_rules()}


@router.post("/secret-rules")
def create_secret_rule(
    request: Request, body: SecretRuleRequest, _: None = Depends(require_admin)
) -> dict[str, Any]:
    try:
        rule = SecretRule.model_validate(body.model_dump(exclude_none=True))
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=exc.errors()) from exc
    if rule.match == "env":
        if not [name for name in rule.env_names if name.strip()]:
            raise HTTPException(status_code=422, detail="at least one env var name is required")
    else:
        if not rule.pattern:
            raise HTTPException(status_code=422, detail="a pattern is required")
        if rule.match == "regex":
            try:
                re.compile(rule.pattern)
            except re.error as exc:
                raise HTTPException(status_code=422, detail=f"invalid regex: {exc}") from exc
    return request.app.state.config_manager.add_secret_rule(rule.model_dump(mode="json"))


@router.delete("/secret-rules/{rule_id}")
def delete_secret_rule(request: Request, rule_id: str, _: None = Depends(require_admin)) -> dict[str, Any]:
    if not request.app.state.config_manager.remove_secret_rule(rule_id):
        raise HTTPException(status_code=404, detail="secret rule not found")
    return {"deleted": True, "id": rule_id}


# ------------------------------------------------------------------- tools


@router.get("/tools")
def list_tools(
    request: Request,
    q: str | None = None,
    session_id: str | None = None,
    request_id: str | None = None,
    tool: str | None = None,
    only_commands: bool = False,
    since: str | None = None,
    until: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _: None = Depends(require_admin),
) -> dict[str, Any]:
    return request.app.state.store.list_tool_events(
        query=q,
        session_id=session_id,
        request_id=request_id,
        tool=tool,
        only_commands=only_commands,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )


@router.get("/tools/stats")
def tools_stats(
    request: Request, hours: int = Query(default=24, ge=1, le=24 * 30), _: None = Depends(require_admin)
) -> dict[str, Any]:
    return request.app.state.store.tool_stats(hours)


@router.get("/mcp")
def list_mcp(
    request: Request,
    q: str | None = None,
    session_id: str | None = None,
    request_id: str | None = None,
    server: str | None = None,
    method: str | None = None,
    errors_only: bool = False,
    since: str | None = None,
    until: str | None = None,
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    _: None = Depends(require_admin),
) -> dict[str, Any]:
    return request.app.state.store.list_mcp_events(
        query=q,
        session_id=session_id,
        request_id=request_id,
        server=server,
        method=method,
        errors_only=errors_only,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )


@router.get("/media/{sha256}")
def get_media(request: Request, sha256: str, _: None = Depends(require_admin)) -> Response:
    ref = request.app.state.store.get_media(sha256)
    if ref is None:
        raise HTTPException(status_code=404, detail="media not found")
    payload = request.app.state.media.read_sync(ref)
    if payload is None:
        raise HTTPException(status_code=404, detail="media object unavailable")
    return Response(content=payload, media_type=ref.get("mime") or "application/octet-stream")