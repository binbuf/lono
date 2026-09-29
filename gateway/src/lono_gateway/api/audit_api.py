"""Audit search API (admin-key protected)."""

from __future__ import annotations

import secrets
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import Response

router = APIRouter(prefix="/audit", tags=["audit"])


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


@router.get("/media/{sha256}")
def get_media(request: Request, sha256: str, _: None = Depends(require_admin)) -> Response:
    ref = request.app.state.store.get_media(sha256)
    if ref is None:
        raise HTTPException(status_code=404, detail="media not found")
    payload = request.app.state.media.read_sync(ref)
    if payload is None:
        raise HTTPException(status_code=404, detail="media object unavailable")
    return Response(content=payload, media_type=ref.get("mime") or "application/octet-stream")