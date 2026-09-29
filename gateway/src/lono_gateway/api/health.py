"""Health and readiness endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse

from lono_gateway import __version__

router = APIRouter()


@router.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok", "service": "lono-gateway", "version": __version__}


@router.get("/readyz")
async def readyz(request: Request) -> JSONResponse:
    checks: dict[str, str] = {}
    try:
        request.app.state.store.stats()
        checks["audit_store"] = "ok"
    except Exception as exc:  # noqa: BLE001
        checks["audit_store"] = f"error: {exc.__class__.__name__}"
    checks["media"] = "ok" if request.app.state.media else "unavailable"
    healthy = all(value == "ok" for value in checks.values())
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={"status": "ready" if healthy else "degraded", "checks": checks},
    )


@router.get("/")
async def root(request: Request) -> dict:
    cfg = request.app.state.settings
    return {
        "service": "lono-gateway",
        "version": __version__,
        "mode": cfg.mode,
        "openai_compatible_endpoints": [
            "POST /v1/chat/completions",
            "POST /v1/completions",
            "POST /v1/embeddings",
            "GET /v1/models",
        ],
        "anthropic_compatible_endpoints": ["POST /v1/messages"],
        "audit_endpoints": [
            "GET /audit/requests",
            "GET /audit/requests/{id}",
            "GET /audit/sessions",
            "GET /audit/stats",
        ],
    }