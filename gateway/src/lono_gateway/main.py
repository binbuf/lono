"""FastAPI application factory."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from lono_gateway import __version__
from lono_gateway.api import audit_api, health, proxy, ui
from lono_gateway.audit.langfuse import LangfuseTracer
from lono_gateway.audit.media import MediaStore
from lono_gateway.audit.store import AuditStore
from lono_gateway.pipeline.engine import SecurityPipeline
from lono_gateway.settings import SecurityConfig, load_settings
from lono_gateway.upstream import UpstreamClient

logger = logging.getLogger(__name__)


def create_app(
    settings: SecurityConfig | None = None,
    upstream_transport: httpx.AsyncBaseTransport | None = None,
) -> FastAPI:
    cfg = settings or load_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        store = AuditStore(cfg.audit.sqlite_path, cfg.audit.retention_days)
        store.prune()
        media = MediaStore(cfg.audit.media, store)
        await media.ensure_ready()
        pipeline = SecurityPipeline(cfg, store)
        upstream = UpstreamClient(cfg.upstream, transport=upstream_transport)
        tracer = LangfuseTracer(cfg.audit.langfuse)

        app.state.store = store
        app.state.media = media
        app.state.pipeline = pipeline
        app.state.upstream = upstream
        app.state.tracer = tracer

        logger.info(
            "Lono ready: mode=%s upstream=%s audit_store=%s media=%s langfuse=%s",
            cfg.mode,
            cfg.upstream.base_url,
            cfg.audit.sqlite_path,
            cfg.audit.media.backend if cfg.audit.media.enabled else "disabled",
            "enabled" if tracer.enabled else "disabled",
        )
        try:
            yield
        finally:
            await upstream.aclose()
            await pipeline.aclose()
            await tracer.aclose()
            store.close()

    app = FastAPI(
        title="Lono Gateway",
        version=__version__,
        lifespan=lifespan,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = cfg
    app.include_router(health.router)
    app.include_router(proxy.router)
    app.include_router(audit_api.router)
    app.include_router(ui.router)

    @app.exception_handler(Exception)
    async def unhandled_exception(request: Request, exc: Exception) -> JSONResponse:  # noqa: ARG001
        logger.exception("unhandled gateway error on %s", request.url.path)
        return JSONResponse(
            status_code=500,
            content={"error": {"message": "internal gateway error", "type": "lono_error"}},
        )

    return app


def app_factory() -> FastAPI:
    """Entry point for `uvicorn --factory lono_gateway.main:app_factory`."""
    return create_app()