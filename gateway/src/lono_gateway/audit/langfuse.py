"""Best-effort Langfuse tracing via the public ingestion API.

No Langfuse SDK dependency: a small, version-tolerant POST of trace and span
create events. Failures are logged and never block a request.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import httpx

from lono_gateway.models import utc_now
from lono_gateway.settings import LangfuseConfig

logger = logging.getLogger(__name__)

_TRUNCATED = "...[truncated by lono]"


class LangfuseTracer:
    def __init__(self, cfg: LangfuseConfig) -> None:
        self.cfg = cfg
        self._client: httpx.AsyncClient | None = None
        self._warned = False

    @property
    def enabled(self) -> bool:
        return self.cfg.configured

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.cfg.host.rstrip("/"),
                auth=(self.cfg.public_key, self.cfg.secret_key),
                timeout=10.0,
            )
        return self._client

    def _clip(self, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            if len(value) > self.cfg.max_chars:
                return value[: self.cfg.max_chars] + _TRUNCATED
            return value
        return value

    async def trace_request(
        self,
        *,
        request_id: str,
        session_id: str,
        project: str | None,
        mode: str,
        model: str | None,
        shape: str,
        request_original: Any,
        request_sanitized: Any,
        response_raw: Any,
        response_final: Any,
        metadata: dict[str, Any],
        spans: list[dict[str, Any]] | None = None,
    ) -> None:
        if not self.enabled:
            return
        timestamp = utc_now()
        trace_id = f"lono-{request_id}"
        events: list[dict[str, Any]] = [
            {
                "id": uuid.uuid4().hex,
                "type": "trace-create",
                "timestamp": timestamp,
                "body": {
                    "id": trace_id,
                    "name": "lono.request",
                    "timestamp": timestamp,
                    "sessionId": session_id,
                    "userId": project or session_id,
                    "tags": ["lono", mode, shape],
                    "input": self._clip(request_sanitized),
                    "output": self._clip(response_raw),
                    "metadata": {**metadata, "lono.request_id": request_id, "lono.mode": mode},
                },
            },
            {
                "id": uuid.uuid4().hex,
                "type": "span-create",
                "timestamp": timestamp,
                "body": {
                    "id": uuid.uuid4().hex,
                    "traceId": trace_id,
                    "name": "lono.original-request",
                    "startTime": timestamp,
                    "endTime": timestamp,
                    "input": self._clip(request_original),
                    "metadata": {"stage": "client-original", "model": model},
                },
            },
            {
                "id": uuid.uuid4().hex,
                "type": "span-create",
                "timestamp": timestamp,
                "body": {
                    "id": uuid.uuid4().hex,
                    "traceId": trace_id,
                    "name": "lono.final-response",
                    "startTime": timestamp,
                    "endTime": timestamp,
                    "output": self._clip(response_final),
                    "metadata": {"stage": "client-final", "model": model},
                },
            },
        ]
        for span in spans or []:
            events.append(
                {
                    "id": uuid.uuid4().hex,
                    "type": "span-create",
                    "timestamp": timestamp,
                    "body": {
                        "id": uuid.uuid4().hex,
                        "traceId": trace_id,
                        "startTime": timestamp,
                        "endTime": timestamp,
                        **span,
                    },
                }
            )
        try:
            response = await self._get_client().post("/api/public/ingestion", json={"batch": events})
            response.raise_for_status()
        except Exception as exc:  # noqa: BLE001 - tracing must never break traffic
            if not self._warned:
                self._warned = True
                logger.warning("langfuse trace delivery failed (%s); will keep retrying", exc.__class__.__name__)

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()