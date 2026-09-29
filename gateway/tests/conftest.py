from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from lono_gateway.main import create_app
from lono_gateway.settings import SecurityConfig


class AsyncChunks(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def __aiter__(self):
        for chunk in self._chunks:
            yield chunk


class UpstreamRecorder:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.parsed_bodies: list[Any] = []
        self.responder = None

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        parsed = None
        if request.content:
            try:
                parsed = json.loads(request.content)
            except ValueError:
                parsed = None
        self.parsed_bodies.append(parsed)
        if self.responder is not None:
            return self.responder(request, parsed)
        return httpx.Response(200, json={"ok": True})

    @property
    def last_body(self) -> Any:
        return self.parsed_bodies[-1]


@pytest.fixture
def settings(tmp_path) -> SecurityConfig:
    cfg = SecurityConfig()
    cfg.detectors.pii.engine = "regex"
    cfg.pseudonymization.secret = "test-secret"
    cfg.audit.sqlite_path = str(tmp_path / "audit.db")
    cfg.audit.media.backend = "local"
    cfg.audit.media.local_path = str(tmp_path / "media")
    cfg.audit.langfuse.enabled = False
    cfg.auth.admin_key = "test-admin"
    return cfg


@pytest.fixture
def upstream() -> UpstreamRecorder:
    return UpstreamRecorder()


@pytest.fixture
def client(settings: SecurityConfig, upstream: UpstreamRecorder):
    app = create_app(settings, upstream_transport=httpx.MockTransport(upstream.handler))
    with TestClient(app) as test_client:
        yield test_client