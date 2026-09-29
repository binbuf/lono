from __future__ import annotations

import httpx

from lono_gateway.main import create_app
from lono_gateway.settings import SecurityConfig, UpstreamConfig
from tests.conftest import UpstreamRecorder

ADMIN = {"x-lono-admin-key": "test-admin"}


def _app(settings: SecurityConfig, upstream: UpstreamRecorder):
    return create_app(settings, upstream_transport=httpx.MockTransport(upstream.handler))


def test_model_glob_routes_to_named_upstream(settings: SecurityConfig) -> None:
    settings.upstream.base_url = "http://default.local"
    settings.upstreams = [
        UpstreamConfig(name="openai-direct", base_url="http://openai.local", models=["gpt-*"])
    ]
    upstream = UpstreamRecorder()
    upstream.responder = lambda request, body: httpx.Response(200, json={"ok": True})

    app = _app(settings, upstream)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        client.post(
            "/v1/chat/completions",
            json={"model": "gpt-4o-mini", "messages": []},
            headers={"authorization": "Bearer x"},
        )
        assert upstream.requests[-1].url.host == "openai.local"

        client.post(
            "/v1/chat/completions",
            json={"model": "deepseek-chat", "messages": []},
            headers={"authorization": "Bearer x"},
        )
        assert upstream.requests[-1].url.host == "default.local"


def test_header_selects_upstream_and_provider_is_audited(settings: SecurityConfig) -> None:
    settings.upstream.base_url = "http://default.local"
    settings.upstreams = [UpstreamConfig(name="other", base_url="http://other.local")]
    upstream = UpstreamRecorder()
    upstream.responder = lambda request, body: httpx.Response(200, json={"ok": True})

    app = _app(settings, upstream)
    from fastapi.testclient import TestClient

    with TestClient(app) as client:
        response = client.post(
            "/v1/chat/completions",
            json={"model": "deepseek-chat", "messages": []},
            headers={"authorization": "Bearer x", "x-lono-upstream": "other"},
        )
        assert upstream.requests[-1].url.host == "other.local"
        record = client.get(
            f"/audit/requests/{response.headers['x-lono-request-id']}", headers=ADMIN
        ).json()
        assert record["provider"] == "other"

        listed = client.get("/audit/upstreams", headers=ADMIN).json()
        assert "other" in listed["active"]
        assert "default" in listed["active"]


def test_all_upstreams_helper_dedupes(settings: SecurityConfig) -> None:
    settings.upstreams = [
        UpstreamConfig(name="default", base_url="http://dup.local"),
        UpstreamConfig(name="extra", base_url="http://extra.local"),
    ]
    names = [upstream.name for upstream in settings.all_upstreams()]
    assert names == ["default", "extra"]