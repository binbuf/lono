from __future__ import annotations

import json

import httpx
from fastapi.testclient import TestClient

from lono_gateway.main import create_app
from lono_gateway.settings import McpServerConfig, SecurityConfig

ADMIN = {"x-lono-admin-key": "test-admin"}


def _make_client(settings: SecurityConfig) -> TestClient:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if request.method == "GET":
            return httpx.Response(
                200,
                headers={"content-type": "text/event-stream"},
                content="data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"ok\":true}}\n\n",
            )
        payload = json.loads(request.content) if request.content else None
        method = payload.get("method") if isinstance(payload, dict) else None
        request_id = payload.get("id") if isinstance(payload, dict) else None
        return httpx.Response(
            200,
            json={"jsonrpc": "2.0", "id": request_id, "result": {"method": method}},
        )

    app = create_app(settings, mcp_transport=httpx.MockTransport(handler))
    return TestClient(app)


def test_mcp_jsonrpc_is_forwarded_and_audited(settings: SecurityConfig) -> None:
    settings.mcp.servers = [McpServerConfig(name="files", url="http://mcp.local")]
    client = _make_client(settings)
    with client:
        response = client.post(
            "/v1/mcp/files",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
        )
        assert response.status_code == 200
        assert response.json()["result"]["method"] == "tools/list"
        request_id = response.headers["x-lono-request-id"]

        record = client.get(f"/audit/requests/{request_id}", headers=ADMIN).json()
        assert record["api_shape"] == "mcp"
        assert record["provider"] == "files"
        assert record["status"] == "completed"

        events = client.get("/audit/mcp", headers=ADMIN).json()["items"]
        assert any(item["direction"] == "request" and item["method"] == "tools/list" for item in events)
        assert any(item["direction"] == "response" for item in events)
        assert all(item["request_id"] == request_id for item in events)


def test_mcp_default_uses_only_server(settings: SecurityConfig) -> None:
    settings.mcp.servers = [McpServerConfig(name="only", url="http://mcp.local")]
    client = _make_client(settings)
    with client:
        response = client.post("/v1/mcp", json={"jsonrpc": "2.0", "id": 9, "method": "ping"})
        assert response.status_code == 200
        assert response.json()["result"]["method"] == "ping"


def test_mcp_unknown_server_404(client) -> None:
    response = client.post("/v1/mcp/nope", json={"jsonrpc": "2.0", "id": 1, "method": "ping"})
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "unknown_mcp_server"


def test_mcp_stream_records_events(settings: SecurityConfig) -> None:
    settings.mcp.servers = [McpServerConfig(name="files", url="http://mcp.local")]
    client = _make_client(settings)
    with client:
        response = client.get("/v1/mcp/files")
        assert response.status_code == 200
        request_id = response.headers["x-lono-request-id"]
        events = client.get(f"/audit/mcp?request_id={request_id}", headers=ADMIN).json()["items"]
        assert any(item["direction"] == "response" and item["kind"] == "response" for item in events)