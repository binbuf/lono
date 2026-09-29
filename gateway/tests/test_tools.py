from __future__ import annotations

import json

import httpx

ADMIN = {"x-lono-admin-key": "test-admin"}
AUTH = {"authorization": "Bearer x"}


def _tool_body() -> dict:
    return {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "clean the workspace"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "bash", "arguments": json.dumps({"command": "rm -rf build/"})},
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_1", "content": "removed build/"},
        ],
        "tools": [{"type": "function", "function": {"name": "bash", "description": "run a shell command"}}],
    }


def test_tool_events_extracted_and_linked(client, upstream) -> None:
    def responder(request, parsed):
        return httpx.Response(
            200,
            json={
                "id": "x",
                "model": "gpt-4o-mini",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call_2",
                                    "type": "function",
                                    "function": {"name": "read_file", "arguments": json.dumps({"path": "a.txt"})},
                                }
                            ],
                        },
                        "finish_reason": "tool_calls",
                    }
                ],
            },
        )

    upstream.responder = responder
    response = client.post("/v1/chat/completions", json=_tool_body(), headers=AUTH)
    request_id = response.headers["x-lono-request-id"]

    data = client.get("/audit/tools", headers=ADMIN).json()
    items = data["items"]
    assert data["total"] >= 3

    commands = [item for item in items if item["is_command"]]
    assert any(item["command"] == "rm -rf build/" for item in commands)
    assert all(item["request_id"] == request_id for item in commands)

    tool_names = {item["tool_name"] for item in items}
    assert "bash" in tool_names
    assert "read_file" in tool_names

    results = [item for item in items if item["kind"] == "result"]
    assert any(item["preview"] == "removed build/" for item in results)

    filtered = client.get("/audit/tools?only_commands=true", headers=ADMIN).json()
    assert all(item["is_command"] for item in filtered["items"])

    stats = client.get("/audit/tools/stats", headers=ADMIN).json()
    assert stats["commands"] >= 1
    assert any(entry["name"] == "bash" for entry in stats["by_tool"])


def test_dashboard_includes_tools(client, upstream) -> None:
    upstream.responder = lambda request, parsed: httpx.Response(200, json={"ok": True})
    client.post("/v1/chat/completions", json=_tool_body(), headers=AUTH)
    dash = client.get("/audit/dashboard?hours=24", headers=ADMIN).json()
    assert "tools" in dash
    assert dash["tools"]["commands"] >= 1
    assert "by_provider" in dash
    assert "latency_series" in dash