from __future__ import annotations

import json

import httpx

from lono_gateway.config_manager import ConfigManager
from lono_gateway.settings import SecurityConfig

ADMIN = {"x-lono-admin-key": "test-admin"}


def test_config_snapshot_redacts_secrets(client) -> None:
    data = client.get("/audit/config", headers=ADMIN).json()
    assert data["pseudonymization"]["secret"] == "***"
    assert data["auth"]["admin_key"] == "***"
    assert "upstreams" in data


def test_config_patch_changes_live_mode(client, upstream) -> None:
    upstream.responder = lambda request, body: httpx.Response(200, json={"ok": True})
    patched = client.patch("/audit/config", json={"mode": "observe"}, headers=ADMIN)
    assert patched.status_code == 200
    assert patched.json()["mode"] == "observe"
    assert client.get("/audit/config", headers=ADMIN).json()["mode"] == "observe"


def test_config_patch_rejects_non_allowlisted(client) -> None:
    client.patch("/audit/config", json={"auth": {"admin_key": "hacked"}}, headers=ADMIN)
    data = client.get("/audit/config", headers=ADMIN).json()
    assert data["auth"]["admin_key"] == "***"
    # The original key still works.
    assert client.get("/audit/stats", headers=ADMIN).status_code == 200


def test_substitution_swaps_and_rehydrates(client, upstream) -> None:
    created = client.post(
        "/audit/substitutions",
        json={"pattern": "youruser", "replacement": "alex", "match": "word"},
        headers=ADMIN,
    )
    assert created.status_code == 200
    assert created.json()["id"]

    def responder(request, parsed):
        content = parsed["messages"][0]["content"]
        assert "youruser" not in content
        assert "alex" in content
        return httpx.Response(
            200,
            json={
                "id": "x",
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "hi alex"}, "finish_reason": "stop"}
                ],
            },
        )

    upstream.responder = responder
    response = client.post(
        "/v1/chat/completions",
        json={"model": "deepseek-v4.1-flash", "messages": [{"role": "user", "content": "hi youruser"}]},
        headers={"authorization": "Bearer x"},
    )
    assert response.status_code == 200
    # The provider echoed "alex" and Lono rehydrated it back to "youruser".
    assert response.json()["choices"][0]["message"]["content"] == "hi youruser"

    items = client.get("/audit/substitutions", headers=ADMIN).json()["items"]
    assert any(item["pattern"] == "youruser" for item in items)

    deleted = client.delete(f"/audit/substitutions/{created.json()['id']}", headers=ADMIN)
    assert deleted.status_code == 200
    assert client.delete(f"/audit/substitutions/{created.json()['id']}", headers=ADMIN).status_code == 404


def test_secret_rule_masks_custom_key(client, upstream) -> None:
    created = client.post(
        "/audit/secret-rules",
        json={"kind": "ACME_KEY", "match": "regex", "pattern": r"\bacme_[A-Za-z0-9]{16}\b", "action": "mask"},
        headers=ADMIN,
    )
    assert created.status_code == 200
    rule_id = created.json()["id"]
    assert rule_id

    seen: dict[str, str] = {}

    def responder(request, parsed):
        seen["content"] = parsed["messages"][0]["content"]
        return httpx.Response(
            200,
            json={
                "id": "x",
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
                ],
            },
        )

    upstream.responder = responder
    response = client.post(
        "/v1/chat/completions",
        json={"model": "x", "messages": [{"role": "user", "content": "key acme_ABCDEFGHIJKLMNOP"}]},
        headers={"authorization": "Bearer x"},
    )
    assert response.status_code == 200
    assert "acme_ABCDEFGHIJKLMNOP" not in seen["content"]

    items = client.get("/audit/secret-rules", headers=ADMIN).json()["items"]
    assert any(item["kind"] == "ACME_KEY" for item in items)

    assert client.delete(f"/audit/secret-rules/{rule_id}", headers=ADMIN).status_code == 200
    assert client.delete(f"/audit/secret-rules/{rule_id}", headers=ADMIN).status_code == 404


def test_masked_secret_round_trips_to_client(client, upstream) -> None:
    real = "rpa_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0u1"

    def responder(request, parsed):
        content = parsed["messages"][0]["content"]
        # The provider must never see the real credential.
        assert real not in content
        return httpx.Response(
            200,
            json={
                "id": "x",
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": "stop"}
                ],
            },
        )

    upstream.responder = responder
    response = client.post(
        "/v1/chat/completions",
        json={"model": "x", "messages": [{"role": "user", "content": f"use {real}"}]},
        headers={"authorization": "Bearer x"},
    )
    assert response.status_code == 200
    # ...but the client gets its own key back in the response.
    assert real in response.json()["choices"][0]["message"]["content"]


def test_secret_rule_rejects_invalid_regex(client) -> None:
    response = client.post(
        "/audit/secret-rules",
        json={"kind": "BROKEN", "match": "regex", "pattern": "([unclosed"},
        headers=ADMIN,
    )
    assert response.status_code == 422


def test_runtime_config_persists_and_reloads(tmp_path) -> None:
    path = tmp_path / "runtime_config.json"
    cfg = SecurityConfig()
    cfg.runtime_config_path = str(path)
    manager = ConfigManager(cfg)
    manager.update({"mode": "enforce", "detectors": {"injection": {"enabled": True}}})

    assert path.exists()
    assert json.loads(path.read_text())["mode"] == "enforce"

    fresh = SecurityConfig()
    fresh.runtime_config_path = str(path)
    reloaded = ConfigManager(fresh)
    reloaded.load()
    assert fresh.mode == "enforce"
    assert fresh.detectors.injection.enabled is True