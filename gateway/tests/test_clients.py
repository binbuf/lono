from __future__ import annotations

import json

from lono_gateway.audit.store import AuditStore

ADMIN = {"x-lono-admin-key": "test-admin"}


def _seed(store: AuditStore) -> None:
    for index, (client, agent) in enumerate(
        [("c-alpha", "opencode/1.2"), ("c-alpha", "opencode/1.2"), ("c-beta", "cursor/0.4")]
    ):
        store.begin_request(
            id=f"r{index}",
            session_id=f"s{index}",
            mode="sanitize",
            api_shape="openai.chat",
            method="POST",
            path="/v1/chat/completions",
            model="gpt-4o-mini",
            provider="default",
            client_id=client,
            status="pending",
            client_meta_json=json.dumps({"user-agent": agent}),
        )
        store.complete_request(
            f"r{index}",
            status="completed" if client == "c-alpha" else "error",
            http_status=200,
            latency_ms=100 + index,
            total_tokens=10,
            cost_usd=0.001,
        )


def test_list_clients_aggregates(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    _seed(store)

    result = store.list_clients()
    assert result["total"] == 2
    by_id = {item["client_id"]: item for item in result["items"]}
    assert by_id["c-alpha"]["requests"] == 2
    assert by_id["c-alpha"]["sessions"] == 2
    assert by_id["c-alpha"]["user_agent"] == "opencode/1.2"
    assert by_id["c-beta"]["requests"] == 1
    assert by_id["c-beta"]["errors"] == 1

    detail = store.client_detail("c-alpha")
    assert detail is not None
    assert detail["requests"] == 2
    assert detail["by_model"][0]["model"] == "gpt-4o-mini"
    assert detail["header_samples"][0]["user-agent"] == "opencode/1.2"

    filtered = store.list_requests(client_id="c-beta")
    assert filtered["total"] == 1
    assert filtered["items"][0]["client_key"] == "c-beta"
    store.close()


def test_legacy_rows_group_by_session(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    store.begin_request(
        id="legacy",
        session_id="ses-old",
        mode="sanitize",
        api_shape="openai.chat",
        method="POST",
        path="/v1/chat/completions",
        status="pending",
    )
    result = store.list_clients()
    assert result["total"] == 1
    assert result["items"][0]["client_id"] == "legacy-ses-old"
    detail = store.client_detail("legacy-ses-old")
    assert detail is not None and detail["requests"] == 1
    store.close()


def test_clients_api_captures_identity_and_headers(client, upstream) -> None:
    upstream.responder = lambda request, body: __import__("httpx").Response(
        200, json={"id": "x", "model": "m", "choices": []}
    )
    headers = {
        "authorization": "Bearer sk-super-secret-key",
        "user-agent": "opencode/9.9",
        "x-lono-client": "laptop",
        "content-type": "application/json",
    }
    response = client.post(
        "/v1/chat/completions",
        json={"model": "deepseek-v4.1-flash", "messages": [{"role": "user", "content": "hi"}]},
        headers=headers,
    )
    assert response.status_code == 200

    listing = client.get("/audit/clients", headers=ADMIN).json()
    item = next(i for i in listing["items"] if i["user_agent"] == "opencode/9.9")
    assert item["label"] == "laptop"

    detail = client.get(f"/audit/clients/{item['client_id']}", headers=ADMIN).json()
    assert detail["requests"] == 1
    assert detail["recent"][0]["client_key"] == item["client_id"]

    blob = json.dumps(detail)
    assert "sk-super-secret-key" not in blob
    sample = detail["header_samples"][0]
    assert sample["x-lono-client"] == "laptop"
    assert "authorization" not in sample

    filtered = client.get("/audit/requests", params={"client_id": item["client_id"]}, headers=ADMIN).json()
    assert filtered["total"] == 1


def test_client_labels_round_trip(client, upstream, settings) -> None:
    import httpx

    upstream.responder = lambda request, body: httpx.Response(
        200, json={"id": "x", "model": "m", "choices": []}
    )
    response = client.post(
        "/v1/chat/completions",
        json={"model": "deepseek-v4.1-flash", "messages": [{"role": "user", "content": "hi"}]},
        headers={
            "authorization": "Bearer sk-key",
            "user-agent": "opencode/9.9 ai-sdk/provider-utils/4.0",
            "x-stainless-lang": "js",
            "content-type": "application/json",
        },
    )
    assert response.status_code == 200
    request_id = response.headers["x-lono-request-id"]

    listing = client.get("/audit/clients", headers=ADMIN).json()
    item = listing["items"][0]
    assert item["label"] == "opencode 9.9"  # parsed from the user agent
    key = item["client_id"]

    assert client.put(f"/audit/clients/{key}", json={"label": "Laptop"}, headers=ADMIN).status_code == 200
    relisting = client.get("/audit/clients", headers=ADMIN).json()
    assert relisting["items"][0]["label"] == "Laptop"

    detail = client.get(f"/audit/clients/{key}", headers=ADMIN).json()
    assert detail["label"] == "Laptop"
    assert detail["recent"][0]["client_label"] == "Laptop"
    assert detail["header_samples"][0]["x-stainless-lang"] == "js"
    assert detail["header_samples"][0]["client"] == "opencode 9.9"

    record = client.get(f"/audit/requests/{request_id}", headers=ADMIN).json()
    assert record["client_label"] == "Laptop"

    assert client.delete(f"/audit/clients/{key}", headers=ADMIN).status_code == 200
    reset = client.get("/audit/clients", headers=ADMIN).json()
    assert reset["items"][0]["label"] == "opencode 9.9"