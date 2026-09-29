from __future__ import annotations

from lono_gateway.audit.store import AuditStore


def _begin(store: AuditStore, request_id: str, **overrides) -> None:
    fields = {
        "id": request_id,
        "session_id": "s1",
        "mode": "sanitize",
        "api_shape": "openai.chat",
        "method": "POST",
        "path": "/v1/chat/completions",
        "status": "pending",
    }
    fields.update(overrides)
    store.begin_request(**fields)


def test_fts_search_and_summaries(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    _begin(
        store,
        "r1",
        request_original="discuss the quarterly roadmap",
        request_sanitized="discuss the quarterly roadmap",
    )
    store.complete_request(
        "r1",
        status="completed",
        http_status=200,
        response_raw="here is the roadmap",
        response_final="here is the roadmap",
        prompt_tokens=4,
        completion_tokens=3,
        total_tokens=7,
    )
    _begin(store, "r2", request_original="unrelated lunch plans", request_sanitized="unrelated lunch plans")
    store.complete_request("r2", status="completed", http_status=200)

    results = store.list_requests(query="roadmap")
    assert results["total"] == 1
    assert results["items"][0]["id"] == "r1"
    assert results["items"][0]["total_tokens"] == 7

    record = store.get_request("r1")
    assert record is not None
    assert "roadmap" in record["request_original"]
    assert record["response_final"] == "here is the roadmap"
    store.close()


def test_mappings_roundtrip(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    store.put_mapping(
        scope="session:s1",
        entity_type="EMAIL_ADDRESS",
        original_key="steve@x.com",
        original="Steve@x.com",
        pseudonym="bob@example.com",
    )
    row = store.get_mapping("session:s1", "EMAIL_ADDRESS", "steve@x.com")
    assert row is not None
    assert row["pseudonym"] == "bob@example.com"
    assert store.pseudonym_in_use("session:s1", "bob@example.com")
    reverse = store.reverse_mappings(["session:s1", "global"])
    assert reverse == {"bob@example.com": "Steve@x.com"}
    mappings = store.list_mappings("session:s1")
    assert mappings[0]["original"] == "Steve@x.com"
    store.close()


def test_prune_retention(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    _begin(store, "old", created_at="2000-01-01T00:00:00.000Z")
    _begin(store, "new")
    deleted = store.prune(retention_days=1)
    assert deleted == 1
    assert store.get_request("old") is None
    assert store.get_request("new") is not None
    store.close()


def test_stats(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    _begin(store, "r1")
    store.complete_request("r1", status="completed", http_status=200, findings_count=2, blocked=0)
    stats = store.stats()
    assert stats["requests"] == 1
    assert stats["findings"] == 2
    store.close()