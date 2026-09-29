from __future__ import annotations

from lono_gateway.audit.store import AuditStore


def test_category_override_lifecycle(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    override = store.add_override(kind="category", category="EMAIL_ADDRESS", note="test")
    assert override["id"] > 0

    active = store.active_overrides()
    assert "EMAIL_ADDRESS" in active["categories"]

    listed = store.list_overrides()
    assert listed and listed[0]["active"] is True

    assert store.revoke_override(override["id"]) is True
    assert store.active_overrides()["categories"] == set()
    assert store.revoke_override(override["id"]) is False
    store.close()


def test_value_override_and_expiry(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    store.add_override(kind="value", category="EMAIL_ADDRESS", value_key="steve@x.com", value_display="Steve@x.com")
    expired = store.add_override(
        kind="category", category="PERSON", expires_at="2000-01-01T00:00:00.000Z"
    )

    active = store.active_overrides()
    assert active["values"].get("EMAIL_ADDRESS") == {"steve@x.com"}
    assert "PERSON" not in active["categories"]

    listed = {item["id"]: item for item in store.list_overrides()}
    assert listed[expired["id"]]["active"] is False
    store.close()


def test_prune_overrides(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    revoked = store.add_override(kind="category", category="PERSON")
    store.revoke_override(revoked["id"])
    store.add_override(kind="category", category="LOCATION", expires_at="2000-01-01T00:00:00.000Z")
    kept = store.add_override(kind="category", category="EMAIL_ADDRESS")

    assert store.prune_overrides() == 2
    remaining = store.list_overrides()
    assert [item["id"] for item in remaining] == [kept["id"]]
    store.close()