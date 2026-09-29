from __future__ import annotations

import json

from lono_gateway.audit.store import AuditStore


def test_dashboard_aggregates(tmp_path) -> None:
    store = AuditStore(str(tmp_path / "audit.db"))
    findings = [
        {"detector": "secrets", "kind": "OPENAI_API_KEY", "action": "masked"},
        {"detector": "pii.regex", "kind": "EMAIL_ADDRESS", "action": "pseudonymized"},
    ]
    store.begin_request(
        id="r1",
        session_id="s1",
        mode="sanitize",
        api_shape="openai.chat",
        method="POST",
        path="/v1/chat/completions",
        model="gpt-4o-mini",
        status="pending",
        findings_json=json.dumps(findings),
        findings_count=len(findings),
    )
    store.complete_request(
        "r1", status="completed", http_status=200, latency_ms=120, total_tokens=10, cost_usd=0.001
    )

    data = store.dashboard(hours=24)
    assert data["totals"]["requests"] == 1
    assert data["totals"]["tokens"] == 10
    assert data["totals"]["findings"] == 2
    assert len(data["timeseries"]) == 24
    assert data["by_kind"][0]["name"] in {"OPENAI_API_KEY", "EMAIL_ADDRESS"}
    assert data["latency"]["p95"] == 120
    assert data["by_model"][0]["model"] == "gpt-4o-mini"
    assert data["top_sessions"][0]["session_id"] == "s1"
    store.close()