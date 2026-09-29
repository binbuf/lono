from __future__ import annotations

from pathlib import Path

from lono_gateway.settings import load_settings

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG = REPO_ROOT / "config" / "security.yaml"


def test_repo_security_yaml_loads(monkeypatch) -> None:
    for name in (
        "AI_GATEWAY_MODE",
        "LONO_MODE",
        "LONO_ADMIN_KEY",
        "LONO_PSEUDONYM_SECRET",
        "LONO_DATA_DIR",
        "LONO_MEDIA_BACKEND",
        "LANGFUSE_PUBLIC_KEY",
        "LANGFUSE_SECRET_KEY",
        "MINIO_ACCESS_KEY",
        "MINIO_SECRET_KEY",
    ):
        monkeypatch.delenv(name, raising=False)

    cfg = load_settings(CONFIG)
    assert cfg.mode == "sanitize"
    assert cfg.detectors.pii.engine == "auto"
    assert cfg.detectors.pii.actions["EMAIL_ADDRESS"] == "pseudonymize"
    assert cfg.detectors.pii.actions["CREDIT_CARD"] == "mask"
    assert cfg.auth.admin_key == ""
    assert cfg.pseudonymization.secret  # ephemeral secret generated with a warning
    assert cfg.audit.sqlite_path.endswith("audit.db")
    assert cfg.upstream.base_url == "http://litellm:4000"
    assert "authorization" in cfg.upstream.forward_headers
    assert "content-type" in cfg.upstream.forward_headers


def test_env_overrides_take_precedence(monkeypatch) -> None:
    monkeypatch.setenv("AI_GATEWAY_MODE", "enforce")
    monkeypatch.setenv("LONO_ADMIN_KEY", "admin-123")
    monkeypatch.setenv("LONO_PSEUDONYM_SECRET", "pseudo-123")
    monkeypatch.setenv("LONO_DATA_DIR", "/custom")
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-lf-x")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk-lf-y")

    cfg = load_settings(CONFIG)
    assert cfg.mode == "enforce"
    assert cfg.auth.admin_key == "admin-123"
    assert cfg.pseudonymization.secret == "pseudo-123"
    assert cfg.audit.sqlite_path == "/custom/audit.db"
    assert cfg.audit.media.local_path == "/custom/media"
    assert cfg.audit.langfuse.configured is True