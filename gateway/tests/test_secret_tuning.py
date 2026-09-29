from __future__ import annotations

from random import Random

from lono_gateway.detectors.secrets import SecretDetector
from lono_gateway.models import Detection, RequestContext
from lono_gateway.pipeline.engine import SecurityPipeline
from lono_gateway.secretsynth import generate_fake_secret, is_synthetic, remember_synthetic
from lono_gateway.settings import SecretRule, SecretsConfig, SecurityConfig

_RANDOM_TOKEN = "b7Kq2Xv9Lm4Rt6Yz1Nc8Pd3Wf5Hg0Ja2"
_OPENAI_KEY = "sk-proj-Kq72Xv9Lm4Rt6Yz1Nc8Pd3Wf5Hg0Ja2Kq72Xv9Lm4Rt6Yz1Nc8"


def _detector() -> SecretDetector:
    return SecretDetector(SecretsConfig())


def test_assignment_placeholders_and_expressions_are_ignored() -> None:
    detector = _detector()
    text = "\n".join(
        [
            "api_key: ${OPENAI_API_KEY:-}",
            "secret = secrets.token_urlsafe(32)",
            'api_base: os.environ["OPENAI_API_KEY"]',
            "password: <your-api-key>",
        ]
    )
    kinds = [detection.kind for detection in detector.scan(text)]
    assert "PASSWORD_ASSIGNMENT" not in kinds


def test_real_assignment_is_still_detected() -> None:
    detector = _detector()
    kinds = [detection.kind for detection in detector.scan('password = "hunter2correcthorse"')]
    assert "PASSWORD_ASSIGNMENT" in kinds


def test_assignment_skips_cmdlet_and_module_names() -> None:
    detector = _detector()
    text = "\n".join(
        [
            "$hfToken = Get-LocalEnvValue 'HF_TOKEN'",
            "$apiKey  = Get-LocalEnvValue 'RUNPOD_API_KEY'",
            "secret = secrets.token_urlsafe(32)",
        ]
    )
    kinds = [detection.kind for detection in detector.scan(text)]
    assert "PASSWORD_ASSIGNMENT" not in kinds


def test_entropy_ignores_coding_context() -> None:
    detector = _detector()
    text = "\n".join(
        [
            "PseudonymizationConfig = Field(default_factory=PseudonymizationConfig)",
            "Named patterns for AWS/GitHub/OpenAI/Anthropic/Stripe/JWT/private keys/connection strings",
            "LONO_PSEUDONYM_SECRET",
        ]
    )
    kinds = [detection.kind for detection in detector.scan(text)]
    assert "HIGH_ENTROPY_STRING" not in kinds


def test_entropy_detects_machine_token() -> None:
    detector = _detector()
    kinds = [detection.kind for detection in detector.scan(f"key = {_RANDOM_TOKEN}")]
    assert "HIGH_ENTROPY_STRING" in kinds


def test_entropy_action_is_flagged_not_masked() -> None:
    cfg = SecurityConfig()
    pipeline = SecurityPipeline(cfg, store=None)
    ctx = RequestContext(request_id="r", session_id="s")
    detection = Detection(
        detector="secrets", kind="HIGH_ENTROPY_STRING", start=0, end=5, score=0.55, suggested="flag"
    )
    assert pipeline._action_for(detection, ctx) == "flag"
    named = Detection(detector="secrets", kind="OPENAI_API_KEY", start=0, end=5, score=0.95, suggested="mask")
    assert pipeline._action_for(named, ctx) == "mask"


def test_popular_provider_tokens_are_detected() -> None:
    detector = _detector()
    samples = {
        "RUNPOD_API_KEY": "rpa_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0u1",
        "RUNPOD_MANAGEMENT_KEY": "mom_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0u1",
        "HUGGINGFACE_TOKEN": "hf_abcdefghijklmnopqrstuvwxyz0123456789",
        "GROQ_API_KEY": "gsk_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5zA7bC9dE1fG3hI5",
        "PERPLEXITY_API_KEY": "pplx-" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0u1V2",
        "OPENROUTER_API_KEY": "sk-or-v1-" + "a" * 64,
        "REPLICATE_API_TOKEN": "r8_abcdefghijklmnopqrstuvwxyzABCDEFGHI",
        "NOTION_API_KEY": "ntn_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0",
        "LINEAR_API_KEY": "lin_api_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t0",
        "POSTMAN_API_KEY": "PMAK-" + "a1b2c3d4e5f6a7b8c9d0e1f2" + "-" + "f" * 34,
        "NEW_RELIC_USER_KEY": "NRAK-" + "A1B2C3D4E5F6G7H8I9J0K1L2M3N",
        "DIGITALOCEAN_OAUTH_TOKEN": "doo_v1_" + "a" * 64,
        "SUPABASE_ACCESS_TOKEN": "sbp_" + "a" * 40,
        "GRAFANA_SERVICE_ACCOUNT_TOKEN": "glsa_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6",
    }
    for expected_kind, value in samples.items():
        kinds = [detection.kind for detection in detector.scan(value)]
        assert expected_kind in kinds, f"{expected_kind} not detected in {value!r}"


def test_custom_regex_rule_honors_action_override() -> None:
    cfg = SecretsConfig(
        custom=[
            SecretRule(
                kind="ACME_KEY",
                match="regex",
                pattern=r"\bacme_[A-Za-z0-9]{16}\b",
                action="block",
            )
        ]
    )
    detections = SecretDetector(cfg).scan("token acme_ABCDEFGHIJKLMNOP")
    assert any(detection.kind == "ACME_KEY" and detection.suggested == "block" for detection in detections)


def test_custom_env_rule_detects_assigned_value() -> None:
    cfg = SecretsConfig(
        custom=[
            SecretRule(
                kind="RUNPOD_API_KEY",
                match="env",
                env_names=["RUNPOD_API_KEY"],
                action="mask",
            )
        ]
    )
    detector = SecretDetector(cfg)
    for text in (
        '$env:RUNPOD_API_KEY = "rpa_ABCDEFGHIJKLMNOPQRSTUVWX"',
        '"RUNPOD_API_KEY": "rpa_ABCDEFGHIJKLMNOPQRSTUVWX"',
        "RUNPOD_API_KEY=rpa_ABCDEFGHIJKLMNOPQRSTUVWX",
    ):
        detections = detector.scan(text)
        assert any(
            detection.kind == "RUNPOD_API_KEY" and detection.value == "rpa_ABCDEFGHIJKLMNOPQRSTUVWX"
            for detection in detections
        ), text


def test_custom_literal_and_disabled_rules() -> None:
    cfg = SecretsConfig(
        custom=[
            SecretRule(kind="KNOWN_LEAK", match="substring", pattern="T39-20260929T081908"),
            SecretRule(kind="IGNORED", match="substring", pattern="deadbeef", enabled=False),
        ]
    )
    detections = SecretDetector(cfg).scan("run T39-20260929T081908 and deadbeef")
    kinds = [detection.kind for detection in detections]
    assert "KNOWN_LEAK" in kinds
    assert "IGNORED" not in kinds


def test_custom_rule_invalid_regex_is_ignored() -> None:
    cfg = SecretsConfig(
        custom=[SecretRule(kind="BROKEN", match="regex", pattern="([unclosed")]
    )
    # Must not raise, and must not emit a BROKEN detection.
    assert not any(detection.kind == "BROKEN" for detection in SecretDetector(cfg).scan("([unclosed"))


def test_fake_secret_preserves_shape_and_is_deterministic() -> None:
    first = generate_fake_secret("OPENAI_API_KEY", _OPENAI_KEY, Random(1))
    second = generate_fake_secret("OPENAI_API_KEY", _OPENAI_KEY, Random(1))
    assert first == second
    assert first != _OPENAI_KEY
    assert first.startswith("sk-proj-")
    assert len(first) == len(_OPENAI_KEY)


def test_fake_secret_is_registered_and_not_redetected() -> None:
    fake = generate_fake_secret("HIGH_ENTROPY_STRING", _RANDOM_TOKEN, Random(2))
    remember_synthetic(fake)
    assert is_synthetic(fake)
    assert not any(detection.value == fake for detection in _detector().scan(f"token {fake}"))