from __future__ import annotations

from random import Random

from lono_gateway.detectors.secrets import SecretDetector
from lono_gateway.models import Detection, RequestContext
from lono_gateway.pipeline.engine import SecurityPipeline
from lono_gateway.secretsynth import generate_fake_secret, is_synthetic, remember_synthetic
from lono_gateway.settings import SecretsConfig, SecurityConfig

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