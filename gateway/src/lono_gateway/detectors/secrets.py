"""Secret scanning: high-confidence credential patterns plus entropy heuristics."""

from __future__ import annotations

import math
import re

from lono_gateway.models import Detection
from lono_gateway.settings import SecretsConfig

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    ("AWS_ACCESS_KEY_ID", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), 0.99),
    (
        "AWS_SECRET_ACCESS_KEY",
        re.compile(r"(?i)\baws_secret_access_key\b\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        0.95,
    ),
    ("GITHUB_TOKEN", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b"), 0.99),
    ("GITHUB_PAT", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), 0.99),
    ("GITLAB_PAT", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), 0.99),
    ("ANTHROPIC_API_KEY", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), 0.99),
    ("OPENAI_API_KEY", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_\-]{20,}\b"), 0.95),
    ("SLACK_TOKEN", re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b"), 0.95),
    ("STRIPE_KEY", re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b"), 0.95),
    ("GOOGLE_API_KEY", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), 0.95),
    (
        "JWT",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        0.9,
    ),
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
            r"[\s\S]{0,8000}?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
        ),
        0.99,
    ),
    (
        "BEARER_TOKEN",
        re.compile(r"(?i)\bbearer\s+([A-Za-z0-9_\-.=+/]{20,})"),
        0.9,
    ),
    (
        "PASSWORD_ASSIGNMENT",
        re.compile(
            r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token)\b"
            r"\s*[:=]\s*['\"]?([^\s'\"]{6,})['\"]?"
        ),
        0.8,
    ),
    (
        "CONNECTION_STRING",
        re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^\s:@/]+:[^\s@/]+@\S+"),
        0.95,
    ),
]

_ENTROPY_TOKEN_RE = re.compile(r"[A-Za-z0-9+/=_\-]{20,}")
_HASHY_RE = re.compile(
    r"^(?:[0-9a-fA-F]{32,}|"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


class SecretDetector:
    name = "secrets"

    def __init__(self, cfg: SecretsConfig) -> None:
        self.cfg = cfg

    def scan(self, text: str) -> list[Detection]:
        if not self.cfg.enabled:
            return []
        found: list[Detection] = []
        for kind, pattern, score in _SECRET_PATTERNS:
            for match in pattern.finditer(text):
                start, end = match.span(1) if match.lastindex else match.span()
                if end <= start:
                    continue
                found.append(
                    Detection(
                        detector=self.name,
                        kind=kind,
                        start=start,
                        end=end,
                        score=score,
                        suggested=self.cfg.action,
                        value=text[start:end],
                    )
                )
        if self.cfg.entropy:
            found.extend(self._entropy_scan(text))
        return found

    def _entropy_scan(self, text: str) -> list[Detection]:
        found: list[Detection] = []
        for match in _ENTROPY_TOKEN_RE.finditer(text):
            token = match.group(0)
            if len(token) < self.cfg.entropy_min_length:
                continue
            if _HASHY_RE.match(token):
                continue
            has_lower = any(c.islower() for c in token)
            has_upper = any(c.isupper() for c in token)
            has_digit = any(c.isdigit() for c in token)
            if sum([has_lower, has_upper, has_digit]) < 2:
                continue
            if shannon_entropy(token) < self.cfg.entropy_threshold:
                continue
            found.append(
                Detection(
                    detector=self.name,
                    kind="HIGH_ENTROPY_STRING",
                    start=match.start(),
                    end=match.end(),
                    score=0.55,
                    suggested=self.cfg.entropy_action,
                    value=token,
                )
            )
        return found