"""Secret scanning: high-confidence credential patterns plus entropy heuristics."""

from __future__ import annotations

import math
import re

from lono_gateway.models import Detection
from lono_gateway.secretsynth import is_synthetic
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
    ("AZURE_STORAGE_KEY", re.compile(r"(?i)\bAccountKey=([A-Za-z0-9+/=]{60,})"), 0.95),
    ("NPM_TOKEN", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), 0.9),
    ("PYPI_TOKEN", re.compile(r"\bpypi-[A-Za-z0-9_\-]{40,}\b"), 0.9),
    ("DIGITALOCEAN_TOKEN", re.compile(r"\bdop_v1_[a-f0-9]{64}\b"), 0.95),
    ("SHOPIFY_TOKEN", re.compile(r"\bshpat_[a-f0-9]{32}\b"), 0.95),
    ("TWILIO_API_KEY", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), 0.9),
    ("SENDGRID_KEY", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), 0.95),
    ("MAILGUN_KEY", re.compile(r"\bkey-[a-f0-9]{32}\b"), 0.85),
    ("HEROKU_API_KEY", re.compile(r"(?i)heroku[_-]?api[_-]?key\s*[:=]\s*['\"]?([0-9a-f-]{36})"), 0.85),
    (
        "DISCORD_TOKEN",
        re.compile(r"\b[MN][A-Za-z0-9]{23}\.[A-Za-z0-9_\-]{6}\.[A-Za-z0-9_\-]{27,}\b"),
        0.9,
    ),
    ("TELEGRAM_BOT_TOKEN", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"), 0.85),
    ("FACEBOOK_ACCESS_TOKEN", re.compile(r"\bEAA[A-Za-z0-9]{20,}\b"), 0.85),
    ("SAS_TOKEN", re.compile(r"(?i)\bsig=[A-Za-z0-9%+/=]{20,}"), 0.85),
    ("BASIC_AUTH", re.compile(r"(?i)\bauthorization\s*:\s*basic\s+([A-Za-z0-9+/=]{8,})"), 0.85),
]

_ENTROPY_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=_\-])[A-Za-z0-9+/=_\-]{20,}(?![A-Za-z0-9+/=_\-])")
_HASHY_RE = re.compile(
    r"^(?:[0-9a-fA-F]{32,}|"
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)
_PLACEHOLDER_HINTS = (
    "example",
    "changeme",
    "change-me",
    "change_me",
    "placeholder",
    "dummy",
    "redacted",
    "your_",
    "your-",
    "yourkey",
    "xxxx",
    "todo",
    "replace",
    "insert_",
    "sample",
)
_PLACEHOLDER_EXPR_PREFIXES = (
    "os.environ",
    "process.env",
    "system.getenv",
    "environ[",
    "getenv(",
    "config.",
    "settings.",
)
_SEGMENT_SPLIT_RE = re.compile(r"[/\\=:.@]+")


def _looks_like_placeholder(value: str) -> bool:
    """Configuration placeholders and code expressions, not real credentials."""
    text = (value or "").strip()
    if not text:
        return True
    lowered = text.lower()
    if text.startswith("${") or "{" in text or "}" in text:
        return True
    if text.startswith("<") and text.endswith(">"):
        return True
    if "(" in text or ")" in text:
        return True
    if lowered in {"null", "none", "true", "false", "undefined", "nil"}:
        return True
    if lowered.startswith(_PLACEHOLDER_EXPR_PREFIXES):
        return True
    if any(hint in lowered for hint in _PLACEHOLDER_HINTS):
        return True
    # Masking with punctuation only (`****`, `....`, `-`).
    return set(text) <= set("-*.#_ ")


def _looks_like_identifier(token: str) -> bool:
    """A code identifier (camelCase / snake_case) with no digits is not a secret."""
    if any(char.isdigit() for char in token):
        return False
    return bool(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token))


_CODE_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*(?:[-.][A-Za-z_][A-Za-z0-9_]*)+")


def _looks_like_code_name(value: str) -> bool:
    """A hyphenated/dotted name with no digits: PowerShell cmdlets, module paths.

    Examples: ``Get-LocalEnvValue`` (a cmdlet call, not a secret),
    ``secrets.token_urlsafe``, ``os.path.join``. Real credentials almost always
    carry a digit, so requiring the token to be digit-free keeps detection
    narrow while stopping config code from being rewritten.
    """
    text = (value or "").strip()
    if not text or any(char.isdigit() for char in text):
        return False
    return bool(_CODE_NAME_RE.fullmatch(text))


def _is_screaming_snake(token: str) -> bool:
    """Env-var names such as LONO_PSEUDONYM_SECRET are names, not values."""
    return bool(re.fullmatch(r"[A-Z][A-Z0-9_]*", token))


def _is_word_list(token: str) -> bool:
    """Slash/colon/equals separated lists of words (e.g. AWS/GitHub/OpenAI)."""
    if any(char.isdigit() for char in token):
        return False
    parts = [part for part in _SEGMENT_SPLIT_RE.split(token) if part]
    if len(parts) < 2:
        return False
    return all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", part) for part in parts)


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
                value = text[start:end]
                if is_synthetic(value):
                    continue
                # Assignment-style patterns fire on config placeholders, code
                # expressions and function/cmdlet names rather than real
                # credentials.
                if kind == "PASSWORD_ASSIGNMENT" and (
                    _looks_like_placeholder(value) or _looks_like_code_name(value)
                ):
                    continue
                found.append(
                    Detection(
                        detector=self.name,
                        kind=kind,
                        start=start,
                        end=end,
                        score=score,
                        suggested=self.cfg.action,
                        value=value,
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
            if is_synthetic(token) or _HASHY_RE.match(token):
                continue
            # Coding context is full of high-entropy-looking text that is not a
            # credential: identifiers, SCREAMING_SNAKE env names, word lists
            # (AWS/GitHub/OpenAI) and configuration placeholders.
            if _looks_like_placeholder(token):
                continue
            if _looks_like_identifier(token) or _is_screaming_snake(token) or _is_word_list(token):
                continue
            has_lower = any(c.islower() for c in token)
            has_upper = any(c.isupper() for c in token)
            has_digit = any(c.isdigit() for c in token)
            # Most machine-generated secrets carry digits; a long mixed-case
            # token without digits is allowed too, but short digit-free prose,
            # identifiers and word lists are not.
            if not has_digit and not (has_lower and has_upper and len(token) >= 32):
                continue
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