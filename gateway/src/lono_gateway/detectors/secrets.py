"""Secret scanning: high-confidence credential patterns plus entropy heuristics."""

from __future__ import annotations

import logging
import math
import re

from lono_gateway.models import Detection
from lono_gateway.secretsynth import is_synthetic
from lono_gateway.settings import SecretRule, SecretsConfig

logger = logging.getLogger(__name__)

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
    # --- AI / LLM providers -------------------------------------------------
    ("RUNPOD_API_KEY", re.compile(r"\brpa_[A-Za-z0-9]{20,}\b"), 0.95),
    ("RUNPOD_MANAGEMENT_KEY", re.compile(r"\bmom_[A-Za-z0-9]{20,}\b"), 0.9),
    ("HUGGINGFACE_TOKEN", re.compile(r"\bhf_[A-Za-z0-9]{30,}\b"), 0.95),
    ("GROQ_API_KEY", re.compile(r"\bgsk_[A-Za-z0-9]{40,}\b"), 0.95),
    ("PERPLEXITY_API_KEY", re.compile(r"\bpplx-[A-Za-z0-9]{40,}\b"), 0.95),
    ("OPENROUTER_API_KEY", re.compile(r"\bsk-or-v1-[a-f0-9]{64}\b"), 0.95),
    ("REPLICATE_API_TOKEN", re.compile(r"\br8_[A-Za-z0-9]{30,}\b"), 0.95),
    ("FIREWORKS_API_KEY", re.compile(r"\bfw_[A-Za-z0-9]{20,}\b"), 0.9),
    ("ELEVENLABS_API_KEY", re.compile(r"\bsk_[a-f0-9]{40,}\b"), 0.9),
    ("TOGETHER_API_KEY", re.compile(r"\btgp_v1_[A-Za-z0-9_\-]{30,}\b"), 0.9),
    # --- Developer / collaboration / infra ---------------------------------
    ("POSTMAN_API_KEY", re.compile(r"\bPMAK-[a-f0-9]{24}-[a-f0-9]{34}\b"), 0.95),
    ("NOTION_API_KEY", re.compile(r"\bntn_[A-Za-z0-9]{40,}\b"), 0.95),
    ("NOTION_INTEGRATION_TOKEN", re.compile(r"\bsecret_[A-Za-z0-9]{43}\b"), 0.9),
    ("LINEAR_API_KEY", re.compile(r"\blin_api_[A-Za-z0-9]{40,}\b"), 0.95),
    ("NEW_RELIC_USER_KEY", re.compile(r"\bNRAK-[A-Z0-9]{27}\b"), 0.95),
    ("PLANETSCALE_TOKEN", re.compile(r"\bpscale_tkn_[A-Za-z0-9_\-]{40,}\b"), 0.95),
    ("SUPABASE_ACCESS_TOKEN", re.compile(r"\bsbp_[a-f0-9]{40}\b"), 0.95),
    ("ATLASSIAN_API_TOKEN", re.compile(r"\bATATT3[A-Za-z0-9_\-=]{186}\b"), 0.95),
    ("AIRTABLE_PAT", re.compile(r"\bpat[A-Za-z0-9]{14}\.[a-f0-9]{64}\b"), 0.95),
    ("DOPPLER_TOKEN", re.compile(r"\bdp\.pt\.[a-z0-9]{43}\b"), 0.95),
    ("DYNATRACE_TOKEN", re.compile(r"\bdt0c01\.[a-z0-9]{24}\.[a-z0-9]{64}\b"), 0.95),
    ("GRAFANA_API_KEY", re.compile(r"\bglc_[A-Za-z0-9+/]{32,}\b"), 0.9),
    ("GRAFANA_SERVICE_ACCOUNT_TOKEN", re.compile(r"\bglsa_[A-Za-z0-9]{32,}\b"), 0.9),
    ("CLOUDFLARE_ORIGIN_CA_KEY", re.compile(r"\bv1\.0-[a-f0-9]{24}-[a-f0-9]{146}\b"), 0.9),
    ("DATABRICKS_TOKEN", re.compile(r"\bdapi[a-f0-9]{32}(?:-\d)?\b"), 0.95),
    ("EASYPOST_API_KEY", re.compile(r"\bEZAK[A-Za-z0-9]{54}\b"), 0.9),
    ("EASYPOST_TEST_API_KEY", re.compile(r"\bEZTK[A-Za-z0-9]{54}\b"), 0.9),
    ("DUFFEL_API_TOKEN", re.compile(r"\bduffel_(?:test|live)_[a-z0-9_\-=]{43}\b"), 0.9),
    ("CLICKHOUSE_CLOUD_KEY", re.compile(r"\b4b1d[A-Za-z0-9]{38}\b"), 0.9),
    ("ARTIFACTORY_API_KEY", re.compile(r"\bAKCp[A-Za-z0-9]{69}\b"), 0.95),
    ("MAILCHIMP_API_KEY", re.compile(r"\b[0-9a-f]{32}-us[0-9]{1,2}\b"), 0.85),
    ("AGE_SECRET_KEY", re.compile(r"\bAGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}\b"), 0.95),
    ("FLY_IO_TOKEN", re.compile(r"\bfo1_[A-Za-z0-9_\-]{43}\b"), 0.9),
    ("SHOPIFY_CUSTOM_APP_TOKEN", re.compile(r"\bshpca_[a-f0-9]{32}\b"), 0.9),
    ("SHOPIFY_PRIVATE_APP_TOKEN", re.compile(r"\bshppa_[a-f0-9]{32}\b"), 0.9),
    ("SHOPIFY_SHARED_SECRET", re.compile(r"\bshpss_[a-f0-9]{32}\b"), 0.95),
    ("SQUARE_ACCESS_TOKEN", re.compile(r"\bEAAA[A-Za-z0-9_\-]{60,}\b"), 0.9),
    ("SQUARE_SECRET", re.compile(r"\bsq0atp-[0-9A-Za-z\-_]{22}\b"), 0.95),
    ("GOOGLE_OAUTH_TOKEN", re.compile(r"\bya29\.[0-9A-Za-z\-_]+\b"), 0.9),
    ("DIGITALOCEAN_OAUTH_TOKEN", re.compile(r"\bdoo_v1_[a-f0-9]{64}\b"), 0.95),
    ("DIGITALOCEAN_REFRESH_TOKEN", re.compile(r"\bdor_v1_[a-f0-9]{64}\b"), 0.95),
    (
        "1PASSWORD_SECRET_KEY",
        re.compile(
            r"\bA3-[A-Z0-9]{6}-(?:[A-Z0-9]{11}|[A-Z0-9]{6}-[A-Z0-9]{5})"
            r"-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b"
        ),
        0.95,
    ),
    ("1PASSWORD_SERVICE_TOKEN", re.compile(r"\bops_eyJ[A-Za-z0-9+/]{250,}={0,3}\b"), 0.95),
    ("ADOBE_CLIENT_SECRET", re.compile(r"\bp8e-[a-z0-9]{32}\b"), 0.9),
    ("ALIBABA_ACCESS_KEY_ID", re.compile(r"\bLTAI[a-z0-9]{20}\b"), 0.9),
    ("CLOJARS_TOKEN", re.compile(r"(?i)\bCLOJARS_[a-z0-9]{60}\b"), 0.9),
    ("AZURE_AD_CLIENT_SECRET", re.compile(r"\b[a-zA-Z0-9_~.]{3}\dQ~[a-zA-Z0-9_~.\-]{31,34}\b"), 0.85),
]

# SSH / encryption key material, grouped so each family can be toggled from
# ``detectors.secrets.key_material``. These are matched by shape (armor headers,
# OpenSSH base64, PuTTY .ppk framing) rather than by algorithm name.
_KEY_PATTERNS: list[tuple[str, str, re.Pattern[str], float]] = [
    (
        "private_keys",
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
            r"[\s\S]{0,16000}?-----END (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
        ),
        0.99,
    ),
    (
        "private_keys",
        "ENCRYPTED_PRIVATE_KEY",
        re.compile(
            r"-----BEGIN ENCRYPTED PRIVATE KEY-----"
            r"[\s\S]{0,16000}?-----END ENCRYPTED PRIVATE KEY-----"
        ),
        0.99,
    ),
    (
        "gpg",
        "PGP_PRIVATE_KEY",
        re.compile(
            r"-----BEGIN PGP PRIVATE KEY BLOCK-----"
            r"[\s\S]{0,16000}?-----END PGP PRIVATE KEY BLOCK-----"
        ),
        0.99,
    ),
    (
        "gpg",
        "PGP_PUBLIC_KEY",
        re.compile(
            r"-----BEGIN PGP PUBLIC KEY BLOCK-----"
            r"[\s\S]{0,16000}?-----END PGP PUBLIC KEY BLOCK-----"
        ),
        0.9,
    ),
    (
        "putty",
        "PUTTY_PRIVATE_KEY",
        re.compile(
            r"PuTTY-User-Key-File-\d+:.*?Private-MAC:[ \t]*[0-9a-fA-F]{16,}",
            re.DOTALL,
        ),
        0.95,
    ),
    (
        "public_keys",
        "SSH_PUBLIC_KEY",
        re.compile(
            r"\b(?:ssh-rsa|ssh-dss|ssh-ed25519|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|"
            r"ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh\.com|"
            r"sk-ecdsa-sha2-nistp256@openssh\.com)\s+AAAA[A-Za-z0-9+/]{15,}={0,3}"
        ),
        0.9,
    ),
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


_ENV_VALUE_RE = r"['\"]?([^\s'\"]{6,})['\"]?"


def _compile_custom_rule(rule: SecretRule) -> tuple[SecretRule, re.Pattern[str] | None]:
    """Compile a console-managed rule into a regex that captures the secret."""
    if rule.match == "env":
        names = [name for name in rule.env_names if name.strip()]
        if not names:
            return rule, None
        alternatives = "|".join(re.escape(name.strip()) for name in names)
        pattern = rf"(?i)(?:^|[^\w.])(?:{alternatives})\s*[:=]\s*{_ENV_VALUE_RE}"
        flags = 0
    elif rule.match == "regex":
        pattern = rule.pattern
        flags = 0 if rule.case_sensitive else re.IGNORECASE
    elif rule.match == "word":
        pattern = rf"(?<!\w){re.escape(rule.pattern)}(?!\w)"
        flags = 0 if rule.case_sensitive else re.IGNORECASE
    else:  # substring
        pattern = re.escape(rule.pattern)
        flags = 0 if rule.case_sensitive else re.IGNORECASE
    try:
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        logger.warning("invalid custom secret rule %r: %s", rule.pattern or rule.env_names, exc)
        return rule, None
    if compiled.groups == 0:
        compiled = re.compile(f"({pattern})", flags)
    return rule, compiled


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
        self._custom = [
            compiled
            for rule in cfg.custom
            if rule.enabled
            for compiled in [_compile_custom_rule(rule)]
            if compiled[1] is not None
        ]

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
        found.extend(self._key_scan(text))
        # Named patterns and user rules are precise; run them first so the
        # speculative entropy heuristic can yield to them. An entropy token can
        # span a wider region than the credential itself (e.g.
        # ``RUNPOD_API_KEY=rpa_...`` is one high-entropy run because ``=`` is in
        # the token charset), and would otherwise win overlap resolution purely
        # by starting earlier.
        found.extend(self._custom_scan(text))
        if self.cfg.entropy:
            named_spans = [(detection.start, detection.end) for detection in found]
            for detection in self._entropy_scan(text):
                if any(
                    not (detection.end <= start or detection.start >= end)
                    for start, end in named_spans
                ):
                    continue
                found.append(detection)
        return found

    def _key_scan(self, text: str) -> list[Detection]:
        km = self.cfg.key_material
        if not km.enabled:
            return []
        found: list[Detection] = []
        for group, kind, pattern, score in _KEY_PATTERNS:
            if not getattr(km, group, False):
                continue
            for match in pattern.finditer(text):
                start, end = match.span(1) if match.lastindex else match.span()
                if end <= start:
                    continue
                value = text[start:end]
                if is_synthetic(value):
                    continue
                found.append(
                    Detection(
                        detector=self.name,
                        kind=kind,
                        start=start,
                        end=end,
                        score=score,
                        suggested=km.action,
                        value=value,
                    )
                )
        return found

    def _custom_scan(self, text: str) -> list[Detection]:
        found: list[Detection] = []
        for rule, regex in self._custom:
            if regex is None:
                continue
            for match in regex.finditer(text):
                start, end = match.span(1) if match.lastindex else match.span()
                if end <= start:
                    continue
                value = text[start:end]
                if is_synthetic(value):
                    continue
                found.append(
                    Detection(
                        detector=self.name,
                        kind=rule.kind or "CUSTOM_SECRET",
                        start=start,
                        end=end,
                        score=0.98,
                        suggested=rule.action or self.cfg.action,
                        value=value,
                    )
                )
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