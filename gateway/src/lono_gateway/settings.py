"""Configuration loading: security.yaml plus environment overrides."""

from __future__ import annotations

import logging
import os
import re
import secrets
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, Field, field_validator

from lono_gateway.models import Mode

logger = logging.getLogger(__name__)

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")

DEFAULT_PII_ACTIONS: dict[str, str] = {
    "EMAIL_ADDRESS": "pseudonymize",
    "PERSON": "pseudonymize",
    "PHONE_NUMBER": "pseudonymize",
    "LOCATION": "pseudonymize",
    "ORGANIZATION": "pseudonymize",
    "IP_ADDRESS": "pseudonymize",
    "STREET_ADDRESS": "pseudonymize",
    "POSTAL_CODE": "pseudonymize",
    "CREDIT_CARD": "mask",
    "US_SSN": "mask",
    "US_PASSPORT": "mask",
    "US_DRIVER_LICENSE": "mask",
    "MEDICAL_LICENSE": "mask",
    "IBAN_CODE": "mask",
    "CRYPTO": "mask",
    "BTC_ADDRESS": "mask",
    "ETH_ADDRESS": "mask",
    "MAC_ADDRESS": "flag",
    "DATE_TIME": "flag",
    "URL": "flag",
}


def _expand_env(text: str) -> str:
    def _sub(match: re.Match[str]) -> str:
        name, default = match.group(1), match.group(2)
        value = os.environ.get(name)
        if value is None or value == "":
            return default if default is not None else ""
        return value

    return _ENV_RE.sub(_sub, text)


class SecretRule(BaseModel):
    """A user-defined secret detection rule managed from the console.

    ``match`` selects how ``pattern`` is interpreted:

    * ``regex`` / ``word`` / ``substring`` — match the literal text directly.
    * ``env`` — treat entries in ``env_names`` as environment-variable names and
      detect the value assigned to them (``NAME=value``, ``"NAME": "value"`` …).

    ``action`` overrides ``detectors.secrets.action`` for this rule only; when
    unset the detector default applies. Custom rules are high confidence (they
    are user-authored) so they never fall back to the noisy entropy heuristic.
    """

    id: str = ""
    kind: str = "CUSTOM_SECRET"
    enabled: bool = True
    action: Literal["mask", "flag", "block"] | None = None
    match: Literal["regex", "word", "substring", "env"] = "regex"
    pattern: str = ""
    env_names: list[str] = Field(default_factory=list)
    case_sensitive: bool = True
    note: str = ""


class SecretsConfig(BaseModel):
    enabled: bool = True
    action: Literal["mask", "flag", "block"] = "mask"
    entropy: bool = True
    entropy_threshold: float = 4.2
    entropy_min_length: int = 24
    entropy_action: Literal["flag", "mask"] = "flag"
    custom: list[SecretRule] = Field(default_factory=list)


class PiiConfig(BaseModel):
    enabled: bool = True
    engine: Literal["auto", "presidio", "regex"] = "auto"
    presidio_url: str = "http://presidio-analyzer:3000"
    language: str = "en"
    score_threshold: float = 0.4
    timeout_s: float = 10.0
    failure_cooldown_s: float = 60.0
    default_action: str = "pseudonymize"
    actions: dict[str, str] = Field(default_factory=lambda: dict(DEFAULT_PII_ACTIONS))
    custom_patterns_file: str = "config/presidio/patterns.yaml"
    filter_technical: bool = True


class InjectionConfig(BaseModel):
    enabled: bool = True
    action: Literal["flag", "block"] = "flag"
    flag_threshold: float = 0.45
    block_threshold: float = 0.8


class UrlsConfig(BaseModel):
    enabled: bool = True
    action: Literal["flag", "block"] = "flag"
    flag_threshold: float = 0.45
    block_threshold: float = 0.9
    allow_schemes: list[str] = Field(default_factory=lambda: ["http", "https"])


class WatchTerm(BaseModel):
    term: str
    category: str = "SENSITIVE_TERM"
    action: Literal["pseudonymize", "mask", "flag", "block"] = "pseudonymize"
    match: Literal["word", "substring", "regex"] = "word"
    case_sensitive: bool = False
    replacement_type: str = ""
    # When set, the finding is replaced with this literal value (still recorded
    # as a mapping, so provider output is rehydrated back to the original).
    replacement: str = ""


class WatchlistConfig(BaseModel):
    enabled: bool = True
    file: str = "${LONO_CONFIG_DIR:-/config}/watchlist.yaml"
    terms: list[WatchTerm] = Field(default_factory=list)


class Substitution(BaseModel):
    """A literal keyword swap (e.g. a GitHub username or a home path)."""

    id: str = ""
    pattern: str
    replacement: str
    match: Literal["word", "substring", "regex"] = "substring"
    case_sensitive: bool = False
    category: str = "SUBSTITUTION"
    enabled: bool = True
    note: str = ""


class SubstitutionsConfig(BaseModel):
    enabled: bool = True
    terms: list[Substitution] = Field(default_factory=list)


class McpServerConfig(BaseModel):
    name: str
    url: str
    enabled: bool = True
    headers: dict[str, str] = Field(default_factory=dict)
    description: str = ""


class McpConfig(BaseModel):
    enabled: bool = True
    timeout_s: float = 120.0
    servers: list[McpServerConfig] = Field(default_factory=list)


class ToolsConfig(BaseModel):
    enabled: bool = True
    extract_commands: bool = True
    command_tools: list[str] = Field(
        default_factory=lambda: [
            "bash",
            "shell",
            "sh",
            "run_command",
            "execute_command",
            "terminal",
            "exec",
            "run_shell_command",
            "command",
        ]
    )
    max_events_per_request: int = 200
    preview_chars: int = 2000


class OutputScanConfig(BaseModel):
    enabled: bool = True
    secrets: bool = True
    injection: bool = True
    pii: bool = True
    watchlist: bool = True
    action: Literal["flag", "mask"] = "flag"


class OverridesConfig(BaseModel):
    enabled: bool = True
    cache_seconds: float = 3.0
    default_max_minutes: int = 60
    allow_permanent: bool = True


class DetectorsConfig(BaseModel):
    secrets: SecretsConfig = Field(default_factory=SecretsConfig)
    pii: PiiConfig = Field(default_factory=PiiConfig)
    injection: InjectionConfig = Field(default_factory=InjectionConfig)
    urls: UrlsConfig = Field(default_factory=UrlsConfig)


class PseudonymizationConfig(BaseModel):
    secret: str = ""
    stable_across_sessions: bool = False
    lists_dir: str = "${LONO_CONFIG_DIR:-/config}/lists"
    lists: dict[str, str] = Field(default_factory=dict)
    pools: dict[str, list[str]] = Field(default_factory=dict)


class MediaConfig(BaseModel):
    enabled: bool = True
    backend: Literal["local", "minio"] = "local"
    local_path: str = "data/media"
    endpoint: str = "minio:9000"
    access_key: str = ""
    secret_key: str = ""
    secure: bool = False
    bucket: str = "lono-media"
    max_store_bytes: int = 50_000_000
    fetch_remote_images: bool = False


class LangfuseConfig(BaseModel):
    enabled: bool = True
    host: str = "http://langfuse-web:3000"
    public_key: str = ""
    secret_key: str = ""
    max_chars: int = 100_000

    @property
    def configured(self) -> bool:
        return bool(self.enabled and self.public_key and self.secret_key)


class AuditConfig(BaseModel):
    enabled: bool = True
    sqlite_path: str = "data/audit.db"
    capture_original: bool = True
    max_payload_bytes: int = 20_000_000
    retention_days: int = 0
    media: MediaConfig = Field(default_factory=MediaConfig)
    langfuse: LangfuseConfig = Field(default_factory=LangfuseConfig)


class UpstreamConfig(BaseModel):
    """A provider proxy the gateway can forward to concurrently.

    The top-level ``upstream`` is the default route; entries in ``upstreams``
    are additional named proxies. Selection is by the ``x-lono-upstream``
    request header, then a model match, then a path prefix, then the default.
    """

    name: str = "default"
    base_url: str = "http://litellm:4000"
    enabled: bool = True
    description: str = ""
    timeout_s: float = 900.0
    connect_timeout_s: float = 10.0
    max_body_bytes: int = 50_000_000
    # fnmatch patterns matched against the request ``model`` (e.g. "deepseek-*",
    # "openai/*", "claude-*").
    models: list[str] = Field(default_factory=list)
    # Route requests whose URL path starts with one of these prefixes.
    path_prefixes: list[str] = Field(default_factory=list)
    forward_headers: list[str] = Field(
        default_factory=lambda: [
            "authorization",
            "x-api-key",
            "anthropic-version",
            "anthropic-beta",
            "openai-organization",
            "openai-project",
            "accept",
        ]
    )

    @field_validator("name", mode="before")
    @classmethod
    def _default_name(cls, value: object) -> object:
        return "default" if value is None or value == "" else value


class AuthConfig(BaseModel):
    admin_key: str = ""
    allow_unauthenticated_audit: bool = False
    client_keys: list[str] = Field(default_factory=list)
    require_client_key: bool = False


class SecurityConfig(BaseModel):
    mode: Mode = "sanitize"
    fail_closed: bool = False
    allow_client_mode_override: bool = False
    inspect_tools: bool = True
    detectors: DetectorsConfig = Field(default_factory=DetectorsConfig)
    watchlist: WatchlistConfig = Field(default_factory=WatchlistConfig)
    substitutions: SubstitutionsConfig = Field(default_factory=SubstitutionsConfig)
    output_scan: OutputScanConfig = Field(default_factory=OutputScanConfig)
    pseudonymization: PseudonymizationConfig = Field(default_factory=PseudonymizationConfig)
    overrides: OverridesConfig = Field(default_factory=OverridesConfig)
    audit: AuditConfig = Field(default_factory=AuditConfig)
    upstream: UpstreamConfig = Field(default_factory=UpstreamConfig)
    upstreams: list[UpstreamConfig] = Field(default_factory=list)
    mcp: McpConfig = Field(default_factory=McpConfig)
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    auth: AuthConfig = Field(default_factory=AuthConfig)
    # SQLite/JSON store for console-managed runtime overrides. Empty disables
    # runtime persistence (changes live only for the process lifetime).
    runtime_config_path: str = "${LONO_DATA_DIR:-data}/runtime_config.json"

    @field_validator("mode", mode="before")
    @classmethod
    def _lower_mode(cls, value: object) -> object:
        return value.lower() if isinstance(value, str) else value

    def all_upstreams(self) -> list[UpstreamConfig]:
        """Default upstream first, then additional named upstreams (deduped)."""
        routes = [self.upstream]
        seen = {self.upstream.name}
        for upstream in self.upstreams:
            if upstream.name in seen:
                continue
            seen.add(upstream.name)
            routes.append(upstream)
        return routes


def _default_config_paths() -> list[Path]:
    repo_root = Path(__file__).resolve().parents[3]
    return [
        Path("/config/security.yaml"),
        Path("config/security.yaml"),
        repo_root / "config" / "security.yaml",
    ]


def _apply_env_overrides(cfg: SecurityConfig) -> None:
    def env(*names: str) -> str | None:
        for name in names:
            value = os.environ.get(name)
            if value:
                return value
        return None

    mode = env("AI_GATEWAY_MODE", "LONO_MODE")
    if mode:
        cfg.mode = mode.lower()  # type: ignore[assignment]

    if (value := env("LONO_ADMIN_KEY")) is not None:
        cfg.auth.admin_key = value
    if (value := env("LONO_PSEUDONYM_SECRET")) is not None:
        cfg.pseudonymization.secret = value
    if (value := env("LONO_UPSTREAM_URL")) is not None:
        cfg.upstream.base_url = value
    if (value := env("LONO_FAIL_CLOSED")) is not None:
        cfg.fail_closed = value.strip().lower() in {"1", "true", "yes", "on"}
    if (value := env("LONO_ALLOW_MODE_OVERRIDE")) is not None:
        cfg.allow_client_mode_override = value.strip().lower() in {"1", "true", "yes", "on"}

    data_dir = env("LONO_DATA_DIR")
    if data_dir:
        if cfg.audit.sqlite_path.startswith("/data") or cfg.audit.sqlite_path.startswith("data"):
            cfg.audit.sqlite_path = str(Path(data_dir) / "audit.db")
        if cfg.audit.media.local_path.startswith("/data") or cfg.audit.media.local_path.startswith("data"):
            cfg.audit.media.local_path = str(Path(data_dir) / "media")
        if cfg.runtime_config_path.startswith("/data") or cfg.runtime_config_path.startswith("data"):
            cfg.runtime_config_path = str(Path(data_dir) / "runtime_config.json")

    if (value := env("LONO_MEDIA_BACKEND")) is not None:
        cfg.audit.media.backend = value.lower()  # type: ignore[assignment]
    if (value := env("MINIO_ENDPOINT")) is not None:
        cfg.audit.media.endpoint = value
    if (value := env("MINIO_ACCESS_KEY", "MINIO_ROOT_USER")) is not None:
        cfg.audit.media.access_key = value
    if (value := env("MINIO_SECRET_KEY", "MINIO_ROOT_PASSWORD")) is not None:
        cfg.audit.media.secret_key = value
    if (value := env("MINIO_BUCKET")) is not None:
        cfg.audit.media.bucket = value
    if (value := env("MINIO_SECURE")) is not None:
        cfg.audit.media.secure = value.strip().lower() in {"1", "true", "yes", "on"}

    if (value := env("LANGFUSE_HOST")) is not None:
        cfg.audit.langfuse.host = value
    if (value := env("LANGFUSE_PUBLIC_KEY")) is not None:
        cfg.audit.langfuse.public_key = value
    if (value := env("LANGFUSE_SECRET_KEY")) is not None:
        cfg.audit.langfuse.secret_key = value
    if (value := env("LANGFUSE_ENABLED")) is not None:
        cfg.audit.langfuse.enabled = value.strip().lower() in {"1", "true", "yes", "on"}

    if not cfg.pseudonymization.secret:
        cfg.pseudonymization.secret = secrets.token_hex(32)
        logger.warning(
            "pseudonymization.secret is not configured; generated ephemeral secret. "
            "Set LONO_PSEUDONYM_SECRET for stable pseudonyms across restarts."
        )


def _clean_nulls(value: object) -> object:
    """Empty env substitutions parse as YAML null; string config fields want ""."""
    if value is None:
        return ""
    if isinstance(value, dict):
        return {key: _clean_nulls(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clean_nulls(item) for item in value]
    return value


def load_settings(path: str | Path | None = None) -> SecurityConfig:
    config_path: Path | None = None
    if path is not None:
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"security config not found: {config_path}")
    else:
        if env_path := os.environ.get("LONO_SECURITY_CONFIG"):
            candidate = Path(env_path)
            if candidate.exists():
                config_path = candidate
        if config_path is None:
            for candidate in _default_config_paths():
                if candidate.exists():
                    config_path = candidate
                    break

    if config_path is not None:
        raw = _clean_nulls(yaml.safe_load(_expand_env(config_path.read_text(encoding="utf-8")))) or {}
        if not isinstance(raw, dict):
            raise ValueError(f"security config must be a mapping: {config_path}")
        cfg = SecurityConfig.model_validate(raw)
        logger.info("loaded security config from %s", config_path)
    else:
        cfg = SecurityConfig()
        logger.warning("no security.yaml found; using built-in defaults")

    _apply_env_overrides(cfg)
    if cfg.mode not in ("observe", "sanitize", "enforce"):
        raise ValueError(f"invalid mode: {cfg.mode}")
    return cfg