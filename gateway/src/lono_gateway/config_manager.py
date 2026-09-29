"""Runtime configuration managed from the console.

The base configuration is loaded from ``security.yaml`` and environment. The
console can then adjust a curated, safe subset of values (detector toggles and
actions, thresholds, mode, watchlist terms, keyword substitutions, upstreams,
MCP servers). Changes are applied to the live config in place — preserving the
nested object identities that detectors hold — persisted to a JSON file, and
callbacks are fired so components that compile config at construction time
(watchlist/substitution detectors, the upstream registry) can rebuild.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path
from typing import Any
from uuid import uuid4

from pydantic import BaseModel

from lono_gateway.settings import SecurityConfig, Substitution

logger = logging.getLogger(__name__)

# Curated allowlist. ``True`` allows the whole value; a set allows only the
# listed keys; a dict recurses. Anything not listed here can never be changed
# or persisted through the runtime API (secrets, media keys, auth, etc.).
_ALLOWED: dict[str, Any] = {
    "mode": True,
    "fail_closed": True,
    "allow_client_mode_override": True,
    "inspect_tools": True,
    "audit": {"enabled", "capture_original", "max_payload_bytes", "retention_days"},
    "detectors": {
        "secrets": {
            "enabled",
            "action",
            "entropy",
            "entropy_threshold",
            "entropy_min_length",
            "entropy_action",
            "custom",
        },
        "pii": {
            "enabled",
            "engine",
            "score_threshold",
            "default_action",
            "filter_technical",
            "actions",
        },
        "injection": {"enabled", "action", "flag_threshold", "block_threshold"},
        "urls": {"enabled", "action", "flag_threshold", "block_threshold", "allow_schemes"},
    },
    "output_scan": {"enabled", "secrets", "injection", "pii", "watchlist", "action"},
    "pseudonymization": {"stable_across_sessions"},
    "overrides": {"enabled", "default_max_minutes", "allow_permanent", "cache_seconds"},
    "watchlist": {"enabled", "terms"},
    "substitutions": {"enabled", "terms"},
    "upstream": True,
    "upstreams": True,
    "mcp": {"enabled", "timeout_s", "servers"},
}


def _filter_allowed(value: Any, spec: Any) -> Any:
    if spec is True:
        return value
    if isinstance(spec, dict) and isinstance(value, dict):
        kept: dict[str, Any] = {}
        for key, item in value.items():
            if key in spec:
                filtered = _filter_allowed(item, spec[key])
                if filtered is not None:
                    kept[key] = filtered
        return kept if kept else None
    if isinstance(spec, set) and isinstance(value, dict):
        kept = {key: item for key, item in value.items() if key in spec}
        return kept if kept else None
    return None


def _deep_merge(base: dict[str, Any], patch: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _copy_into(target: BaseModel, source: BaseModel) -> None:
    """Update ``target`` fields from ``source`` without replacing nested models."""
    for name in type(source).model_fields:
        value = getattr(source, name)
        current = getattr(target, name, None)
        if isinstance(value, BaseModel) and isinstance(current, BaseModel):
            _copy_into(current, value)
        else:
            setattr(target, name, value)


def _remove_nulls(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _remove_nulls(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [_remove_nulls(item) for item in value]
    return value


class ConfigManager:
    def __init__(self, cfg: SecurityConfig) -> None:
        self.cfg = cfg
        self.path = Path(cfg.runtime_config_path) if cfg.runtime_config_path else None
        self._store: dict[str, Any] = {}
        self._listeners: list[Callable[[], None]] = []

    # ------------------------------------------------------------- lifecycle

    def add_listener(self, callback: Callable[[], None]) -> None:
        self._listeners.append(callback)

    def _notify(self) -> None:
        for callback in self._listeners:
            try:
                callback()
            except Exception:  # noqa: BLE001 - a bad listener must not break config
                logger.exception("runtime config listener failed")

    def load(self) -> None:
        """Apply persisted runtime overrides on top of the loaded config."""
        if self.path is None or not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            logger.warning("could not read runtime config %s: %s", self.path, exc)
            return
        if not isinstance(raw, dict):
            return
        self._store = _filter_allowed(raw, _ALLOWED) or {}
        if self._store:
            self._apply(self._store)
            logger.info("applied runtime config overrides from %s", self.path)

    def _persist(self) -> None:
        if self.path is None:
            return
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._store, indent=2, ensure_ascii=False), encoding="utf-8")
        except OSError as exc:
            logger.warning("could not persist runtime config %s: %s", self.path, exc)

    def _apply(self, data: dict[str, Any]) -> None:
        merged = _deep_merge(self.cfg.model_dump(mode="json"), data)
        validated = SecurityConfig.model_validate(_remove_nulls(merged))
        _copy_into(self.cfg, validated)

    # ---------------------------------------------------------------- public

    def update(self, patch: dict[str, Any], *, persist: bool = True) -> dict[str, Any]:
        filtered = _filter_allowed(patch, _ALLOWED) or {}
        if filtered:
            self._store = _deep_merge(self._store, filtered)
            self._apply(self._store)
            if persist:
                self._persist()
            self._notify()
        return self.snapshot()

    def snapshot(self) -> dict[str, Any]:
        """The full config with secrets redacted, for the console."""
        data = self.cfg.model_dump(mode="json")
        auth = data.get("auth") or {}
        auth["admin_key"] = "***" if auth.get("admin_key") else ""
        data["auth"] = auth
        pseudo = data.get("pseudonymization") or {}
        pseudo["secret"] = "***" if pseudo.get("secret") else ""
        data["pseudonymization"] = pseudo
        audit = data.get("audit") or {}
        media = audit.get("media") or {}
        for key in ("access_key", "secret_key"):
            if media.get(key):
                media[key] = "***"
        audit["media"] = media
        langfuse = audit.get("langfuse") or {}
        for key in ("public_key", "secret_key"):
            if langfuse.get(key):
                langfuse[key] = "***"
        audit["langfuse"] = langfuse
        data["audit"] = audit
        mcp = data.get("mcp") or {}
        servers = mcp.get("servers") or []
        for server in servers:
            headers = server.get("headers") or {}
            server["headers"] = {key: "***" for key in headers}
        mcp["servers"] = servers
        data["mcp"] = mcp
        data["runtime_config_path"] = self.cfg.runtime_config_path
        data["upstreams"] = [upstream.model_dump(mode="json") for upstream in self.cfg.all_upstreams()]
        return data

    # ---------------------------------------------------------- substitutions

    def list_substitutions(self) -> list[dict[str, Any]]:
        return [item.model_dump(mode="json") for item in self.cfg.substitutions.terms]

    def add_substitution(self, body: dict[str, Any]) -> dict[str, Any]:
        if not body.get("id"):
            body = {**body, "id": uuid4().hex[:12]}
        terms = [item.model_dump(mode="json") for item in self.cfg.substitutions.terms]
        terms.append(body)
        self.update({"substitutions": {"terms": terms}})
        return next(
            item.model_dump(mode="json")
            for item in self.cfg.substitutions.terms
            if item.id == body["id"]
        )

    def remove_substitution(self, substitution_id: str) -> bool:
        terms = [item for item in self.cfg.substitutions.terms if item.id != substitution_id]
        if len(terms) == len(self.cfg.substitutions.terms):
            return False
        self.update(
            {"substitutions": {"terms": [item.model_dump(mode="json") for item in terms]}}
        )
        return True

    def validate_substitution(self, body: dict[str, Any]) -> Substitution:
        return Substitution.model_validate(body)

    # ---------------------------------------------------------- secret rules

    def list_secret_rules(self) -> list[dict[str, Any]]:
        return [rule.model_dump(mode="json") for rule in self.cfg.detectors.secrets.custom]

    def add_secret_rule(self, body: dict[str, Any]) -> dict[str, Any]:
        if not body.get("id"):
            body = {**body, "id": uuid4().hex[:12]}
        rules = [rule.model_dump(mode="json") for rule in self.cfg.detectors.secrets.custom]
        rules.append(body)
        self.update({"detectors": {"secrets": {"custom": rules}}})
        return next(
            rule.model_dump(mode="json")
            for rule in self.cfg.detectors.secrets.custom
            if rule.id == body["id"]
        )

    def remove_secret_rule(self, rule_id: str) -> bool:
        rules = [rule for rule in self.cfg.detectors.secrets.custom if rule.id != rule_id]
        if len(rules) == len(self.cfg.detectors.secrets.custom):
            return False
        self.update(
            {"detectors": {"secrets": {"custom": [rule.model_dump(mode="json") for rule in rules]}}}
        )
        return True