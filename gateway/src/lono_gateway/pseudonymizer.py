"""Deterministic pseudonymization with a persisted, reversible mapping."""

from __future__ import annotations

import hashlib
import hmac
import random
from dataclasses import dataclass, field

from lono_gateway.models import Detection, Finding, MappingRecord, normalize_key, preview_span
from lono_gateway.pools import Pools, generate_pseudonym
from lono_gateway.settings import PseudonymizationConfig


@dataclass
class ResolvedDetection:
    detection: Detection
    action: str  # pseudonymize | mask | strip | flag | observed | block | ignore


@dataclass
class SubstituteResult:
    text: str
    findings: list[Finding] = field(default_factory=list)
    mappings: list[MappingRecord] = field(default_factory=list)
    blocked: bool = False
    block_kinds: list[str] = field(default_factory=list)


class Pseudonymizer:
    """Maps sensitive spans to deterministic synthetic values.

    Determinism is scoped: within a session by default, globally when
    ``stable_across_sessions`` is enabled. The mapping is persisted so the
    gateway can rehydrate provider responses now or after a restart.
    """

    def __init__(
        self,
        store,
        cfg: PseudonymizationConfig,
        session_id: str,
        pools: Pools | None = None,
    ) -> None:
        self.store = store
        self.cfg = cfg
        self.session_id = session_id
        self.scope = "global" if cfg.stable_across_sessions else f"session:{session_id}"
        self.pools = pools or Pools()
        self._cache: dict[tuple[str, str], str] = {}

    def substitute(self, text: str, resolved: list[ResolvedDetection]) -> SubstituteResult:
        parts: list[str] = []
        findings: list[Finding] = []
        mappings: list[MappingRecord] = []
        blocked = False
        block_kinds: list[str] = []
        position = 0

        for item in resolved:
            det = item.detection
            action = item.action
            if action == "ignore":
                continue
            parts.append(text[position : det.start])
            original = text[det.start : det.end]
            replacement: str | None = None

            if action == "block":
                blocked = True
                block_kinds.append(det.kind)
                parts.append(original)
            elif action == "pseudonymize":
                replacement = self._get_or_create(det.kind, original)
                parts.append(replacement)
                mappings.append(
                    MappingRecord(
                        scope=self.scope,
                        entity_type=det.kind,
                        original_key=normalize_key(original),
                        original=original,
                        pseudonym=replacement,
                    )
                )
            elif action == "mask":
                replacement = f"[REDACTED:{det.kind}]"
                parts.append(replacement)
            elif action == "strip":
                pass
            else:  # flag / observed
                parts.append(original)

            finding_action = {
                "pseudonymize": "pseudonymized",
                "mask": "masked",
                "strip": "stripped",
                "block": "blocked",
                "observed": "observed",
                "allow": "allowed",
            }.get(action, "flagged")
            findings.append(
                Finding(
                    detector=det.detector,
                    kind=det.kind,
                    start=det.start,
                    end=det.end,
                    score=det.score,
                    action=finding_action,  # type: ignore[arg-type]
                    preview=preview_span(text, det.start, det.end),
                    replacement=replacement,
                )
            )
            position = det.end

        parts.append(text[position:])
        return SubstituteResult(
            text="".join(parts), findings=findings, mappings=mappings, blocked=blocked, block_kinds=block_kinds
        )

    def _get_or_create(self, entity_type: str, original: str) -> str:
        key = normalize_key(original)
        cache_key = (entity_type, key)
        if cache_key in self._cache:
            return self._cache[cache_key]

        row = self.store.get_mapping(self.scope, entity_type, key)
        if row is not None:
            pseudonym = row["pseudonym"]
        else:
            pseudonym = self._generate(entity_type, key)
            attempt = 0
            while self.store.pseudonym_in_use(self.scope, pseudonym) and attempt < 20:
                attempt += 1
                pseudonym = self._generate(entity_type, f"{key}#{attempt}")
            self.store.put_mapping(
                scope=self.scope,
                entity_type=entity_type,
                original_key=key,
                original=original,
                pseudonym=pseudonym,
            )
        self._cache[cache_key] = pseudonym
        return pseudonym

    def _generate(self, entity_type: str, seed_material: str) -> str:
        digest = hmac.new(
            self.cfg.secret.encode("utf-8"),
            f"{self.scope}|{entity_type}|{seed_material}".encode(),
            hashlib.sha256,
        ).digest()
        rng = random.Random(int.from_bytes(digest[:8], "big"))
        original = seed_material
        return generate_pseudonym(entity_type, original, rng, self.pools)