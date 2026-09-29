"""Keyword substitutions: swap exact strings for chosen replacements.

Unlike the watchlist (which generates a plausible fake), a substitution carries
an explicit replacement — e.g. ``youruser`` → ``alex`` or
``C:\\Users\\youruser`` → ``/home/user``. The swap is still recorded as a mapping so
provider output is rehydrated back to the original value.
"""

from __future__ import annotations

import logging
import re

from lono_gateway.models import Detection
from lono_gateway.settings import SubstitutionsConfig

logger = logging.getLogger(__name__)


class _CompiledSubstitution:
    def __init__(self, spec) -> None:
        self.spec = spec
        self.kind = spec.category or "SUBSTITUTION"
        flags = 0 if spec.case_sensitive else re.IGNORECASE
        self.regex: re.Pattern[str] | None
        if spec.match == "regex":
            try:
                self.regex = re.compile(spec.pattern, flags)
            except re.error as exc:
                logger.warning("invalid substitution regex %r: %s", spec.pattern, exc)
                self.regex = None
        else:
            escaped = re.escape(spec.pattern)
            if spec.match == "word":
                pattern = rf"(?<!\w){escaped}(?!\w)"
            else:
                pattern = escaped
            self.regex = re.compile(pattern, flags)

    def scan(self, text: str) -> list[Detection]:
        if self.regex is None or not self.spec.enabled:
            return []
        return [
            Detection(
                detector="substitution",
                kind=self.kind,
                start=match.start(),
                end=match.end(),
                score=1.0,
                suggested="pseudonymize",
                value=match.group(0),
                replacement=self.spec.replacement,
            )
            for match in self.regex.finditer(text)
        ]


class SubstitutionDetector:
    name = "substitution"

    def __init__(self, cfg: SubstitutionsConfig) -> None:
        self.cfg = cfg
        self.terms = [_CompiledSubstitution(spec) for spec in cfg.terms if spec.pattern]

    def scan(self, text: str) -> list[Detection]:
        if not self.cfg.enabled or not text:
            return []
        detections: list[Detection] = []
        for term in self.terms:
            detections.extend(term.scan(text))
        return detections