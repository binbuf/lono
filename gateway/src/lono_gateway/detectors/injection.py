"""Prompt-injection heuristics.

No classifier is foolproof; these are weighted signals, not ground truth.
"""

from __future__ import annotations

import re

from lono_gateway.models import Detection
from lono_gateway.settings import InjectionConfig

_PATTERNS: list[tuple[str, re.Pattern[str], float]] = [
    (
        "instruction_override",
        re.compile(
            r"\b(?:ignore|disregard|forget)\b[^.\n]{0,40}\b(?:all\s+)?"
            r"(?:previous|prior|above|earlier|system)\b[^.\n]{0,20}"
            r"\b(?:instructions?|prompts?|rules?|directions?)\b",
            re.I,
        ),
        0.9,
    ),
    (
        "instruction_override",
        re.compile(
            r"\b(?:override|bypass|circumvent)\b[^.\n]{0,30}\b(?:safety|security|guardrails?|filters?|restrictions?)\b",
            re.I,
        ),
        0.7,
    ),
    (
        "system_prompt_exfiltration",
        re.compile(
            r"\b(?:reveal|show|print|repeat|display|output|leak|expose)\b[^.\n]{0,30}"
            r"\b(?:system|hidden|initial|developer|original|internal)\b[^.\n]{0,20}"
            r"\b(?:prompt|instructions?|message)\b",
            re.I,
        ),
        0.9,
    ),
    (
        "system_prompt_probe",
        re.compile(r"\b(?:what|which)\b[^.\n]{0,30}\b(?:system prompt|initial instructions?)\b", re.I),
        0.5,
    ),
    (
        "jailbreak_persona",
        re.compile(
            r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be|roleplay\s+as)\b[^.\n]{0,40}"
            r"\b(?:dan|jailbroken|unrestricted|unfiltered|no\s+(?:rules|restrictions|filters|limits))\b",
            re.I,
        ),
        0.8,
    ),
    ("dan", re.compile(r"\bdo\s+anything\s+now\b|\bDAN\s+mode\b", re.I), 0.7),
    (
        "developer_mode",
        re.compile(r"\b(?:developer|debug|god|sudo|admin(?:istrator)?)\s+mode\b", re.I),
        0.5,
    ),
    (
        "exfiltration_intent",
        re.compile(
            r"\b(?:exfiltrate|send|post|upload|transmit|leak|forward)\b[^.\n]{0,60}"
            r"\b(?:https?://|api\s+keys?|credentials?|secrets?|tokens?|env(?:ironment)?\s+variables?|"
            r"\.ssh|ssh\s+keys?)\b",
            re.I,
        ),
        0.8,
    ),
    (
        "secret_probe",
        re.compile(
            r"\b(?:print|list|show|dump|reveal)\b[^.\n]{0,40}"
            r"\b(?:env(?:ironment)?\s+variables?|api\s+keys?|secrets?|credentials?|tokens?|\.env\b)",
            re.I,
        ),
        0.6,
    ),
    (
        "tool_abuse",
        re.compile(
            r"\b(?:run|execute|eval(?:uate)?)\b[^.\n]{0,30}"
            r"\b(?:shell|bash|powershell|cmd(?:\.exe)?|curl|wget|rm\s+-rf)\b",
            re.I,
        ),
        0.45,
    ),
    (
        "encoded_payload",
        re.compile(r"\b(?:base64|rot13|hex|encoded)\b[^.\n]{0,40}\b(?:decode|execute|run|follow)\b", re.I),
        0.7,
    ),
    (
        "hidden_unicode",
        re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]{3,}"),
        0.6,
    ),
    (
        "bidi_override",
        re.compile(r"[\u202a-\u202e\u2066-\u2069]"),
        0.5,
    ),
]


class InjectionDetector:
    name = "injection"

    def __init__(self, cfg: InjectionConfig) -> None:
        self.cfg = cfg

    def scan(self, text: str) -> list[Detection]:
        if not self.cfg.enabled or not text:
            return []
        found: list[Detection] = []
        for kind, pattern, weight in _PATTERNS:
            match = pattern.search(text)
            if match is None:
                continue
            found.append(
                Detection(
                    detector=self.name,
                    kind=kind,
                    start=match.start(),
                    end=match.end(),
                    score=weight,
                    suggested="flag",
                    value=match.group(0)[:64],
                )
            )
        return found

    @staticmethod
    def aggregate_score(detections: list[Detection]) -> float:
        """Combine independent signals: 1 - prod(1 - w)."""
        remaining = 1.0
        for det in detections:
            remaining *= 1.0 - max(0.0, min(1.0, det.score))
        return round(min(1.0, 1.0 - remaining), 4)