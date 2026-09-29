"""Shared internal types for the Lono gateway."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

Mode = Literal["observe", "sanitize", "enforce"]
FindingAction = Literal[
    "observed", "flagged", "masked", "pseudonymized", "blocked", "ignored", "stripped", "allowed"
]
Shape = Literal["openai.chat", "openai.completions", "openai.responses", "anthropic.messages", "passthrough"]


def utc_now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class Detection(BaseModel):
    """A raw detector hit before policy is applied."""

    detector: str
    kind: str
    start: int
    end: int
    score: float = 0.5
    suggested: str = "flag"
    value: str = ""
    # Explicit literal replacement (keyword swaps). When set, the pseudonymizer
    # uses it verbatim instead of generating a synthetic value.
    replacement: str = ""


class Finding(BaseModel):
    """A detector hit after policy has been applied, safe to persist."""

    detector: str
    kind: str
    start: int
    end: int
    score: float
    action: FindingAction
    preview: str = ""
    before: str | None = None
    replacement: str | None = None


class MappingRecord(BaseModel):
    scope: str
    entity_type: str
    original_key: str
    original: str
    pseudonym: str


class RequestContext(BaseModel):
    request_id: str
    session_id: str
    project: str | None = None
    mode: Mode = "sanitize"
    shape: Shape = "passthrough"
    path: str = "/"
    stream: bool = False
    client_meta: dict[str, Any] = Field(default_factory=dict)


_WS_RE = re.compile(r"\s+")


def preview_span(text: str, start: int, end: int, radius: int = 28) -> str:
    """Redacted context preview: the matched span is replaced, never persisted."""
    before = text[max(0, start - radius) : start]
    after = text[end : end + radius]
    snippet = f"{before}«…»{after}"
    snippet = _WS_RE.sub(" ", snippet).strip()
    return snippet[:200]


def normalize_key(value: str) -> str:
    return _WS_RE.sub(" ", value.strip()).casefold()


def resolve_overlaps(detections: list[Detection]) -> list[Detection]:
    """Greedy non-overlapping selection: earliest, then highest score, then longest."""
    ordered = sorted(detections, key=lambda d: (d.start, -d.score, -(d.end - d.start)))
    selected: list[Detection] = []
    last_end = -1
    for det in ordered:
        if det.start >= last_end and det.end > det.start:
            selected.append(det)
            last_end = det.end
    return selected