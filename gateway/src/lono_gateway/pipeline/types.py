"""Shared pipeline result types (kept dependency-free to avoid import cycles)."""

from __future__ import annotations

from dataclasses import dataclass, field

from lono_gateway.models import Finding, MappingRecord


@dataclass
class TextResult:
    text: str
    findings: list[Finding] = field(default_factory=list)
    mappings: list[MappingRecord] = field(default_factory=list)
    blocked: bool = False
    block_kinds: list[str] = field(default_factory=list)


@dataclass
class ResponseOutcome:
    payload: object
    findings: list[Finding] = field(default_factory=list)