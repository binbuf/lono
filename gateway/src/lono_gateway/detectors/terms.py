"""Watchlist detector: project codenames, internal terms and other sensitive strings.

Terms come from ``config/watchlist.yaml`` and/or inline
``watchlist.terms`` in ``security.yaml``. Each term declares a category (used
as the finding kind), a replacement type (which pseudonym generator to use),
an action, and a match mode.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import yaml

from lono_gateway.models import Detection
from lono_gateway.settings import WatchlistConfig, WatchTerm

logger = logging.getLogger(__name__)


class _CompiledTerm:
    def __init__(self, term: WatchTerm) -> None:
        self.term = term
        self.kind = term.replacement_type or term.category
        flags = 0 if term.case_sensitive else re.IGNORECASE
        self.regex: re.Pattern[str] | None
        if term.match == "regex":
            try:
                self.regex = re.compile(term.term, flags)
            except re.error as exc:
                logger.warning("invalid watchlist regex %r: %s", term.term, exc)
                self.regex = None
        else:
            escaped = re.escape(term.term)
            pattern = rf"(?<!\w){escaped}(?!\w)" if term.match == "word" else escaped
            self.regex = re.compile(pattern, flags)

    def scan(self, text: str) -> list[Detection]:
        if self.regex is None:
            return []
        return [
            Detection(
                detector="watchlist",
                kind=self.kind,
                start=match.start(),
                end=match.end(),
                score=0.95,
                suggested=self.term.action,
                value=match.group(0),
                replacement=self.term.replacement,
            )
            for match in self.regex.finditer(text)
        ]


def _load_terms_file(path: str) -> list[WatchTerm]:
    candidate = Path(path)
    if not candidate.exists() and path.startswith("/"):
        repo_root = Path(__file__).resolve().parents[3]
        candidate = repo_root / path.lstrip("/")
    if not candidate.exists():
        return []
    try:
        raw = yaml.safe_load(candidate.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001 - config errors must not kill the gateway
        logger.warning("could not read watchlist %s: %s", candidate, exc)
        return []
    entries = raw.get("terms") if isinstance(raw, dict) else None
    terms: list[WatchTerm] = []
    for entry in entries or []:
        if not isinstance(entry, dict) or not entry.get("term"):
            continue
        try:
            terms.append(WatchTerm.model_validate(entry))
        except ValueError as exc:
            logger.warning("invalid watchlist entry %r: %s", entry.get("term"), exc)
    if terms:
        logger.info("loaded %d watchlist term(s) from %s", len(terms), candidate)
    return terms


class WatchlistDetector:
    name = "watchlist"

    def __init__(self, cfg: WatchlistConfig) -> None:
        self.cfg = cfg
        terms: list[WatchTerm] = list(cfg.terms)
        if cfg.enabled and cfg.file:
            terms.extend(_load_terms_file(cfg.file))
        seen: set[tuple[str, str, str]] = set()
        self.terms: list[_CompiledTerm] = []
        for term in terms:
            key = (term.term, term.category, term.match)
            if key in seen:
                continue
            seen.add(key)
            self.terms.append(_CompiledTerm(term))

    def scan(self, text: str) -> list[Detection]:
        if not self.cfg.enabled or not text:
            return []
        detections: list[Detection] = []
        for term in self.terms:
            detections.extend(term.scan(text))
        return detections