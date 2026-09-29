"""PII detection: Presidio analyzer over HTTP with a regex fallback."""

from __future__ import annotations

import logging
import re
import time
from pathlib import Path

import httpx
import yaml

from lono_gateway.detectors import DetectorUnavailable
from lono_gateway.models import Detection
from lono_gateway.settings import PiiConfig

logger = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
_PHONE_INTL_RE = re.compile(r"(?<!\w)\+\d{1,3}[\s.\-]?\(?\d{1,4}\)?(?:[\s.\-]\d{2,4}){2,4}(?!\w)")
_PHONE_US_RE = re.compile(r"(?<!\w)\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}(?!\w)")
_SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_CC_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ \-]?){13,19}(?!\d)")
_IPV4_RE = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{0,4}\b")
_STREET_RE = re.compile(
    r"\b\d{1,5}\s+(?:[A-Z][A-Za-z0-9.'\-]*\s){1,4}"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|"
    r"Place|Pl|Terrace|Ter|Highway|Hwy|Circle|Cir|Square|Sq|Parkway|Pkwy)\.?"
    r"(?:\s*,?\s*(?:Suite|Ste|Apt|Unit|#)\s*[A-Za-z0-9\-]+)?",
    re.IGNORECASE,
)
_POSTAL_UK_RE = re.compile(r"\b[A-Z]{1,2}\d{1,2}[A-Z]?\s?\d[A-Z]{2}\b")
_POSTAL_US_RE = re.compile(r"(?<=\b[A-Z]{2}\s)\d{5}(?:-\d{4})?\b")
_BTC_RE = re.compile(r"\b(?:bc1[a-z0-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
_ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
_MAC_RE = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")

_MAX_CC_DIGITS = 19


def _luhn_ok(digits: str) -> bool:
    if len(digits) < 13 or len(digits) > _MAX_CC_DIGITS or len(set(digits)) == 1:
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


class _RegexPii:
    def __init__(self, custom_patterns: list[tuple[str, re.Pattern[str], float, str]]) -> None:
        self.custom_patterns = custom_patterns

    def scan(self, text: str) -> list[Detection]:
        found: list[Detection] = []

        def add(kind: str, start: int, end: int, score: float, suggested: str = "pseudonymize") -> None:
            found.append(
                Detection(
                    detector="pii.regex",
                    kind=kind,
                    start=start,
                    end=end,
                    score=score,
                    suggested=suggested,
                    value=text[start:end],
                )
            )

        for match in _EMAIL_RE.finditer(text):
            add("EMAIL_ADDRESS", match.start(), match.end(), 0.9)
        for pattern in (_PHONE_INTL_RE, _PHONE_US_RE):
            for match in pattern.finditer(text):
                add("PHONE_NUMBER", match.start(), match.end(), 0.7)
        for match in _SSN_RE.finditer(text):
            if match.group(0)[:3] not in {"000", "666"} and not match.group(0).startswith("9"):
                add("US_SSN", match.start(), match.end(), 0.85, suggested="mask")
        for match in _CC_CANDIDATE_RE.finditer(text):
            digits = re.sub(r"\D", "", match.group(0))
            if _luhn_ok(digits):
                add("CREDIT_CARD", match.start(), match.end(), 0.85, suggested="mask")
        for match in _IPV4_RE.finditer(text):
            add("IP_ADDRESS", match.start(), match.end(), 0.6)
        for match in _IPV6_RE.finditer(text):
            if "::" in match.group(0) or match.group(0).count(":") >= 3:
                add("IP_ADDRESS", match.start(), match.end(), 0.6)
        for match in _STREET_RE.finditer(text):
            add("STREET_ADDRESS", match.start(), match.end(), 0.6)
        for match in _POSTAL_UK_RE.finditer(text):
            add("POSTAL_CODE", match.start(), match.end(), 0.7)
        for match in _POSTAL_US_RE.finditer(text):
            add("POSTAL_CODE", match.start(), match.end(), 0.6)
        for match in _BTC_RE.finditer(text):
            add("BTC_ADDRESS", match.start(), match.end(), 0.75, suggested="mask")
        for match in _ETH_RE.finditer(text):
            add("ETH_ADDRESS", match.start(), match.end(), 0.75, suggested="mask")
        for match in _MAC_RE.finditer(text):
            add("MAC_ADDRESS", match.start(), match.end(), 0.4, suggested="flag")
        for name, pattern, score, suggested in self.custom_patterns:
            for match in pattern.finditer(text):
                add(name, match.start(), match.end(), score, suggested=suggested)
        return found


def _load_custom_patterns(path: str) -> list[tuple[str, re.Pattern[str], float, str]]:
    candidates = [Path(path)]
    if path.startswith("/"):
        candidates.append(Path(path.lstrip("/")))
    repo_root = Path(__file__).resolve().parents[3]
    candidates.append(repo_root / path.lstrip("/"))
    pattern_path = next((candidate for candidate in candidates if candidate.exists()), None)
    if pattern_path is None:
        return []
    try:
        raw = yaml.safe_load(pattern_path.read_text(encoding="utf-8")) or {}
    except Exception as exc:  # noqa: BLE001 - config errors must not kill the gateway
        logger.warning("could not read custom PII patterns from %s: %s", pattern_path, exc)
        return []
    recognizers = raw.get("recognizers") if isinstance(raw, dict) else None
    compiled: list[tuple[str, re.Pattern[str], float, str]] = []
    for entry in recognizers or []:
        if not isinstance(entry, dict):
            continue
        name = entry.get("entity") or entry.get("name")
        regex = entry.get("regex")
        if not name or not regex:
            continue
        try:
            compiled.append(
                (
                    str(name),
                    re.compile(str(regex)),
                    float(entry.get("score", 0.8)),
                    str(entry.get("action", "pseudonymize")),
                )
            )
        except re.error as exc:
            logger.warning("invalid custom PII pattern %r: %s", name, exc)
    if compiled:
        logger.info("loaded %d custom PII recognizer pattern(s) from %s", len(compiled), pattern_path)
    return compiled


class PresidioClient:
    """Minimal async client for the Presidio analyzer HTTP API."""

    def __init__(self, cfg: PiiConfig, fail_closed: bool) -> None:
        self.cfg = cfg
        self.fail_closed = fail_closed
        self._client = httpx.AsyncClient(base_url=cfg.presidio_url.rstrip("/"), timeout=cfg.timeout_s)
        self._cooldown_until = 0.0

    async def analyze(self, text: str) -> list[Detection]:
        if time.monotonic() < self._cooldown_until:
            return []
        payload = {
            "text": text,
            "language": self.cfg.language,
            "score_threshold": self.cfg.score_threshold,
        }
        try:
            response = await self._client.post("/analyze", json=payload)
            response.raise_for_status()
            results = response.json()
        except Exception as exc:  # noqa: BLE001 - external analyzer
            logger.warning(
                "presidio analyzer unavailable (%s); using regex PII patterns only",
                exc.__class__.__name__,
            )
            self._cooldown_until = time.monotonic() + self.cfg.failure_cooldown_s
            if self.cfg.engine == "presidio" and self.fail_closed:
                raise DetectorUnavailable("presidio analyzer unavailable") from exc
            return []
        detections: list[Detection] = []
        for item in results if isinstance(results, list) else []:
            try:
                start = int(item["start"])
                end = int(item["end"])
                kind = str(item["entity_type"])
                score = float(item.get("score", 0.5))
            except (KeyError, TypeError, ValueError):
                continue
            detections.append(
                Detection(
                    detector="pii.presidio",
                    kind=kind,
                    start=start,
                    end=end,
                    score=score,
                    suggested="pseudonymize",
                    value=text[start:end],
                )
            )
        return detections

    async def aclose(self) -> None:
        await self._client.aclose()


class PiiDetector:
    name = "pii"

    def __init__(self, cfg: PiiConfig, fail_closed: bool = False) -> None:
        self.cfg = cfg
        self.regex = _RegexPii(_load_custom_patterns(cfg.custom_patterns_file))
        self.presidio = PresidioClient(cfg, fail_closed) if cfg.engine in {"auto", "presidio"} else None

    async def scan(self, text: str) -> list[Detection]:
        if not self.cfg.enabled:
            return []
        detections = self.regex.scan(text)
        if self.presidio is not None:
            detections.extend(await self.presidio.analyze(text))
        return detections

    async def aclose(self) -> None:
        if self.presidio is not None:
            await self.presidio.aclose()