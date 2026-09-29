"""URL validation: scheme allowlists, private/metadata hosts, credential and exfil checks."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlsplit

from lono_gateway.models import Detection
from lono_gateway.settings import UrlsConfig

_URL_RE = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^\s<>\"'`\]\)}]+")
_BARE_METADATA_RE = re.compile(
    r"\b(169\.254\.169\.254|metadata\.google\.internal|metadata\.goog|fd00:ec2::254)\b", re.I
)
_PRIVATE_NAME_RE = re.compile(r"(?:^|\.)(?:local|internal|lan|localhost)$", re.I)
_OPAQUE_RE = re.compile(r"^[A-Za-z0-9+/=_\-]{200,}$")


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


class UrlDetector:
    name = "urls"

    def __init__(self, cfg: UrlsConfig) -> None:
        self.cfg = cfg

    def scan(self, text: str) -> list[Detection]:
        if not self.cfg.enabled or not text:
            return []
        found: list[Detection] = []
        for match in _BARE_METADATA_RE.finditer(text):
            found.append(
                Detection(
                    detector=self.name,
                    kind="URL_METADATA_ENDPOINT",
                    start=match.start(),
                    end=match.end(),
                    score=0.95,
                    suggested="flag",
                    value=match.group(0),
                )
            )
        for match in _URL_RE.finditer(text):
            found.extend(self._check_url(match.group(0), match.start(), match.end()))
        return found

    def _check_url(self, url: str, start: int, end: int) -> list[Detection]:
        issues: list[Detection] = []

        def add(kind: str, score: float) -> None:
            issues.append(
                Detection(
                    detector=self.name,
                    kind=kind,
                    start=start,
                    end=end,
                    score=score,
                    suggested="flag",
                    value=url[:120],
                )
            )

        try:
            parts = urlsplit(url)
        except ValueError:
            add("URL_MALFORMED", 0.5)
            return issues

        scheme = parts.scheme.lower()
        if scheme not in {s.lower() for s in self.cfg.allow_schemes}:
            add("URL_DISALLOWED_SCHEME", 0.9)
        if parts.username or parts.password:
            add("URL_EMBEDDED_CREDENTIALS", 0.85)

        host = parts.hostname or ""
        if host:
            if _is_private_ip(host):
                add("URL_PRIVATE_HOST", 0.9)
            elif _PRIVATE_NAME_RE.search(host):
                add("URL_INTERNAL_HOST", 0.6)
            if host.lower().startswith("xn--") or ".xn--" in host.lower():
                add("URL_PUNYCODE_HOST", 0.6)

        for key, value in parse_qsl(parts.query, keep_blank_values=False):
            if _OPAQUE_RE.match(value):
                add("URL_OPAQUE_QUERY", 0.7)
                break
            if len(value) > 100 and key.lower() in {"data", "url", "payload", "token", "key", "secret"}:
                add("URL_OPAQUE_QUERY", 0.6)
                break

        return issues