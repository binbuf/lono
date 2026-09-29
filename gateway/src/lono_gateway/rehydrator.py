"""Rehydration of pseudonyms back to their originals, including streaming-safe mode."""

from __future__ import annotations

import json
import re

from lono_gateway.models import MappingRecord

_BOUNDARY_LEFT = r"(?<![A-Za-z0-9])"
_BOUNDARY_RIGHT = r"(?![A-Za-z0-9])"


def _json_string_content(value: str) -> str:
    """Escape a value so it is safe *inside* a JSON string literal.

    Pseudonyms are rehydrated into tool-call arguments, which are themselves
    JSON documents streamed as a string. If the original contains a quote,
    backslash or control character, inserting it raw corrupts that inner JSON
    (the client then fails with "bad escaped character"). Escaping here keeps
    the arguments valid while still delivering the original value.
    """
    return json.dumps(value, ensure_ascii=False)[1:-1]


class Rehydrator:
    """Restores original values for pseudonyms emitted by the gateway."""

    def __init__(self, mappings: dict[str, str], *, json_escape: bool = False) -> None:
        self._mappings = dict(mappings)
        if json_escape:
            self._replacements = {key: _json_string_content(value) for key, value in self._mappings.items()}
        else:
            self._replacements = dict(self._mappings)
        self._regex: re.Pattern[str] | None = None
        if self._mappings:
            pseudonyms = sorted(self._mappings, key=len, reverse=True)
            alternation = "|".join(re.escape(p) for p in pseudonyms)
            self._regex = re.compile(rf"{_BOUNDARY_LEFT}({alternation}){_BOUNDARY_RIGHT}")

    @property
    def has_mappings(self) -> bool:
        return bool(self._mappings)

    def rehydrate(self, text: str) -> str:
        if not self._regex or not text:
            return text
        return self._regex.sub(lambda match: self._replacements.get(match.group(1), match.group(1)), text)

    def rehydrate_prefix(self, text: str, limit: int) -> str:
        """Rehydrate only matches that end at or before ``limit``.

        Matching runs over the full text so word-boundary lookarounds see the
        real following character; matches crossing the limit are left for later.
        """
        if limit <= 0:
            return ""
        if not self._regex:
            return text[:limit]
        output: list[str] = []
        position = 0
        for match in self._regex.finditer(text):
            if match.start() >= limit:
                break
            if match.end() > limit:
                break
            output.append(text[position : match.start()])
            output.append(self._replacements.get(match.group(1), match.group(1)))
            position = match.end()
        output.append(text[position:limit])
        return "".join(output)

    def crossing_start(self, text: str, index: int) -> int | None:
        """Start index of a match straddling ``index``, if any."""
        if not self._regex:
            return None
        for match in self._regex.finditer(text):
            if match.start() < index < match.end():
                return match.start()
        return None

    def last_match_end(self, text: str) -> int:
        """End offset of the last complete match, or 0 when there is none."""
        if not self._regex:
            return 0
        end = 0
        for match in self._regex.finditer(text):
            end = match.end()
        return end


class StreamingRehydrator:
    """Incrementally rehydrates deltas without splitting pseudonyms across chunks.

    Holds back text that could be the prefix of a known pseudonym (or the
    beginning of a match that straddles the emission point) and rehydrates the
    rest using full-buffer context.
    """

    def __init__(self, mappings: dict[str, str], *, json_escape: bool = False) -> None:
        self._rehydrator = Rehydrator(mappings, json_escape=json_escape)
        self._pseudonyms = tuple(mappings.keys())
        self._max_len = max((len(p) for p in self._pseudonyms), default=0)
        self._buffer = ""

    def feed(self, delta: str) -> str:
        if not delta:
            return ""
        if self._max_len == 0:
            return delta
        self._buffer += delta
        hold = self._hold_index()
        if hold <= 0:
            return ""
        transformed = self._rehydrator.rehydrate_prefix(self._buffer, hold)
        self._buffer = self._buffer[hold:]
        return transformed

    def flush(self) -> str:
        remaining, self._buffer = self._buffer, ""
        return self._rehydrator.rehydrate(remaining)

    def _hold_index(self) -> int:
        buffer = self._buffer
        length = len(buffer)
        hold = length
        # Tails inside an already-complete match are not the start of a new
        # pseudonym (e.g. "mona...com" ends with the same char it starts with).
        last_match_end = self._rehydrator.last_match_end(buffer)
        scan_from = max(0, length - self._max_len + 1, last_match_end)
        for index in range(scan_from, length):
            tail = buffer[index:]
            # Hold back only strict prefixes: a complete pseudonym is rehydrated now.
            if any(tail != p and p.startswith(tail) for p in self._pseudonyms):
                hold = index
                break
        if hold < length:
            crossing = self._rehydrator.crossing_start(buffer, hold)
            if crossing is not None:
                hold = crossing
        return hold


def mapping_scopes(session_id: str, stable_across_sessions: bool = False) -> list[str]:
    return ["global"] if stable_across_sessions else [f"session:{session_id}", "global"]


def load_rehydrator(store, session_id: str, stable_across_sessions: bool = False) -> Rehydrator:
    return Rehydrator(store.reverse_mappings(mapping_scopes(session_id, stable_across_sessions)))


def load_records(records: list[MappingRecord]) -> dict[str, str]:
    return {record.pseudonym: record.original for record in records}