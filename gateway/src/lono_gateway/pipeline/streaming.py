"""SSE stream translation: rehydrate deltas and assemble an auditable response."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from lono_gateway.rehydrator import StreamingRehydrator, load_records

_SEPARATORS = (b"\r\n\r\n", b"\n\n")


@dataclass
class StreamOutcome:
    assembled: dict[str, Any]
    raw_text: str
    raw_truncated: bool = False
    done: bool = False
    chunk_count: int = 0
    usage: dict[str, Any] = field(default_factory=dict)


class StreamTranslator:
    """Transforms provider SSE frames on the way back to the client.

    Rehydrates text and tool-argument deltas with a boundary-safe stream
    rehydrator, while accumulating the raw stream and an assembled final
    response for the audit store.
    """

    def __init__(self, shape: str, mappings: dict[str, str], max_raw_chars: int = 4_000_000) -> None:
        self.shape = shape
        self._mappings = mappings
        self._max_raw_chars = max_raw_chars
        self._buffer = b""
        self._rehydrators: dict[tuple, StreamingRehydrator] = {}
        self._raw_parts: list[str] = []
        self._raw_len = 0
        self.raw_truncated = False
        self.chunk_count = 0
        self.done = False
        self._pending_done: bytes | None = None
        self.usage: dict[str, Any] = {}
        self._openai_choices: dict[int, dict[str, Any]] = {}
        self._anthropic_message: dict[str, Any] = {}
        self._anthropic_blocks: dict[int, dict[str, Any]] = {}

    # ------------------------------------------------------------------ input

    def feed(self, chunk: bytes) -> list[bytes]:
        self._buffer += chunk
        output: list[bytes] = []
        while True:
            found = self._find_separator()
            if found is None:
                break
            start, end = found
            block, self._buffer = self._buffer[:start], self._buffer[end:]
            transformed = self._process_block(block)
            if transformed:
                output.append(transformed)
        return output

    def flush(self) -> tuple[bytes | None, StreamOutcome]:
        extra_parts: list[bytes] = []
        tail, self._buffer = self._buffer, b""
        if tail.strip():
            transformed = self._process_block(tail)
            if transformed:
                extra_parts.append(transformed)
        # Any pseudonym prefix held back by a stream rehydrator will never be
        # completed now that the stream is over; emit it instead of dropping it.
        extra_parts.extend(self._residual_events())
        if self._pending_done:
            extra_parts.append(self._pending_done)
            self._pending_done = None
        extra = b"".join(extra_parts) or None
        assembled = self._assembled()
        raw_text = "\n".join(self._raw_parts)
        return extra, StreamOutcome(
            assembled=assembled,
            raw_text=raw_text,
            raw_truncated=self.raw_truncated,
            done=self.done,
            chunk_count=self.chunk_count,
            usage=self.usage,
        )

    # --------------------------------------------------------------- internals

    def _find_separator(self) -> tuple[int, int] | None:
        best: tuple[int, int] | None = None
        for separator in _SEPARATORS:
            index = self._buffer.find(separator)
            if index != -1:
                candidate = (index, index + len(separator))
                if best is None or candidate[0] < best[0]:
                    best = candidate
        return best

    def _process_block(self, block: bytes) -> bytes:
        try:
            text = block.decode("utf-8")
        except UnicodeDecodeError:
            return block + b"\n\n"

        event_name: str | None = None
        data_lines: list[str] = []
        passthrough: list[str] = []
        for line in text.split("\n"):
            if line.startswith("event:"):
                event_name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
            elif line.strip() == "":
                continue
            else:
                passthrough.append(line)

        if not data_lines:
            return block + b"\n\n"

        data = "\n".join(data_lines)
        self._record_raw(data)
        if data.strip() == "[DONE]":
            # Hold the sentinel until flush so any rehydrator-held tail can be
            # emitted before the client is told the stream is over.
            self.done = True
            self._pending_done = block + b"\n\n"
            return b""

        try:
            payload = json.loads(data)
        except (ValueError, TypeError):
            return block + b"\n\n"
        if not isinstance(payload, dict):
            return block + b"\n\n"

        if self.shape == "openai.chat":
            self._handle_openai(payload)
        elif self.shape == "anthropic.messages":
            self._handle_anthropic(event_name, payload)

        new_data = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        lines = list(passthrough)
        if event_name is not None:
            lines.append(f"event: {event_name}")
        lines.append(f"data: {new_data}")
        return ("\n".join(lines) + "\n\n").encode("utf-8")

    def _record_raw(self, data: str) -> None:
        self.chunk_count += 1
        if self._raw_len >= self._max_raw_chars:
            self.raw_truncated = True
            return
        remaining = self._max_raw_chars - self._raw_len
        snippet = data if len(data) <= remaining else data[:remaining]
        if len(snippet) < len(data):
            self.raw_truncated = True
        self._raw_parts.append(snippet)
        self._raw_len += len(snippet)

    def _residual_events(self) -> list[bytes]:
        """Emit text held back by stream rehydrators at end of stream."""
        events: list[bytes] = []
        for cache_key, rehydrator in self._rehydrators.items():
            residual = rehydrator.flush()
            if not residual:
                continue
            fields = cache_key[1:]
            if self.shape == "openai.chat":
                payload = self._openai_residual_payload(fields, residual)
                if payload is not None:
                    self._accumulate_openai(payload["choices"][0])
                    events.append(self._encode_event(None, payload))
            elif self.shape == "anthropic.messages":
                event_name, payload = self._anthropic_residual_payload(fields, residual)
                if payload is not None:
                    events.append(self._encode_event(event_name, payload))
        return events

    def _openai_residual_payload(self, fields: list, residual: str) -> dict | None:
        choice = fields[1]
        kind = fields[2] if len(fields) > 2 else None
        if kind == "content":
            return {"choices": [{"index": choice, "delta": {"content": residual}}]}
        if kind == "part":
            part_index = fields[3] if len(fields) > 3 else 0
            return {
                "choices": [
                    {
                        "index": choice,
                        "delta": {"content": [{"type": "text", "text": residual, "index": part_index}]},
                    }
                ]
            }
        if kind == "tool":
            tool_index = fields[3] if len(fields) > 3 else 0
            return {
                "choices": [
                    {
                        "index": choice,
                        "delta": {"tool_calls": [{"index": tool_index, "function": {"arguments": residual}}]},
                    }
                ]
            }
        return None

    def _anthropic_residual_payload(self, fields: list, residual: str) -> tuple[str, dict | None]:
        index = fields[1]
        kind = fields[2] if len(fields) > 2 else None
        if kind == "text":
            self._append_anthropic_text(index, residual)
            return (
                "content_block_delta",
                {"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": residual}},
            )
        if kind == "thinking":
            self._append_anthropic_field(index, "thinking", residual)
            return (
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": index,
                    "delta": {"type": "thinking_delta", "thinking": residual},
                },
            )
        if kind == "input":
            block = self._anthropic_blocks.setdefault(index, {"type": "tool_use", "input": {}})
            block["_partial_json"] = block.get("_partial_json", "") + residual
            try:
                block["input"] = json.loads(block["_partial_json"])
            except (ValueError, TypeError):
                block["input"] = block["_partial_json"]
            return (
                "content_block_delta",
                {
                    "type": "content_block_delta",
                    "index": index,
                    "delta": {"type": "input_json_delta", "partial_json": residual},
                },
            )
        return "", None

    @staticmethod
    def _encode_event(event_name: str | None, payload: dict) -> bytes:
        lines = []
        if event_name is not None:
            lines.append(f"event: {event_name}")
        lines.append(f"data: {json.dumps(payload, ensure_ascii=False, separators=(',', ':'))}")
        return ("\n".join(lines) + "\n\n").encode("utf-8")

    def _reh(self, key: tuple, *, json_escape: bool = False) -> StreamingRehydrator:
        cache_key = (json_escape, *key)
        if cache_key not in self._rehydrators:
            self._rehydrators[cache_key] = StreamingRehydrator(self._mappings, json_escape=json_escape)
        return self._rehydrators[cache_key]

    def _handle_openai(self, payload: dict) -> None:
        for choice in payload.get("choices") or []:
            if not isinstance(choice, dict):
                continue
            index = choice.get("index", 0)
            delta = choice.get("delta")
            if isinstance(delta, dict):
                content = delta.get("content")
                if isinstance(content, str) and content:
                    delta["content"] = self._reh(("o", index, "content")).feed(content)
                elif isinstance(content, list):
                    for part_index, part in enumerate(content):
                        if (
                            isinstance(part, dict)
                            and part.get("type") == "text"
                            and isinstance(part.get("text"), str)
                        ):
                            part["text"] = self._reh(("o", index, "part", part_index)).feed(part["text"])
                for tool_call in delta.get("tool_calls") or []:
                    if not isinstance(tool_call, dict):
                        continue
                    tool_index = tool_call.get("index", 0)
                    function = tool_call.get("function")
                    if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                        function["arguments"] = self._reh(
                            ("o", index, "tool", tool_index), json_escape=True
                        ).feed(function["arguments"])
            self._accumulate_openai(choice)
        if isinstance(payload.get("usage"), dict):
            self.usage.update(payload["usage"])

    def _accumulate_openai(self, choice: dict) -> None:
        index = choice.get("index", 0)
        acc = self._openai_choices.setdefault(
            index,
            {"index": index, "message": {"role": "assistant", "content": "", "tool_calls": {}}, "finish_reason": None},
        )
        delta = choice.get("delta")
        if isinstance(delta, dict):
            content = delta.get("content")
            if isinstance(content, str):
                acc["message"]["content"] += content
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        acc["message"]["content"] += part["text"]
            for tool_call in delta.get("tool_calls") or []:
                if not isinstance(tool_call, dict):
                    continue
                tool_index = tool_call.get("index", 0)
                entry = acc["message"]["tool_calls"].setdefault(
                    tool_index, {"id": None, "type": "function", "function": {"name": None, "arguments": ""}}
                )
                if tool_call.get("id"):
                    entry["id"] = tool_call["id"]
                function = tool_call.get("function") or {}
                if function.get("name"):
                    entry["function"]["name"] = function["name"]
                if isinstance(function.get("arguments"), str):
                    entry["function"]["arguments"] += function["arguments"]
        if choice.get("finish_reason"):
            acc["finish_reason"] = choice["finish_reason"]

    def _handle_anthropic(self, event_name: str | None, payload: dict) -> None:
        event = event_name or payload.get("type") or ""
        if event == "message_start":
            message = payload.get("message")
            if isinstance(message, dict):
                self._anthropic_message = message
                usage = message.get("usage")
                if isinstance(usage, dict):
                    self.usage.update(usage)
        elif event == "content_block_start":
            index = payload.get("index", 0)
            block = payload.get("content_block")
            if isinstance(block, dict):
                self._anthropic_blocks[index] = dict(block)
                if block.get("type") == "tool_use":
                    self._anthropic_blocks[index]["_partial_json"] = ""
        elif event == "content_block_delta":
            index = payload.get("index", 0)
            delta = payload.get("delta")
            if isinstance(delta, dict):
                delta_type = delta.get("type")
                if delta_type == "text_delta" and isinstance(delta.get("text"), str):
                    delta["text"] = self._reh(("a", index, "text")).feed(delta["text"])
                    self._append_anthropic_text(index, delta["text"])
                elif delta_type == "thinking_delta" and isinstance(delta.get("thinking"), str):
                    delta["thinking"] = self._reh(("a", index, "thinking")).feed(delta["thinking"])
                    self._append_anthropic_field(index, "thinking", delta["thinking"])
                elif delta_type == "input_json_delta" and isinstance(delta.get("partial_json"), str):
                    delta["partial_json"] = self._reh(("a", index, "input"), json_escape=True).feed(
                        delta["partial_json"]
                    )
                    block = self._anthropic_blocks.setdefault(index, {"type": "tool_use", "input": {}})
                    block["_partial_json"] = block.get("_partial_json", "") + delta["partial_json"]
        elif event == "content_block_stop":
            index = payload.get("index", 0)
            block = self._anthropic_blocks.get(index)
            if isinstance(block, dict):
                # Keep ``_partial_json`` so a held-back tail flushed after the
                # block stop can still be appended and re-parsed.
                partial = block.get("_partial_json")
                if partial:
                    try:
                        block["input"] = json.loads(partial)
                    except (ValueError, TypeError):
                        block["input"] = partial
        elif event == "message_delta":
            usage = payload.get("usage")
            if isinstance(usage, dict):
                self.usage.update(usage)
            delta = payload.get("delta")
            if isinstance(delta, dict) and delta.get("stop_reason"):
                self._anthropic_message["stop_reason"] = delta["stop_reason"]
        elif event == "message_stop":
            self.done = True

    def _append_anthropic_text(self, index: int, text: str) -> None:
        block = self._anthropic_blocks.setdefault(index, {"type": "text", "text": ""})
        if block.get("type") == "text":
            block["text"] = block.get("text", "") + text

    def _append_anthropic_field(self, index: int, field_name: str, value: str) -> None:
        block = self._anthropic_blocks.setdefault(index, {"type": "thinking", field_name: ""})
        block[field_name] = block.get(field_name, "") + value

    def assembled(self) -> dict[str, Any]:
        return self._assembled()

    def _assembled(self) -> dict[str, Any]:
        if self.shape == "openai.chat":
            choices = []
            for index in sorted(self._openai_choices):
                acc = self._openai_choices[index]
                tool_calls = [
                    acc["message"]["tool_calls"][key] for key in sorted(acc["message"]["tool_calls"])
                ]
                message = dict(acc["message"])
                message["tool_calls"] = tool_calls
                choices.append({"index": index, "message": message, "finish_reason": acc["finish_reason"]})
            assembled = {"choices": choices}
            if self.usage:
                assembled["usage"] = self.usage
            return assembled
        if self.shape == "anthropic.messages":
            blocks = []
            for index in sorted(self._anthropic_blocks):
                block = {k: v for k, v in self._anthropic_blocks[index].items() if not k.startswith("_")}
                blocks.append(block)
            assembled = dict(self._anthropic_message)
            assembled["content"] = blocks
            if self.usage:
                usage = dict(assembled.get("usage") or {})
                usage.update(self.usage)
                assembled["usage"] = usage
            return assembled
        return {}

    # ------------------------------------------------------------------ misc

    @staticmethod
    def mappings_from_records(records) -> dict[str, str]:
        return load_records(records)