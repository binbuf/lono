"""Extract tool calls, tool results and shell commands from audited payloads.

The audit store keeps the four raw payload stages; this module derives a flat,
queryable list of tool activity so the console can answer "what did the agent
actually do, and which task did it belong to?".
"""

from __future__ import annotations

import json
from typing import Any

from lono_gateway.settings import ToolsConfig


def _truncate(value: str | None, limit: int) -> str | None:
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return value[:limit] + "…"


def _stringify(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(value)


def _command_from_arguments(tool_name: str, arguments: str | None, cfg: ToolsConfig) -> str | None:
    if not cfg.extract_commands or not arguments:
        return None
    commands = {name.casefold() for name in cfg.command_tools}
    if tool_name.casefold() not in commands:
        return None
    try:
        parsed = json.loads(arguments)
    except (ValueError, TypeError):
        return arguments.strip() or None
    if isinstance(parsed, dict):
        for key in ("command", "cmd", "script", "shell", "input"):
            value = parsed.get(key)
            if isinstance(value, str) and value.strip():
                return value
    return None


def _event(
    *,
    request_id: str | None,
    session_id: str | None,
    project: str | None,
    source: str,
    tool_name: str | None,
    call_id: str | None,
    kind: str,
    command: str | None,
    arguments: str | None,
    preview: str | None,
    cfg: ToolsConfig,
) -> dict[str, Any]:
    limit = cfg.preview_chars
    return {
        "request_id": request_id,
        "session_id": session_id,
        "project": project,
        "source": source,
        "tool_name": tool_name,
        "call_id": call_id,
        "kind": kind,
        "command": _truncate(command, limit),
        "arguments": _truncate(arguments, limit),
        "preview": _truncate(preview, limit),
        "is_command": 1 if command else 0,
    }


def _openai_events(
    payload: dict,
    *,
    source: str,
    envelope: dict[str, Any],
    cfg: ToolsConfig,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    messages = payload.get("messages") if isinstance(payload.get("messages"), list) else []
    if source == "response":
        messages = []
        for choice in payload.get("choices") or []:
            if isinstance(choice, dict) and isinstance(choice.get("message"), dict):
                messages.append(choice["message"])
            elif isinstance(choice, dict) and isinstance(choice.get("delta"), dict):
                messages.append(choice["delta"])
    for message in messages:
        if not isinstance(message, dict):
            continue
        role = message.get("role")
        tool_calls = message.get("tool_calls")
        if not isinstance(tool_calls, list):
            tool_calls = []
        function_call = message.get("function_call")
        if isinstance(function_call, dict):
            tool_calls = [{"id": None, "function": function_call}, *tool_calls]
        for call in tool_calls:
            if not isinstance(call, dict):
                continue
            function = call.get("function") if isinstance(call.get("function"), dict) else {}
            name = function.get("name") or call.get("name")
            arguments = _stringify(function.get("arguments") or call.get("arguments"))
            events.append(
                _event(
                    source=source,
                    tool_name=name,
                    call_id=call.get("id"),
                    kind="call",
                    command=_command_from_arguments(str(name or ""), arguments, cfg),
                    arguments=arguments,
                    preview=None,
                    cfg=cfg,
                    **envelope,
                )
            )
        if role == "tool" or message.get("tool_call_id"):
            events.append(
                _event(
                    source=source,
                    tool_name=message.get("name") or message.get("tool_call_id"),
                    call_id=message.get("tool_call_id"),
                    kind="result",
                    command=None,
                    arguments=None,
                    preview=_stringify(message.get("content")),
                    cfg=cfg,
                    **envelope,
                )
            )
    return events


def _anthropic_events(
    payload: dict,
    *,
    source: str,
    envelope: dict[str, Any],
    cfg: ToolsConfig,
) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    blocks: list[Any] = []
    if source == "response":
        content = payload.get("content")
        if isinstance(content, list):
            blocks = content
    else:
        if isinstance(payload.get("system"), list):
            blocks.extend(payload["system"])
        for message in payload.get("messages") or []:
            if isinstance(message, dict) and isinstance(message.get("content"), list):
                blocks.extend(message["content"])
    for block in blocks:
        if not isinstance(block, dict):
            continue
        if block.get("type") == "tool_use":
            arguments = _stringify(block.get("input"))
            events.append(
                _event(
                    source=source,
                    tool_name=block.get("name"),
                    call_id=block.get("id"),
                    kind="call",
                    command=_command_from_arguments(str(block.get("name") or ""), arguments, cfg),
                    arguments=arguments,
                    preview=None,
                    cfg=cfg,
                    **envelope,
                )
            )
        elif block.get("type") == "tool_result":
            events.append(
                _event(
                    source=source,
                    tool_name=block.get("tool_use_id"),
                    call_id=block.get("tool_use_id"),
                    kind="result",
                    command=None,
                    arguments=None,
                    preview=_stringify(block.get("content")),
                    cfg=cfg,
                    **envelope,
                )
            )
    return events


def extract_tool_events(
    payload: Any,
    *,
    shape: str,
    source: str,
    request_id: str | None,
    session_id: str | None,
    project: str | None,
    cfg: ToolsConfig,
) -> list[dict[str, Any]]:
    """Return flat tool events for one audited payload, or an empty list."""
    if not cfg.enabled or not isinstance(payload, dict):
        return []
    envelope = {
        "request_id": request_id,
        "session_id": session_id,
        "project": project,
    }
    try:
        if shape.startswith("openai"):
            events = _openai_events(payload, source=source, envelope=envelope, cfg=cfg)
        elif shape == "anthropic.messages":
            events = _anthropic_events(payload, source=source, envelope=envelope, cfg=cfg)
        else:
            events = []
    except Exception:  # noqa: BLE001 - extraction must never break a request
        return []
    return events[: cfg.max_events_per_request]


def mcp_event(
    message: Any,
    *,
    server: str,
    direction: str,
    request_id: str | None,
    session_id: str | None,
    project: str | None,
    latency_ms: int | None = None,
    preview_chars: int = 4000,
) -> dict[str, Any]:
    """Build an MCP audit event from a JSON-RPC message.

    Handles both single JSON-RPC objects and batches (JSON-RPC 2.0 arrays).
    """
    if not isinstance(message, dict):
        return {
            "request_id": request_id,
            "session_id": session_id,
            "project": project,
            "server": server,
            "method": None,
            "direction": direction,
            "kind": "raw",
            "params": None,
            "result_preview": _truncate(_stringify(message), preview_chars),
            "is_error": 0,
            "latency_ms": latency_ms,
            "raw": _truncate(_stringify(message), preview_chars),
        }
    method = message.get("method")
    error = message.get("error")
    if error is not None:
        kind = "error"
    elif method is not None:
        kind = "request" if direction == "request" else "notification"
    elif "result" in message:
        kind = "response"
    else:
        kind = "message"
    result = message.get("result")
    params = message.get("params")
    preview_source = error if error is not None else result if result is not None else params
    return {
        "request_id": request_id,
        "session_id": session_id,
        "project": project,
        "server": server,
        "method": method,
        "direction": direction,
        "kind": kind,
        "params": _truncate(_stringify(params), preview_chars),
        "result_preview": _truncate(_stringify(preview_source), preview_chars),
        "is_error": 1 if error is not None else 0,
        "latency_ms": latency_ms,
        "raw": _truncate(_stringify(message), preview_chars),
    }