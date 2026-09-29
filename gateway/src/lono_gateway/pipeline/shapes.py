"""Request/response walkers for OpenAI- and Anthropic-shaped payloads.

Every string that can reach or come from a provider is routed through the
pipeline. Tool arguments and tool_use inputs are parsed as JSON and their
string leaves are processed individually.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any

from lono_gateway.pipeline.types import TextResult

ProcessText = Callable[..., Awaitable[TextResult]]


async def transform_json_string(value: str, process: ProcessText) -> tuple[str, list[TextResult]]:
    """Process a JSON-encoded string (tool arguments) field by field."""
    stripped = value.strip()
    if stripped[:1] in {"{", "["}:
        try:
            parsed = json.loads(value)
        except (ValueError, TypeError):
            parsed = None
        if parsed is not None:
            results: list[TextResult] = []
            transformed = await _transform_json_value(parsed, process, results)
            return json.dumps(transformed, ensure_ascii=False, separators=(",", ":")), results
    result = await process(value)
    return result.text, [result]


async def _transform_json_value(value: Any, process: ProcessText, results: list[TextResult]) -> Any:
    if isinstance(value, str):
        result = await process(value)
        results.append(result)
        return result.text
    if isinstance(value, list):
        return [await _transform_json_value(item, process, results) for item in value]
    if isinstance(value, dict):
        return {key: await _transform_json_value(item, process, results) for key, item in value.items()}
    return value


# ---------------------------------------------------------------- OpenAI chat


async def process_openai_chat_request(
    payload: dict, process: ProcessText, inspect_tools: bool = True
) -> list[TextResult]:
    results: list[TextResult] = []
    for message in payload.get("messages") or []:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str) and content:
            result = await process(content)
            message["content"] = result.text
            results.append(result)
        elif isinstance(content, list):
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                    result = await process(part["text"])
                    part["text"] = result.text
                    results.append(result)
        for tool_call in message.get("tool_calls") or []:
            if not isinstance(tool_call, dict):
                continue
            function = tool_call.get("function")
            if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                new_value, sub_results = await transform_json_string(function["arguments"], process)
                function["arguments"] = new_value
                results.extend(sub_results)

    if inspect_tools:
        for tool in payload.get("tools") or []:
            function = tool.get("function") if isinstance(tool, dict) else None
            if isinstance(function, dict) and isinstance(function.get("description"), str):
                results.append(await process(function["description"], flag_only=True))
    return results


async def process_openai_chat_response(payload: dict, process: ProcessText) -> list[TextResult]:
    results: list[TextResult] = []
    for choice in payload.get("choices") or []:
        if not isinstance(choice, dict):
            continue
        message = choice.get("message")
        if isinstance(message, dict):
            content = message.get("content")
            if isinstance(content, str) and content:
                result = await process(content)
                message["content"] = result.text
                results.append(result)
            elif isinstance(content, list):
                for part in content:
                    if isinstance(part, dict) and part.get("type") == "text" and isinstance(part.get("text"), str):
                        result = await process(part["text"])
                        part["text"] = result.text
                        results.append(result)
            for tool_call in message.get("tool_calls") or []:
                if not isinstance(tool_call, dict):
                    continue
                function = tool_call.get("function")
                if isinstance(function, dict) and isinstance(function.get("arguments"), str):
                    new_value, sub_results = await transform_json_string(function["arguments"], process)
                    function["arguments"] = new_value
                    results.extend(sub_results)
        if isinstance(choice.get("text"), str) and choice["text"]:
            result = await process(choice["text"])
            choice["text"] = result.text
            results.append(result)
    return results


# ----------------------------------------------------------------- completions


async def process_openai_completions_request(
    payload: dict, process: ProcessText, inspect_tools: bool = True
) -> list[TextResult]:
    results: list[TextResult] = []
    prompt = payload.get("prompt")
    if isinstance(prompt, str) and prompt:
        result = await process(prompt)
        payload["prompt"] = result.text
        results.append(result)
    elif isinstance(prompt, list):
        for index, item in enumerate(prompt):
            if isinstance(item, str) and item:
                result = await process(item)
                prompt[index] = result.text
                results.append(result)
    return results


async def process_openai_completions_response(payload: dict, process: ProcessText) -> list[TextResult]:
    results: list[TextResult] = []
    for choice in payload.get("choices") or []:
        if isinstance(choice, dict) and isinstance(choice.get("text"), str) and choice["text"]:
            result = await process(choice["text"])
            choice["text"] = result.text
            results.append(result)
    return results


# ------------------------------------------------------------- Anthropic API


async def _process_anthropic_blocks(blocks: list, process: ProcessText, results: list[TextResult]) -> None:
    for block in blocks:
        if not isinstance(block, dict):
            continue
        block_type = block.get("type")
        if block_type == "text" and isinstance(block.get("text"), str):
            result = await process(block["text"])
            block["text"] = result.text
            results.append(result)
        elif block_type == "thinking" and isinstance(block.get("thinking"), str):
            result = await process(block["thinking"])
            block["thinking"] = result.text
            results.append(result)
        elif block_type == "tool_use" and isinstance(block.get("input"), (dict, list)):
            block["input"] = await _transform_json_value(block["input"], process, results)
        elif block_type == "tool_result":
            inner = block.get("content")
            if isinstance(inner, str) and inner:
                result = await process(inner)
                block["content"] = result.text
                results.append(result)
            elif isinstance(inner, list):
                await _process_anthropic_blocks(inner, process, results)


async def process_anthropic_request(
    payload: dict, process: ProcessText, inspect_tools: bool = True
) -> list[TextResult]:
    results: list[TextResult] = []
    system = payload.get("system")
    if isinstance(system, str) and system:
        result = await process(system)
        payload["system"] = result.text
        results.append(result)
    elif isinstance(system, list):
        await _process_anthropic_blocks(system, process, results)

    for message in payload.get("messages") or []:
        if not isinstance(message, dict):
            continue
        content = message.get("content")
        if isinstance(content, str) and content:
            result = await process(content)
            message["content"] = result.text
            results.append(result)
        elif isinstance(content, list):
            await _process_anthropic_blocks(content, process, results)

    if inspect_tools:
        for tool in payload.get("tools") or []:
            if isinstance(tool, dict) and isinstance(tool.get("description"), str):
                results.append(await process(tool["description"], flag_only=True))
    return results


async def process_anthropic_response(payload: dict, process: ProcessText) -> list[TextResult]:
    results: list[TextResult] = []
    content = payload.get("content")
    if isinstance(content, list):
        await _process_anthropic_blocks(content, process, results)
    return results


REQUEST_WALKERS: dict[str, Callable[..., Awaitable[list[TextResult]]]] = {
    "openai.chat": process_openai_chat_request,
    "openai.completions": process_openai_completions_request,
    "anthropic.messages": process_anthropic_request,
}

RESPONSE_WALKERS: dict[str, Callable[..., Awaitable[list[TextResult]]]] = {
    "openai.chat": process_openai_chat_response,
    "openai.completions": process_openai_completions_response,
    "anthropic.messages": process_anthropic_response,
}


# ---------------------------------------------------------------------- usage


def extract_usage(shape: str, payload: dict) -> dict[str, Any]:
    """Normalize token accounting across API shapes."""
    if not isinstance(payload, dict):
        return {}
    usage = payload.get("usage")
    if not isinstance(usage, dict):
        return {}
    if shape == "anthropic.messages":
        prompt = usage.get("input_tokens")
        completion = usage.get("output_tokens")
        return {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": (prompt or 0) + (completion or 0) if prompt is not None or completion is not None else None,
            "cache_read_tokens": usage.get("cache_read_input_tokens"),
            "cache_creation_tokens": usage.get("cache_creation_input_tokens"),
            "raw": usage,
        }
    return {
        "prompt_tokens": usage.get("prompt_tokens"),
        "completion_tokens": usage.get("completion_tokens"),
        "total_tokens": usage.get("total_tokens"),
        "cache_read_tokens": (usage.get("prompt_tokens_details") or {}).get("cached_tokens")
        if isinstance(usage.get("prompt_tokens_details"), dict)
        else None,
        "cache_creation_tokens": None,
        "raw": usage,
    }