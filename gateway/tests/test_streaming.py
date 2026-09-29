from __future__ import annotations

import json

from lono_gateway.pipeline.streaming import StreamTranslator
from lono_gateway.rehydrator import StreamingRehydrator

WINDOWS_PATH = r"C:\Users\youruser\.config\opencode\opencode.json"


def _sse(payload: dict) -> bytes:
    return f"data: {json.dumps(payload)}\n\n".encode()


def _emitted_tool_arguments(frames: list[bytes], tool_index: int = 0) -> str:
    args = ""
    for block in frames:
        for line in block.decode().splitlines():
            if not line.startswith("data:"):
                continue
            data = line[5:].strip()
            if data == "[DONE]":
                continue
            payload = json.loads(data)
            for choice in payload.get("choices") or []:
                delta = choice.get("delta") or {}
                for tool_call in delta.get("tool_calls") or []:
                    if tool_call.get("index", 0) != tool_index:
                        continue
                    args += (tool_call.get("function") or {}).get("arguments", "")
    return args


def test_streaming_tool_arguments_stay_valid_json() -> None:
    # The rehydrated original contains backslashes; inserting it raw would make
    # the client's inner JSON invalid ("bad escaped character").
    translator = StreamTranslator("openai.chat", {"Vera": WINDOWS_PATH})

    frames = translator.feed(
        _sse(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": 0,
                                    "id": "call_1",
                                    "type": "function",
                                    "function": {"name": "read", "arguments": '{"path":"Ve'},
                                }
                            ]
                        },
                    }
                ]
            }
        )
    )
    frames += translator.feed(
        _sse(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {
                            "tool_calls": [{"index": 0, "function": {"arguments": 'ra"}'}}]
                        },
                    }
                ]
            }
        )
    )
    frames += translator.feed(b"data: [DONE]\n\n")
    extra, outcome = translator.flush()
    if extra:
        frames.append(extra)

    streamed_args = _emitted_tool_arguments(frames)
    assert json.loads(streamed_args) == {"path": WINDOWS_PATH}

    assembled_args = outcome.assembled["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
    assert json.loads(assembled_args) == {"path": WINDOWS_PATH}


def test_streaming_anthropic_input_json_stays_valid() -> None:
    translator = StreamTranslator("anthropic.messages", {"Vera": WINDOWS_PATH})

    def event(name: str, payload: dict) -> bytes:
        return f"event: {name}\ndata: {json.dumps(payload)}\n\n".encode()

    frames = translator.feed(
        event(
            "content_block_start",
            {
                "type": "content_block_start",
                "index": 0,
                "content_block": {"type": "tool_use", "id": "t1", "name": "read"},
            },
        )
    )
    frames += translator.feed(
        event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": '{"path":"Ve'},
            },
        )
    )
    frames += translator.feed(
        event(
            "content_block_delta",
            {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "input_json_delta", "partial_json": 'ra"}'},
            },
        )
    )
    frames += translator.feed(event("content_block_stop", {"type": "content_block_stop", "index": 0}))
    extra, outcome = translator.flush()

    block = outcome.assembled["content"][0]
    assert block["input"] == {"path": WINDOWS_PATH}


def test_streaming_rehydrator_json_escape() -> None:
    stream = StreamingRehydrator({"Vera": WINDOWS_PATH}, json_escape=True)
    assert stream.feed('"Ve') == '"'
    assert stream.feed('ra"') == 'C:\\\\Users\\\\youruser\\\\.config\\\\opencode\\\\opencode.json"'
    assert stream.flush() == ""