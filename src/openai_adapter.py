"""OpenAI-compatible ``/v1/chat/completions`` support."""

import json
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

from .tool_interceptor import hydrate_tool_calls
from .vault import TOKEN_RE, PIIVault


def session_seed(payload: dict[str, Any]) -> Any:
    for message in payload.get("messages") or []:
        if isinstance(message, dict) and message.get("role") in ("system", "developer", "user"):
            return message.get("content")
    return None


def hydrate_completion(vault: PIIVault, session_id: str, completion: Any) -> Any:
    if not isinstance(completion, dict):
        return completion
    for choice in completion.get("choices") or []:
        message = choice.get("message") or {}
        if isinstance(message.get("content"), str):
            message["content"] = vault.hydrate_text(session_id, message["content"])
        if message.get("tool_calls"):
            message["tool_calls"] = hydrate_tool_calls(session_id, message["tool_calls"], vault)
    return completion


# --- Offline mock upstream (MOCK_UPSTREAM=true) ------------------------------------------------

_MOCK_CHUNK_SIZES = (3, 1, 4, 2, 5)  # irregular, so tokens are split across chunk boundaries


def mock_split(text: str) -> list[str]:
    chunks, pos, i = [], 0, 0
    while pos < len(text):
        size = _MOCK_CHUNK_SIZES[i % len(_MOCK_CHUNK_SIZES)]
        chunks.append(text[pos : pos + size])
        pos, i = pos + size, i + 1
    return chunks


def mock_text(tokens: list[str]) -> str:
    if tokens:
        return "[mock upstream] I only ever saw these placeholders: " + ", ".join(tokens) + "."
    return "[mock upstream] No sensitive entities were present in your request."


def _mock_reply(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Echo back every token the (sanitized) request contained, plus a tool call if tools were offered."""
    tokens = list(dict.fromkeys(TOKEN_RE.findall(json.dumps(payload.get("messages") or []))))
    tool_call = None
    tools = payload.get("tools") or []
    if tools:
        name = (tools[0].get("function") or {}).get("name", "tool")
        tool_call = {
            "id": "call_mock_1",
            "type": "function",
            "function": {"name": name, "arguments": json.dumps({"entities": tokens})},
        }
    return mock_text(tokens), tool_call


def mock_completion(payload: dict[str, Any]) -> dict[str, Any]:
    text, tool_call = _mock_reply(payload)
    message: dict[str, Any] = {"role": "assistant", "content": text}
    if tool_call:
        message["tool_calls"] = [tool_call]
    return {
        "id": f"chatcmpl-mock-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": payload.get("model", "mock"),
        "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls" if tool_call else "stop"}],
    }


async def mock_stream_lines(payload: dict[str, Any]) -> AsyncIterator[str]:
    text, tool_call = _mock_reply(payload)
    envelope = {
        "id": f"chatcmpl-mock-{uuid.uuid4().hex[:12]}",
        "object": "chat.completion.chunk",
        "created": int(time.time()),
        "model": payload.get("model", "mock"),
    }

    def event(delta: dict[str, Any], finish_reason: str | None = None) -> str:
        return "data: " + json.dumps({**envelope, "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}]})

    yield event({"role": "assistant", "content": ""})
    yield ""
    for piece in mock_split(text):
        yield event({"content": piece})
        yield ""
    if tool_call:
        head = {"index": 0, "id": tool_call["id"], "type": "function", "function": {"name": tool_call["function"]["name"], "arguments": ""}}
        yield event({"tool_calls": [head]})
        yield ""
        for piece in mock_split(tool_call["function"]["arguments"]):
            yield event({"tool_calls": [{"index": 0, "function": {"arguments": piece}}]})
            yield ""
    yield event({}, "tool_calls" if tool_call else "stop")
    yield ""
    yield "data: [DONE]"
    yield ""
