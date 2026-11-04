"""Native Gemini API (``/v1beta/models/{model}:generateContent``) support, as used by the ``agy`` CLI
when ``GOOGLE_GEMINI_BASE_URL`` points at pii-harness."""

import copy
import json
from collections.abc import AsyncIterator
from typing import Any

from fastapi import Request

from .hydrator import GeminiStreamHydrator
from .openai_adapter import mock_split, mock_text
from .sanitizer import Sanitizer
from .vault import TOKEN_RE, PIIVault

METHODS = {"generateContent", "streamGenerateContent", "countTokens"}
API_VERSIONS = {"v1", "v1beta", "v1alpha"}
# Forwarded untouched, so whatever credential the client presents is what Google sees.
FORWARD_HEADERS = ("authorization", "x-goog-api-key", "x-goog-user-project", "x-goog-api-client")

# The REST API accepts both proto field spellings.
_FUNCTION_CALL = ("functionCall", "function_call")
_FUNCTION_RESPONSE = ("functionResponse", "function_response")


def forward_headers(request: Request) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    for name in FORWARD_HEADERS:
        if value := request.headers.get(name):
            headers[name] = value
    return headers


def session_seed(payload: dict[str, Any]) -> Any:
    system = payload.get("systemInstruction") or payload.get("system_instruction")
    if system:
        return system
    contents = payload.get("contents") or []
    return contents[0] if contents else None


def _sanitize_content(sanitizer: Sanitizer, session_id: str, content: Any) -> Any:
    if not isinstance(content, dict) or not isinstance(content.get("parts"), list):
        return content
    content = copy.deepcopy(content)
    for part in content["parts"]:
        if not isinstance(part, dict):
            continue
        if isinstance(part.get("text"), str):
            part["text"] = sanitizer.sanitize_text(session_id, part["text"])
        # Earlier model tool calls and local tool output (read_file, run_command, ...).
        for key, field in [(k, "args") for k in _FUNCTION_CALL] + [(k, "response") for k in _FUNCTION_RESPONSE]:
            if isinstance(part.get(key), dict) and field in part[key]:
                part[key][field] = sanitizer.sanitize_json_value(session_id, part[key][field])
    return content


def sanitize_request(sanitizer: Sanitizer, session_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    sanitized = dict(payload)
    for key in ("systemInstruction", "system_instruction"):
        if key in payload:
            sanitized[key] = _sanitize_content(sanitizer, session_id, payload[key])
    if isinstance(payload.get("contents"), list):
        sanitized["contents"] = [_sanitize_content(sanitizer, session_id, c) for c in payload["contents"]]
    for key in ("generateContentRequest", "generate_content_request"):  # countTokens
        if isinstance(payload.get(key), dict):
            sanitized[key] = sanitize_request(sanitizer, session_id, payload[key])
    return sanitized


def hydrate_response(vault: PIIVault, session_id: str, body: Any) -> Any:
    """Hydrate a ``generateContent`` response, or the JSON array a non-SSE ``streamGenerateContent`` returns."""
    hydrator = GeminiStreamHydrator(vault, session_id)
    events = [hydrator.process_event(e) if isinstance(e, dict) else e for e in (body if isinstance(body, list) else [body])]
    tail = hydrator.finish()
    if isinstance(body, list):
        return events + [tail] if tail else events
    for leftover in (tail or {}).get("candidates", []):  # a candidate without finishReason
        candidate = next(c for c in body["candidates"] if c.get("index", 0) == leftover["index"])
        candidate["content"]["parts"] += leftover["content"]["parts"]
    return body


# --- Offline mock upstream (MOCK_UPSTREAM=true) ------------------------------------------------
# Text only: agy validates tool arguments against its own schemas, so a made-up functionCall would fail.


def _mock_text(payload: dict[str, Any]) -> str:
    seen = json.dumps([payload.get("systemInstruction"), payload.get("system_instruction"), payload.get("contents")])
    return mock_text(list(dict.fromkeys(TOKEN_RE.findall(seen))))


def _mock_event(text: str, finish: bool) -> dict[str, Any]:
    candidate: dict[str, Any] = {"content": {"role": "model", "parts": [{"text": text}]}, "index": 0}
    if finish:
        candidate["finishReason"] = "STOP"
    return {"candidates": [candidate], "modelVersion": "mock"}


def mock_response(method: str, payload: dict[str, Any]) -> Any:
    if method == "countTokens":
        return {"totalTokens": len(json.dumps(payload)) // 4}
    if method == "streamGenerateContent":
        pieces = mock_split(_mock_text(payload))
        return [_mock_event(p, i == len(pieces) - 1) for i, p in enumerate(pieces)]
    return _mock_event(_mock_text(payload), True)


async def mock_stream_lines(payload: dict[str, Any]) -> AsyncIterator[str]:
    for event in mock_response("streamGenerateContent", payload):
        yield "data: " + json.dumps(event)
        yield ""
