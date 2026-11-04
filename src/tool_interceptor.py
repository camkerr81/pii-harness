"""Tool-call boundary: JSON-aware hydration of ``function.arguments`` (LLM -> local tools).

Arguments are parsed and only string values are edited, so plaintext containing quotes,
backslashes, or newlines can never break the JSON structure. The egress direction lives in
``Sanitizer.sanitize_json_arguments``.
"""

import copy
import json
from collections.abc import Callable
from typing import Any

from .vault import TOKEN_RE, PIIVault


def map_json_strings(value: Any, fn: Callable[[str], str]) -> Any:
    """Apply ``fn`` to every string (object keys included) in a decoded JSON value."""
    if isinstance(value, str):
        return fn(value)
    if isinstance(value, list):
        return [map_json_strings(v, fn) for v in value]
    if isinstance(value, dict):
        return {fn(k): map_json_strings(v, fn) for k, v in value.items()}
    return value


def hydrate_json_arguments(session_id: str, raw_json_str: str, vault: PIIVault) -> str:
    try:
        data = json.loads(raw_json_str)
    except ValueError:
        # Not valid JSON (the model produced something malformed): substitute in place, JSON-escaping
        # the plaintext so a string literal around the token stays well formed.
        return TOKEN_RE.sub(
            lambda m: json.dumps(vault.resolve_token(session_id, m.group()), ensure_ascii=False)[1:-1],
            raw_json_str,
        )
    return json.dumps(map_json_strings(data, lambda s: vault.hydrate_text(session_id, s)), ensure_ascii=False)


def hydrate_tool_calls(session_id: str, tool_calls: list[dict], vault: PIIVault) -> list[dict]:
    """Hydrate the arguments of non-streamed ``message.tool_calls`` entries."""
    hydrated = copy.deepcopy(tool_calls)
    for call in hydrated:
        function = call.get("function") or {}
        if isinstance(function.get("arguments"), str):
            function["arguments"] = hydrate_json_arguments(session_id, function["arguments"], vault)
    return hydrated
