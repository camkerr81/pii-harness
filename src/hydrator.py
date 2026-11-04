"""Ingress re-hydration of semantic tokens in streamed (SSE) OpenAI and Gemini responses."""

import json
import re
from collections.abc import AsyncIterator
from typing import Any

from .tool_interceptor import map_json_strings
from .vault import PIIVault

TOKEN_EXACT_RE = re.compile(r"^<<[A-Z0-9_]+_\d{2,}>>$")
# A buffer that could still grow into a token: "<<" followed only by token characters and at most one ">".
_TOKEN_PREFIX_RE = re.compile(r"^<<[A-Z0-9_]*>?$")
MAX_TOKEN_LEN = 32


class StreamHydrator:
    """Lookahead buffer that re-hydrates tokens split across arbitrary chunk boundaries.

    Output is lossless: every character that is not part of a known token is emitted unchanged.
    With ``json_escape=True`` resolved plaintext is escaped for insertion inside a JSON string
    literal (used for streamed ``tool_calls[].function.arguments``).
    """

    def __init__(self, vault: PIIVault, session_id: str, json_escape: bool = False):
        self.vault = vault
        self.session_id = session_id
        self.json_escape = json_escape
        self.buffer = ""

    def _resolve(self, token: str) -> str:
        value = self.vault.resolve_token(self.session_id, token)
        if self.json_escape and value != token:
            value = json.dumps(value, ensure_ascii=False)[1:-1]
        return value

    def process_chunk(self, chunk: str) -> str:
        self.buffer += chunk
        out: list[str] = []
        while self.buffer:
            idx = self.buffer.find("<")
            if idx == -1:
                out.append(self.buffer)
                self.buffer = ""
                break
            if idx > 0:
                out.append(self.buffer[:idx])
                self.buffer = self.buffer[idx:]
                continue
            if len(self.buffer) == 1:
                break  # lone "<" at a chunk boundary
            if not self.buffer.startswith("<<"):
                out.append(self.buffer[0])
                self.buffer = self.buffer[1:]
                continue
            end_idx = self.buffer.find(">>", 2)
            if end_idx != -1:
                candidate = self.buffer[: end_idx + 2]
                if TOKEN_EXACT_RE.match(candidate):
                    out.append(self._resolve(candidate))
                    self.buffer = self.buffer[end_idx + 2 :]
                else:
                    # Release one "<" and rescan, so a real token inside the candidate
                    # (e.g. "<<<IPV4_01>>" or "a << b <<IPV4_01>>") is still hydrated.
                    out.append("<")
                    self.buffer = self.buffer[1:]
                continue
            if len(self.buffer) > MAX_TOKEN_LEN or not _TOKEN_PREFIX_RE.match(self.buffer):
                # Cannot become a token: release one "<" instead of buffering until MAX_TOKEN_LEN.
                out.append("<")
                self.buffer = self.buffer[1:]
                continue
            break  # possible token prefix such as "<<IPV4_0": wait for more data
        return "".join(out)

    def flush(self) -> str:
        """Emit whatever is still buffered when the stream ends."""
        rest, self.buffer = self.buffer, ""
        return rest


class ChatStreamHydrator:
    """Hydrates ``chat.completion.chunk`` events, keeping one ``StreamHydrator`` per choice
    for ``delta.content`` and one per (choice, tool call) for ``function.arguments``."""

    def __init__(self, vault: PIIVault, session_id: str):
        self.vault = vault
        self.session_id = session_id
        self._content: dict[int, StreamHydrator] = {}
        self._args: dict[tuple[int, int], StreamHydrator] = {}
        self._envelope: dict[str, Any] = {"object": "chat.completion.chunk"}

    def process_event(self, event: dict[str, Any]) -> dict[str, Any]:
        self._envelope.update({k: event[k] for k in ("id", "object", "created", "model") if k in event})
        for choice in event.get("choices") or []:
            index = choice.get("index", 0)
            delta = choice.get("delta")
            if not isinstance(delta, dict):
                continue
            if isinstance(delta.get("content"), str):
                hydrator = self._content.setdefault(index, StreamHydrator(self.vault, self.session_id))
                delta["content"] = hydrator.process_chunk(delta["content"])
            for call in delta.get("tool_calls") or []:
                function = call.get("function") or {}
                if isinstance(function.get("arguments"), str):
                    key = (index, call.get("index", 0))
                    hydrator = self._args.setdefault(key, StreamHydrator(self.vault, self.session_id, json_escape=True))
                    function["arguments"] = hydrator.process_chunk(function["arguments"])
            if choice.get("finish_reason"):
                self._flush_choice(index, delta)
        return event

    def _flush_choice(self, index: int, delta: dict[str, Any]) -> None:
        hydrator = self._content.pop(index, None)
        rest = hydrator.flush() if hydrator else ""
        if rest:
            delta["content"] = (delta.get("content") or "") + rest
        for key in sorted(k for k in self._args if k[0] == index):
            rest = self._args.pop(key).flush()
            if not rest:
                continue
            calls = delta.setdefault("tool_calls", [])
            call = next((c for c in calls if c.get("index", 0) == key[1]), None)
            if call is None:
                calls.append({"index": key[1], "function": {"arguments": rest}})
            else:
                function = call.setdefault("function", {})
                function["arguments"] = (function.get("arguments") or "") + rest

    def finish(self) -> dict[str, Any] | None:
        """A final event carrying text still buffered for choices that never sent a finish_reason."""
        choices = []
        for index in sorted({*self._content, *(k[0] for k in self._args)}):
            delta: dict[str, Any] = {}
            self._flush_choice(index, delta)
            if delta:
                choices.append({"index": index, "delta": delta, "finish_reason": None})
        return {**self._envelope, "choices": choices} if choices else None


class GeminiStreamHydrator:
    """Hydrates streamed Gemini ``GenerateContentResponse`` events.

    Text is streamed through one ``StreamHydrator`` per (candidate, thought/answer). ``functionCall``
    parts arrive whole, so their ``args`` are hydrated directly. Text still buffered when a different
    kind of part arrives is flushed in front of it, so part order is preserved.
    """

    def __init__(self, vault: PIIVault, session_id: str):
        self.vault = vault
        self.session_id = session_id
        self._text: dict[tuple[int, bool], StreamHydrator] = {}
        self._enveloped = False  # Code Assist wraps each event as {"response": {...}}

    def _flush(self, index: int, keep: tuple[int, bool] | None = None) -> list[dict[str, Any]]:
        parts = []
        for key in [k for k in self._text if k[0] == index and k != keep]:
            if rest := self._text.pop(key).flush():
                parts.append({"text": rest, "thought": True} if key[1] else {"text": rest})
        return parts

    def process_event(self, event: dict[str, Any]) -> dict[str, Any]:
        self._enveloped = isinstance(event.get("response"), dict)
        for candidate in (event["response"] if self._enveloped else event).get("candidates") or []:
            index = candidate.get("index", 0)
            content = candidate.get("content")
            if isinstance(content, dict) and isinstance(content.get("parts"), list):
                parts: list[Any] = []
                for part in content["parts"]:
                    if isinstance(part, dict) and isinstance(part.get("text"), str):
                        key = (index, bool(part.get("thought")))
                        parts.extend(self._flush(index, keep=key))
                        hydrator = self._text.setdefault(key, StreamHydrator(self.vault, self.session_id))
                        part["text"] = hydrator.process_chunk(part["text"])
                    else:
                        parts.extend(self._flush(index))
                        call = (part.get("functionCall") or part.get("function_call")) if isinstance(part, dict) else None
                        if isinstance(call, dict) and "args" in call:
                            call["args"] = map_json_strings(call["args"], lambda s: self.vault.hydrate_text(self.session_id, s))
                    parts.append(part)
                content["parts"] = parts
            if candidate.get("finishReason") and (rest := self._flush(index)):
                if not isinstance(content, dict):
                    content = candidate["content"] = {"role": "model"}
                content["parts"] = (content.get("parts") or []) + rest
        return event

    def finish(self) -> dict[str, Any] | None:
        """A final event carrying text still buffered for candidates that never sent a finishReason."""
        candidates = []
        for index in sorted({k[0] for k in self._text}):
            if parts := self._flush(index):
                candidates.append({"index": index, "content": {"role": "model", "parts": parts}})
        if not candidates:
            return None
        return {"response": {"candidates": candidates}} if self._enveloped else {"candidates": candidates}


def _sse(data: str) -> bytes:
    return f"data: {data}\n\n".encode()


async def hydrate_sse_stream(
    lines: AsyncIterator[str], hydrator: ChatStreamHydrator | GeminiStreamHydrator
) -> AsyncIterator[bytes]:
    """Re-emit an upstream SSE stream (as text lines) with every ``data:`` event hydrated."""
    finished = False
    async for line in lines:
        if not line.startswith("data:"):
            if line:
                yield f"{line}\n".encode()  # comments / "event:" fields pass through
            continue
        data = line[5:].strip()
        if data == "[DONE]":
            if (tail := hydrator.finish()) is not None:
                yield _sse(json.dumps(tail, ensure_ascii=False))
            finished = True
            yield _sse("[DONE]")
            continue
        try:
            event = json.loads(data)
        except ValueError:
            event = None
        if not isinstance(event, dict):
            yield _sse(data)
            continue
        yield _sse(json.dumps(hydrator.process_event(event), ensure_ascii=False))
    if not finished and (tail := hydrator.finish()) is not None:
        yield _sse(json.dumps(tail, ensure_ascii=False))
