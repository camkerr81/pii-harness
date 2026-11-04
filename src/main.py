import hashlib
import json
import logging
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.concurrency import run_in_threadpool

from .config import DEFAULT_HMAC_SECRET, Settings
from .hydrator import ChatStreamHydrator, hydrate_sse_stream
from .ner import build_ner
from .sanitizer import Sanitizer
from .tool_interceptor import hydrate_tool_calls
from .vault import TOKEN_RE, PIIVault

logger = logging.getLogger("pii_harness")


def derive_session_id(request: Request, payload: dict[str, Any]) -> str:
    if header := request.headers.get("x-session-id"):
        return header
    for message in payload.get("messages") or []:
        if isinstance(message, dict) and message.get("role") in ("system", "developer", "user"):
            seed = json.dumps(message.get("content"), sort_keys=True, ensure_ascii=False)
            return "auto-" + hashlib.sha256(seed.encode()).hexdigest()[:16]
    return "default_session"


def hydrate_completion(session_id: str, completion: dict[str, Any], vault: PIIVault) -> dict[str, Any]:
    for choice in completion.get("choices") or []:
        message = choice.get("message") or {}
        if isinstance(message.get("content"), str):
            message["content"] = vault.resolve_text(session_id, message["content"])
        if message.get("tool_calls"):
            message["tool_calls"] = hydrate_tool_calls(session_id, message["tool_calls"], vault)
    return completion


# --- Offline mock upstream (MOCK_UPSTREAM=true) ------------------------------------------------

_MOCK_CHUNK_SIZES = (3, 1, 4, 2, 5)  # irregular, so tokens are split across chunk boundaries


def _mock_split(text: str) -> list[str]:
    chunks, pos, i = [], 0, 0
    while pos < len(text):
        size = _MOCK_CHUNK_SIZES[i % len(_MOCK_CHUNK_SIZES)]
        chunks.append(text[pos : pos + size])
        pos, i = pos + size, i + 1
    return chunks


def _mock_reply(payload: dict[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Echo back every token the (sanitized) request contained, plus a tool call if tools were offered."""
    tokens = list(dict.fromkeys(TOKEN_RE.findall(json.dumps(payload.get("messages") or []))))
    if tokens:
        text = "[mock upstream] I only ever saw these placeholders: " + ", ".join(tokens) + "."
    else:
        text = "[mock upstream] No sensitive entities were present in your request."
    tool_call = None
    tools = payload.get("tools") or []
    if tools:
        name = (tools[0].get("function") or {}).get("name", "tool")
        tool_call = {
            "id": "call_mock_1",
            "type": "function",
            "function": {"name": name, "arguments": json.dumps({"entities": tokens})},
        }
    return text, tool_call


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
    for piece in _mock_split(text):
        yield event({"content": piece})
        yield ""
    if tool_call:
        head = {"index": 0, "id": tool_call["id"], "type": "function", "function": {"name": tool_call["function"]["name"], "arguments": ""}}
        yield event({"tool_calls": [head]})
        yield ""
        for piece in _mock_split(tool_call["function"]["arguments"]):
            yield event({"tool_calls": [{"index": 0, "function": {"arguments": piece}}]})
            yield ""
    yield event({}, "tool_calls" if tool_call else "stop")
    yield ""
    yield "data: [DONE]"
    yield ""


# --- Application -------------------------------------------------------------------------------


def create_app(settings: Settings | None = None, http_client: httpx.AsyncClient | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if settings.VAULT_HMAC_SECRET == DEFAULT_HMAC_SECRET:
            logger.warning("VAULT_HMAC_SECRET is the built-in default; set a unique secret in production.")
        ner = build_ner(settings)
        vault = PIIVault(settings.DB_PATH, settings.VAULT_HMAC_SECRET)
        client = http_client or httpx.AsyncClient(timeout=httpx.Timeout(settings.UPSTREAM_TIMEOUT_SECONDS, connect=10.0))
        app.state.vault = vault
        app.state.sanitizer = Sanitizer(vault, ner=ner)
        app.state.http_client = client
        try:
            yield
        finally:
            if http_client is None:
                await client.aclose()
            vault.close()

    app = FastAPI(title="pii-harness", lifespan=lifespan)

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "db_path": settings.DB_PATH}

    @app.get("/v1/vault/{session_id}")
    async def vault_tokens(session_id: str, request: Request) -> dict[str, Any]:
        return {"session_id": session_id, "tokens": request.app.state.vault.list_tokens(session_id)}

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        try:
            payload = await request.json()
        except ValueError:
            return JSONResponse({"error": {"message": "Request body must be JSON."}}, status_code=400)
        if not isinstance(payload, dict):
            return JSONResponse({"error": {"message": "Request body must be a JSON object."}}, status_code=400)

        vault: PIIVault = request.app.state.vault
        session_id = derive_session_id(request, payload)
        # NER is CPU-bound; keep it off the event loop so concurrent streams stay responsive.
        sanitized = await run_in_threadpool(request.app.state.sanitizer.sanitize_payload, session_id, payload)
        stream = bool(payload.get("stream"))
        session_header = {"X-Session-ID": session_id}
        sse_headers = {**session_header, "Cache-Control": "no-cache"}

        if settings.MOCK_UPSTREAM:
            if stream:
                body = hydrate_sse_stream(mock_stream_lines(sanitized), ChatStreamHydrator(vault, session_id))
                return StreamingResponse(body, media_type="text/event-stream", headers=sse_headers)
            return JSONResponse(hydrate_completion(session_id, mock_completion(sanitized), vault), headers=session_header)

        headers = {"Content-Type": "application/json"}
        auth = f"Bearer {settings.UPSTREAM_API_KEY}" if settings.UPSTREAM_API_KEY else request.headers.get("authorization")
        if auth:
            headers["Authorization"] = auth
        url = settings.UPSTREAM_BASE_URL.rstrip("/") + "/chat/completions"
        client: httpx.AsyncClient = request.app.state.http_client

        try:
            upstream = await client.send(client.build_request("POST", url, json=sanitized, headers=headers), stream=True)
        except httpx.HTTPError as exc:
            return JSONResponse({"error": {"message": f"Upstream request failed: {exc!r}"}}, status_code=502)

        content_type = upstream.headers.get("content-type", "")
        if upstream.status_code >= 400 or not stream:
            raw = await upstream.aread()
            await upstream.aclose()
            if upstream.status_code < 400 and "json" in content_type:
                completion = hydrate_completion(session_id, json.loads(raw), vault)
                return JSONResponse(completion, headers=session_header)
            return Response(raw, status_code=upstream.status_code, media_type=content_type or None, headers=session_header)

        async def relay() -> AsyncIterator[bytes]:
            try:
                async for chunk in hydrate_sse_stream(upstream.aiter_lines(), ChatStreamHydrator(vault, session_id)):
                    yield chunk
            finally:
                await upstream.aclose()

        return StreamingResponse(relay(), media_type="text/event-stream", headers=sse_headers)

    return app


app = create_app()
