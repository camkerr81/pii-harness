import hashlib
import json
import logging
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from . import gemini_adapter, openai_adapter
from .config import DEFAULT_HMAC_SECRET, Settings
from .hydrator import ChatStreamHydrator, GeminiStreamHydrator, hydrate_sse_stream
from .ner import build_ner
from .sanitizer import Sanitizer
from .vault import PIIVault

logger = logging.getLogger("pii_harness")


def derive_session_id(request: Request, seed: Any) -> str:
    """``X-Session-ID`` if sent, else a hash of the conversation's first (system) message."""
    if header := request.headers.get("x-session-id"):
        return header
    if seed:
        digest = hashlib.sha256(json.dumps(seed, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        return "auto-" + digest[:16]
    return "default_session"


async def read_json_object(request: Request) -> dict[str, Any] | JSONResponse:
    try:
        payload = await request.json()
    except ValueError:
        return JSONResponse({"error": {"message": "Request body must be JSON."}}, status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse({"error": {"message": "Request body must be a JSON object."}}, status_code=400)
    return payload


class TextRequest(BaseModel):
    session_id: str
    text: str


def create_app(settings: Settings | None = None, http_client: httpx.AsyncClient | None = None) -> FastAPI:
    settings = settings or Settings.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if settings.VAULT_HMAC_SECRET == DEFAULT_HMAC_SECRET:
            logger.warning("VAULT_HMAC_SECRET is the built-in default; set a unique secret in production.")
        ner = build_ner(settings)
        vault = PIIVault(settings.DB_PATH, settings.VAULT_HMAC_SECRET, settings.VAULT_FALLBACK_SESSION)
        client = http_client or httpx.AsyncClient(timeout=httpx.Timeout(settings.UPSTREAM_TIMEOUT_SECONDS, connect=10.0))
        app.state.vault = vault
        app.state.sanitizer = Sanitizer(vault, ner=ner, custom_terms=settings.CUSTOM_REDACT_TERMS.split(","))
        app.state.http_client = client
        try:
            yield
        finally:
            if http_client is None:
                await client.aclose()
            vault.close()

    app = FastAPI(title="pii-harness", lifespan=lifespan)

    async def forward(
        request: Request,
        url: str,
        body: dict[str, Any],
        headers: dict[str, str],
        session_id: str,
        hydrate_body: Callable[[Any], Any],
        stream_hydrator: ChatStreamHydrator | GeminiStreamHydrator | None,
    ) -> Response:
        """Send the sanitized body upstream and hydrate the reply: SSE when ``stream_hydrator`` is
        given, otherwise a whole JSON body. Error responses are passed through as they are."""
        client: httpx.AsyncClient = request.app.state.http_client
        session_header = {"X-Session-ID": session_id}
        try:
            upstream = await client.send(client.build_request("POST", url, json=body, headers=headers), stream=True)
        except httpx.HTTPError as exc:
            return JSONResponse({"error": {"message": f"Upstream request failed: {exc!r}"}}, status_code=502)

        content_type = upstream.headers.get("content-type", "")
        if upstream.status_code >= 400 or stream_hydrator is None:
            raw = await upstream.aread()
            await upstream.aclose()
            if upstream.status_code < 400 and "json" in content_type:
                return JSONResponse(hydrate_body(json.loads(raw)), headers=session_header)
            return Response(raw, status_code=upstream.status_code, media_type=content_type or None, headers=session_header)

        async def relay() -> AsyncIterator[bytes]:
            try:
                async for chunk in hydrate_sse_stream(upstream.aiter_lines(), stream_hydrator):
                    yield chunk
            finally:
                await upstream.aclose()

        return StreamingResponse(
            relay(), media_type="text/event-stream", headers={**session_header, "Cache-Control": "no-cache"}
        )

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok", "db_path": settings.DB_PATH}

    # --- Bridge helpers for wrapper scripts -----------------------------------------------------

    @app.post("/v1/sanitize")
    async def sanitize(body: TextRequest, request: Request) -> dict[str, Any]:
        vault: PIIVault = request.app.state.vault
        before = len(vault.list_tokens(body.session_id))
        text = await run_in_threadpool(request.app.state.sanitizer.sanitize_text, body.session_id, body.text)
        created = len(vault.list_tokens(body.session_id)) - before
        return {"session_id": body.session_id, "sanitized_text": text, "tokens_created": created}

    @app.post("/v1/hydrate")
    async def hydrate(body: TextRequest, request: Request) -> dict[str, Any]:
        text = request.app.state.vault.hydrate_text(body.session_id, body.text)
        return {"session_id": body.session_id, "hydrated_text": text}

    @app.get("/v1/vault/{session_id}")
    async def vault_tokens(session_id: str, request: Request, include_plaintext: bool = False) -> dict[str, Any]:
        tokens = request.app.state.vault.list_tokens(session_id, include_plaintext=include_plaintext)
        return {"session_id": session_id, "count": len(tokens), "tokens": tokens}

    # --- OpenAI-compatible ----------------------------------------------------------------------

    @app.post("/v1/chat/completions")
    async def chat_completions(request: Request) -> Response:
        payload = await read_json_object(request)
        if isinstance(payload, Response):
            return payload
        vault: PIIVault = request.app.state.vault
        session_id = derive_session_id(request, openai_adapter.session_seed(payload))
        # NER is CPU-bound; keep it off the event loop so concurrent streams stay responsive.
        sanitized = await run_in_threadpool(request.app.state.sanitizer.sanitize_payload, session_id, payload)
        stream = bool(payload.get("stream"))

        if settings.MOCK_UPSTREAM:
            if stream:
                body = hydrate_sse_stream(openai_adapter.mock_stream_lines(sanitized), ChatStreamHydrator(vault, session_id))
                return StreamingResponse(body, media_type="text/event-stream", headers={"X-Session-ID": session_id})
            completion = openai_adapter.hydrate_completion(vault, session_id, openai_adapter.mock_completion(sanitized))
            return JSONResponse(completion, headers={"X-Session-ID": session_id})

        headers = {"Content-Type": "application/json"}
        auth = f"Bearer {settings.UPSTREAM_API_KEY}" if settings.UPSTREAM_API_KEY else request.headers.get("authorization")
        if auth:
            headers["Authorization"] = auth
        return await forward(
            request,
            settings.UPSTREAM_OPENAI_URL.rstrip("/") + "/chat/completions",
            sanitized,
            headers,
            session_id,
            lambda completion: openai_adapter.hydrate_completion(vault, session_id, completion),
            ChatStreamHydrator(vault, session_id) if stream else None,
        )

    # --- Native Gemini (agy with GOOGLE_GEMINI_BASE_URL) ----------------------------------------

    @app.post("/{api_version}/models/{model}:{method}")
    async def gemini(api_version: str, model: str, method: str, request: Request) -> Response:
        if api_version not in gemini_adapter.API_VERSIONS or method not in gemini_adapter.METHODS:
            # Refuse rather than pass unknown request shapes upstream unsanitized.
            message = f"pii-harness does not proxy {api_version}/models/*:{method}"
            return JSONResponse({"error": {"code": 404, "message": message, "status": "NOT_FOUND"}}, status_code=404)
        payload = await read_json_object(request)
        if isinstance(payload, Response):
            return payload
        vault: PIIVault = request.app.state.vault
        session_id = derive_session_id(request, gemini_adapter.session_seed(payload))
        sanitized = await run_in_threadpool(gemini_adapter.sanitize_request, request.app.state.sanitizer, session_id, payload)
        sse = method == "streamGenerateContent" and request.query_params.get("alt") == "sse"

        def hydrate_body(body: Any) -> Any:
            return gemini_adapter.hydrate_response(vault, session_id, body)

        if settings.MOCK_UPSTREAM:
            if sse:
                body = hydrate_sse_stream(gemini_adapter.mock_stream_lines(sanitized), GeminiStreamHydrator(vault, session_id))
                return StreamingResponse(body, media_type="text/event-stream", headers={"X-Session-ID": session_id})
            return JSONResponse(hydrate_body(gemini_adapter.mock_response(method, sanitized)), headers={"X-Session-ID": session_id})

        url = f"{settings.UPSTREAM_GEMINI_URL.rstrip('/')}/{api_version}/models/{model}:{method}"
        if request.url.query:
            url += "?" + request.url.query
        return await forward(
            request,
            url,
            sanitized,
            gemini_adapter.forward_headers(request),
            session_id,
            hydrate_body,
            GeminiStreamHydrator(vault, session_id) if sse else None,
        )

    return app


app = create_app()
