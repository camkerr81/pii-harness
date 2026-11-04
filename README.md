# pii-harness

A local, zero-trust proxy that sits between your AI agents or tools and an OpenAI-compatible LLM API. It removes personal data, secrets, and infrastructure IPs from everything you send to the model, and puts the real values back into what the model returns.

```text
 agent / tool                 pii-harness (local)                    frontier LLM
 ────────────                 ───────────────────                    ────────────
 "ssh to 10.0.0.5 as   ──►   sanitize: 10.0.0.5 → <<IPV4_01>>   ──►  "ssh to <<IPV4_01>> as
  ops@example.com"            ops@example.com → <<EMAIL_01>>         <<EMAIL_01>>"
                              (stored in local SQLite vault)

 "Connecting to        ◄──   hydrate: <<IPV4_01>> → 10.0.0.5    ◄──  "Connecting to
  10.0.0.5…"                  (streaming-safe, tool-call safe)       <<IPV4_01>>…"
```

The model only ever sees readable placeholders such as `<<IPV4_01>>`, `<<EMAIL_02>>`, or `<<API_KEY_01>>`. It can still reason about them ("the same host as before"), but the plaintext never leaves your machine. Raw hashes are never sent either.

## Features

- **Deterministic semantic tokens.** The same value always maps to the same token within a session, so `admin@example.com` stays `<<EMAIL_01>>` across every message and turn.
- **Full request coverage.** Scrubs system, user, and assistant messages, multi-part text content, the arguments of earlier assistant tool calls, and `role: "tool"` outputs, so local tool stdout never leaks raw data back into the context window. Image parts are passed through untouched.
- **Streaming re-hydration.** A lookahead buffer restores tokens even when the upstream SSE stream splits them across chunks (`"Host is <<IP"`, `"V4_0"`, `"1>>."`). Text that only looks like a token (`x < 10`, `a << b`, `<<EOF`, `<div>`) passes through unchanged.
- **Tool-call safety.** Tool-call arguments are hydrated as JSON, so plaintext containing quotes, backslashes, or newlines always produces valid, parseable arguments, both streamed and non-streamed.
- **Session isolation.** Tokens are numbered per session and only resolve within the session that created them.
- **Persistent vault.** SQLite in WAL mode with HMAC-SHA256 lookup keys, stored on a mounted volume.
- **Offline mock mode.** A built-in fake upstream for trying the proxy without an API key.

### What gets detected

| Token type | Examples |
| --- | --- |
| `EMAIL` | `jane.doe@corp.example`, `ops+alerts@mail.example.com` |
| `IPV4` | `10.0.0.5`, `192.168.1.254` (octets are validated, so `999.1.1.1` is ignored) |
| `API_KEY` | `sk-…` (OpenAI style, incl. `sk-proj-…`), `ghp_…` (GitHub), `xoxb-…` / `xoxp-…` (Slack) |
| `PHONE` | `+61 412 345 678`, `0412 345 678`, `(02) 9876 5432`, `03-9876-5432`, `1300 123 456`, `+44 20 7946 0958`, `(415) 555-0132` |

Unstructured entities such as names can be added with a local NER model; see [Adding an NER model](#adding-an-ner-model).

## Quick start (Docker Compose)

```bash
git clone https://github.com/camkerr81/pii-harness.git
cd pii-harness
cp .env.example .env            # then edit .env
mkdir -p data && sudo chown 1000:1000 data
docker compose up -d --build
curl http://localhost:8000/health
# {"status":"ok","db_path":"/data/vault.db"}
```

The container runs as a non-root user with UID 1000, so the `./data` folder must be writable by that UID. On Unraid, appdata shares are usually owned by `99:100`; `chown` the folder before first start.

To try it without an API key, start it in mock mode:

```bash
MOCK_UPSTREAM=true docker compose up -d --build
```

## Configuration

Set these in `.env` (read by Docker Compose) or as environment variables.

| Variable | Default | Description |
| --- | --- | --- |
| `UPSTREAM_BASE_URL` | `https://api.openai.com/v1` | OpenAI-compatible base URL. Requests go to `{UPSTREAM_BASE_URL}/chat/completions`. |
| `UPSTREAM_API_KEY` | _(empty)_ | If set, the proxy uses this key upstream. If empty, it forwards each client's own `Authorization: Bearer …` header. |
| `VAULT_HMAC_SECRET` | `change-me-in-prod-hmac-key` | Secret for the HMAC-SHA256 vault keys. **Change it.** The proxy logs a warning while the default is in use. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. |
| `DB_PATH` | `/data/vault.db` | SQLite vault location. Use `:memory:` for a throwaway vault. |
| `MOCK_UPSTREAM` | `false` | `true` answers from the built-in offline mock instead of calling upstream. |
| `UPSTREAM_TIMEOUT_SECONDS` | `600` | Read timeout for upstream requests. |

Changing `VAULT_HMAC_SECRET` on an existing vault does not break anything, but values seen again afterwards get new token numbers.

## Usage

Point any OpenAI-compatible client at the proxy instead of the real API.

### OpenAI Python SDK

```python
from openai import OpenAI

client = OpenAI(
    base_url="http://localhost:8000/v1",
    api_key="sk-your-real-key",                   # forwarded upstream unless UPSTREAM_API_KEY is set
    default_headers={"X-Session-ID": "infra-agent"},
)

stream = client.chat.completions.create(
    model="gpt-4o",
    stream=True,
    messages=[{"role": "user", "content": "Why can't I reach 10.0.0.5 from 10.0.0.9?"}],
)
for chunk in stream:
    print(chunk.choices[0].delta.content or "", end="")
```

The model receives `Why can't I reach <<IPV4_01>> from <<IPV4_02>>?`; you receive its answer with the real addresses restored.

### curl

```bash
curl http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "X-Session-ID: demo" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4o", "messages": [{"role": "user", "content": "Email ops@example.com about 10.0.0.5"}]}'
```

### Sessions

The `X-Session-ID` request header selects the vault session. Use one ID per conversation or agent so token numbering stays stable across turns.

If the header is missing, the proxy derives a session ID from a hash of the first system, developer, or user message (`auto-<16 hex chars>`), so repeated requests for the same conversation land in the same session. If there are no messages it uses `default_session`. Every response includes the session it used in an `X-Session-ID` header.

### Tool calls

The proxy does not run tools itself. Your client does, as usual:

1. The model returns a tool call such as `{"host": "<<IPV4_01>>"}`. The proxy hydrates it, so your client receives `{"host": "10.0.0.5"}` and runs the tool against the real host.
2. Your client sends the tool output back as a `role: "tool"` message. The proxy tokenises it before it reaches the model.

## API

| Endpoint | Description |
| --- | --- |
| `POST /v1/chat/completions` | OpenAI-compatible chat completions, with `stream: true` (SSE) or `stream: false`. Upstream error responses are passed through with their original status code. |
| `GET /v1/vault/{session_id}` | Tokens stored for a session, with entity type and creation time. Plaintext is deliberately not returned. |
| `GET /health` | `{"status": "ok", "db_path": "…"}`. Used by the container `HEALTHCHECK`. |

Only `Content-Type` and `Authorization` are forwarded upstream; other client headers are dropped.

## Adding an NER model

Regexes catch structured data. For names, organisations, and addresses, plug in a local model such as [GLiNER](https://github.com/urchade/GLiNER) or [Presidio](https://github.com/microsoft/presidio). Any callable that takes text and returns `(entity_type, value)` pairs works:

```python
from src.sanitizer import Sanitizer

def my_ner(text: str) -> list[tuple[str, str]]:
    # e.g. run GLiNER/Presidio here
    return [("PERSON", "Jane Doe")] if "Jane Doe" in text else []

sanitizer = Sanitizer(vault, ner=my_ner)   # "Jane Doe" → <<PERSON_01>>
```

The default hook, `extract_unstructured_entities`, returns nothing. To enable a model in the running app, pass it where `Sanitizer(vault)` is created in `src/main.py`.

## How it works

| Module | Role |
| --- | --- |
| `src/vault.py` | `PIIVault`: SQLite store keyed by `(session_id, HMAC-SHA256(plaintext))`. `get_or_create_token` returns the existing token or allocates the next `<<TYPE_NN>>` for that session and type; `resolve_token` maps back, returning unknown tokens unchanged. |
| `src/sanitizer.py` | Regex detectors plus the NER hook. Overlapping matches are resolved earliest-first, then longest. Walks every text-bearing field of the request messages. |
| `src/hydrator.py` | `StreamHydrator`: a lookahead buffer (tokens up to 32 characters) that holds back a possible partial token until it can be resolved or ruled out. `ChatStreamHydrator` keeps one buffer per choice and per tool call and flushes on `finish_reason`. |
| `src/tool_interceptor.py` | JSON-aware tokenising and hydration of `tool_calls[].function.arguments`. |
| `src/main.py` | FastAPI app, upstream forwarding with `httpx`, and the mock upstream. |

## Security notes and limitations

- **The vault holds plaintext.** HMAC is used for lookups, not encryption, so `data/vault.db` contains every value it has seen. Protect it like a secret store, and don't commit or share it.
- **Port 8000 has no authentication.** Anyone who can reach it can send requests through your upstream key (if `UPSTREAM_API_KEY` is set) and list token metadata. Keep it on localhost or a trusted network.
- **Detection is pattern-based.** Values that don't match a detector (names, addresses, unusual key formats) pass through unless you add an NER model. Treat the proxy as a strong safety net, not a guarantee.
- **Only message text is scanned.** Image inputs, tool definitions, and other request fields are forwarded as-is.
- **Only `/v1/chat/completions` is proxied.** Embeddings, the Responses API, and other endpoints are not supported.
- **Vault entries are never deleted.** The database grows with each new value; delete the file to reset all sessions.

## Development

Requires Python 3.12+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest -v
```

Run locally without Docker:

```bash
DB_PATH=./data/vault.db MOCK_UPSTREAM=true uvicorn src.main:app --reload
```

The test suite covers deterministic token reuse, tokens split across arbitrary chunk boundaries (fixed, random, and exhaustive splits), JSON safety of hydrated tool arguments, and an end-to-end check that the upstream request contains none of the original sensitive values.
