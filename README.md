# pii-harness

A local, zero-trust proxy that sits between your AI agents or tools and an LLM API: OpenAI-compatible chat completions, Google's native Gemini API, or the Code Assist backend the Antigravity `agy` CLI uses when signed in with a Google account. It removes personal data (names, schools, emails, phone numbers), credentials, and infrastructure IPs from everything you send to the model, and puts the real values back into what the model returns.

```text
 agent / tool                 pii-harness (local)                    frontier LLM
 ────────────                 ───────────────────                    ────────────
 "ssh to 10.0.0.5 as   ──►   sanitize: 10.0.0.5 → <<IPV4_01>>   ──►  "ssh to <<IPV4_01>> as
  ops@example.com"            ops@example.com → <<EMAIL_01>>         <<EMAIL_01>>"
                              (stored in local SQLite vault)

 "Connecting to        ◄──   hydrate: <<IPV4_01>> → 10.0.0.5    ◄──  "Connecting to
  10.0.0.5…"                  (streaming-safe, tool-call safe)       <<IPV4_01>>…"
```

The model only ever sees readable placeholders such as `<<PERSON_01>>`, `<<SCHOOL_01>>`, `<<IPV4_01>>`, or `<<CREDENTIAL_02>>`. It can still reason about them ("the same host as before"), but the plaintext never leaves your machine. Raw hashes are never sent either.

## Features

- **Deterministic semantic tokens.** The same value always maps to the same token within a session, so `admin@example.com` stays `<<EMAIL_01>>` across every message and turn.
- **Full request coverage.** Scrubs system, user, and assistant messages, multi-part text content, the arguments of earlier assistant tool calls, and `role: "tool"` outputs, so local tool stdout never leaks raw data back into the context window. Image parts are passed through untouched.
- **Streaming re-hydration.** A lookahead buffer restores tokens even when the upstream SSE stream splits them across chunks (`"Host is <<IP"`, `"V4_0"`, `"1>>."`). Text that only looks like a token (`x < 10`, `a << b`, `<<EOF`, `<div>`) passes through unchanged.
- **Tool-call safety.** Tool-call arguments are hydrated as JSON, so plaintext containing quotes, backslashes, or newlines always produces valid, parseable arguments, both streamed and non-streamed.
- **Local NER for names and schools.** A bundled [GLiNER](https://github.com/urchade/GLiNER) model finds people, schools, and any other entity types you configure. It runs on CPU inside the container with the model baked into the image, so no text leaves the machine for detection.
- **Session isolation.** Tokens are numbered per session and only resolve within the session that created them.
- **Persistent vault.** SQLite in WAL mode with HMAC-SHA256 lookup keys, stored on a mounted volume.
- **Native Gemini API and Code Assist.** Serves `/v1beta/models/{model}:generateContent`, `:streamGenerateContent`, and `:countTokens` (`agy` with an API key) and `/v1internal:{method}` (`agy` signed in with a Google account). Tool output (`functionResponse`) is tokenised before it reaches Google, and `functionCall` arguments are hydrated before `agy` runs them.
- **Bridge endpoints.** `POST /v1/sanitize` and `POST /v1/hydrate` let a wrapper script tokenise and restore plain text directly.
- **Custom terms.** `CUSTOM_REDACT_TERMS` redacts your own hostnames, domains, project names, or people as `<<CUSTOM_NN>>`.
- **Offline mock mode.** A built-in fake upstream for trying the proxy without an API key.

### What gets detected

| Token type | Detected by | Examples |
| --- | --- | --- |
| `PERSON` | NER | `Sarah O'Connor`, `Dr. Rajesh Kumar`, `Mrs. Patel` |
| `SCHOOL` | NER | `Northmead Public School`, `James Ruse Agricultural High School`, `University of Sydney` |
| `EMAIL` | regex | `jane.doe@corp.example`, `ops+alerts@mail.example.com` |
| `PHONE` | regex | `+61 412 345 678`, `0412 345 678`, `(02) 9876 5432`, `03-9876-5432`, `1300 123 456`, `+44 20 7946 0958`, `(415) 555-0132` |
| `IPV4` | regex | `10.0.0.5`, `192.168.1.254` (octets are validated, so `999.1.1.1` is ignored; loopback `127.x.x.x` and `0.0.0.0` stay readable so local URLs keep working) |
| `CUSTOM` | `CUSTOM_REDACT_TERMS` | Whatever you list, matched case-insensitively as whole words: `nas01.home.lan`, `corp.example`, `Project Falcon` |
| `API_KEY` | regex | OpenAI/Anthropic `sk-…`, GitHub `ghp_…` / `github_pat_…`, GitLab `glpat-…`, Slack `xoxb-…` / `xapp-…`, AWS `AKIA…`, Google `AIza…`, Stripe `sk_live_…`, Hugging Face `hf_…`, npm `npm_…`, SendGrid `SG.…` |
| `CREDENTIAL` | regex | The value of any secret-named field: `DB_PASSWORD=hunter2`, `"client_secret": "…"`, `aws_secret_access_key = …`, `SECRET_KEY='…'`; passwords in URLs (`postgres://app:pa55word@db/app`); `Authorization: Bearer …` / `Basic …` |
| `JWT` | regex | `eyJhbGciOi….eyJzdWIi….signature` |
| `PRIVATE_KEY` | regex | Whole `-----BEGIN … PRIVATE KEY-----` blocks, including truncated ones |

For credentials only the secret is replaced (`DB_PASSWORD=<<CREDENTIAL_01>>`), so the model still knows what the value is for. Code that merely mentions secrets, such as `def login(password: str)`, `password = getpass()`, or `token = os.environ["TOKEN"]`, is left alone. In tool-call arguments, any string or number under a secret-named JSON key (`password`, `token`, `api_key`, `db.password`, …) is tokenised even if it matches no pattern.

More NER types can be added through `NER_LABELS`; see [Names, schools, and other entities](#names-schools-and-other-entities).

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

The first build downloads CPU-only PyTorch and the GLiNER model, so it takes a few minutes and the image is about 4 GB. Startup takes 10–20 seconds while the model loads. For a small regex-only image (no names or schools), build with `NER_BACKEND=none docker compose up -d --build`.

The container runs as a non-root user with UID 1000, so the `./data` folder must be writable by that UID. On Unraid, appdata shares are usually owned by `99:100`; `chown` the folder before first start.

To try it without an API key, start it in mock mode:

```bash
MOCK_UPSTREAM=true docker compose up -d --build
```

## Configuration

Set these in `.env` (read by Docker Compose) or as environment variables.

| Variable | Default | Description |
| --- | --- | --- |
| `UPSTREAM_OPENAI_URL` | `https://api.openai.com/v1` | OpenAI-compatible base URL. Requests go to `{UPSTREAM_OPENAI_URL}/chat/completions`. The old name `UPSTREAM_BASE_URL` is still read if this is unset. |
| `UPSTREAM_API_KEY` | _(empty)_ | OpenAI route only. If set, the proxy uses this key upstream. If empty, it forwards each client's own `Authorization: Bearer …` header. |
| `UPSTREAM_GEMINI_URL` | `https://generativelanguage.googleapis.com` | Gemini API host. Requests keep their path and query, e.g. `{UPSTREAM_GEMINI_URL}/v1beta/models/gemini-3.1-pro-preview:streamGenerateContent?alt=sse`. |
| `UPSTREAM_CODE_ASSIST_URL` | `https://daily-cloudcode-pa.googleapis.com` | Code Assist backend for `/v1internal:{method}` requests. This is the host `agy` 1.5.0 uses by default; gemini-cli uses `https://cloudcode-pa.googleapis.com`. |
| `CUSTOM_REDACT_TERMS` | _(empty)_ | Comma-separated terms always replaced with `<<CUSTOM_NN>>`. |
| `VAULT_FALLBACK_SESSION` | _(empty)_ | If set (e.g. `global`), tokens a session doesn't know are looked up in this session too. Lets a bridge script create tokens once with `/v1/sanitize` in `global` and have them hydrate everywhere. |
| `VAULT_HMAC_SECRET` | `change-me-in-prod-hmac-key` | Secret for the HMAC-SHA256 vault keys. **Change it.** The proxy logs a warning while the default is in use. Generate one with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. |
| `DB_PATH` | `/data/vault.db` | SQLite vault location. Use `:memory:` for a throwaway vault. |
| `MOCK_UPSTREAM` | `false` | `true` answers from the built-in offline mock instead of calling upstream. |
| `UPSTREAM_TIMEOUT_SECONDS` | `600` | Read timeout for upstream requests. |
| `NER_BACKEND` | `gliner` in Docker, `none` otherwise | `gliner` enables name/school detection; `none` uses regex detectors only. Also a build argument: changing it requires `--build`. |
| `NER_MODEL` | `urchade/gliner_multi_pii-v1` | GLiNER model baked into the image (build argument). `urchade/gliner_small-v2.1` is about twice as fast with slightly lower recall. |
| `NER_LABELS` | `person:PERSON,school:SCHOOL,university:SCHOOL` | Comma-separated `model label:TOKEN_TYPE` pairs. Token types use `A-Z0-9_`, up to 24 characters. |
| `NER_THRESHOLD` | `0.5` | Model confidence cut-off (0–1). Lower catches more but adds false positives. |
| `NER_IGNORE` | _(empty)_ | Comma-separated words never treated as entities, e.g. `Claude,Siri` if the model tags product names as people. |

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

### Antigravity CLI (`agy`)

`agy` can go through the proxy in both of its sign-in modes.

**Signed in with a Google account** (for example Google AI Pro). Set `CLOUD_CODE_URL`; `agy` then sends its Code Assist (`/v1internal:…`) requests to the proxy:

```bash
CLOUD_CODE_URL=http://localhost:8000 agy
```

Generate and token-count calls are scrubbed and hydrated like the Gemini API; their bodies just wrap the Gemini request and response in `{"request": …}` / `{"response": …}`. `recordTrajectoryAnalytics`, which uploads the whole conversation in plaintext, is answered locally and never forwarded. Every other method (`loadCodeAssist`, `fetchAvailableModels`, quota checks, …) is forwarded after a whole-body scrub, which leaves today's ID-only bodies unchanged. Your OAuth `Authorization` header and `User-Agent` are passed through as-is.

Verified with `agy` 1.5.0 on a Google AI Pro account: tool calls ran locally with the real values, and none of the forwarded requests contained them. (`CODE_ASSIST_ENDPOINT` is gemini-cli's variable; `agy` ignores it.) A few connections bypass `CLOUD_CODE_URL` and go straight to Google: `www.googleapis.com` (account info), `aicode.googleapis.com`, and `play.googleapis.com` (telemetry). What `aicode` and the telemetry contain was not inspected; `agy` keeps working when both are blocked.

This mode is not a documented integration. Routing a subscription through a proxy that rewrites requests is close to the third-party-client use that Google has suspended Antigravity accounts for, so weigh that risk for your account.

**With a Gemini API key**, the documented bring-your-own-key mode:

```bash
export GEMINI_API_KEY=AIza...                         # your Gemini API key (forwarded to Google untouched)
export GOOGLE_GEMINI_BASE_URL=http://localhost:8000   # or http://pii-harness:8000 from another container
agy --settings '{"modelProvider":"gemini"}'
```

To make it permanent, put `"modelProvider": "gemini"` in `~/.gemini/antigravity-cli/settings.json` or add a shell alias. Verified with `agy` 1.5.0: the conversation-title request, the main agent requests, and command output sent back as `functionResponse` all reach Google tokenised, while the commands `agy` runs locally use the real values.

`agy` reads `GOOGLE_GEMINI_BASE_URL` only in API-key mode. The Antigravity desktop app and IDE extension cannot be pointed at a custom endpoint.

The Gemini route forwards the client's `Authorization`, `x-goog-api-key`, `x-goog-user-project`, and `x-goog-api-client` headers and the query string (`?alt=sse`, `?key=…`) unchanged; other headers are dropped. It refuses other Gemini methods (`embedContent`, …) with a 404 rather than forwarding them unscrubbed.

### Bridge scripts

```bash
curl -s localhost:8000/v1/sanitize -H 'Content-Type: application/json' \
  -d '{"session_id": "job-42", "text": "ssh root@10.0.0.5"}'
# {"session_id":"job-42","sanitized_text":"ssh root@<<IPV4_01>>","tokens_created":1}

curl -s localhost:8000/v1/hydrate -H 'Content-Type: application/json' \
  -d '{"session_id": "job-42", "text": "Connected to <<IPV4_01>>"}'
# {"session_id":"job-42","hydrated_text":"Connected to 10.0.0.5"}
```

### Sessions

The `X-Session-ID` request header selects the vault session. Use one ID per conversation or agent so token numbering stays stable across turns.

If the header is missing, the proxy derives a session ID from a hash of the first system, developer, or user message, or the Gemini `systemInstruction` (`auto-<16 hex chars>`), so repeated requests for the same conversation land in the same session. If there are no messages it uses `default_session`. Every response includes the session it used in an `X-Session-ID` header.

### Tool calls

The proxy does not run tools itself. Your client does, as usual:

1. The model returns a tool call such as `{"host": "<<IPV4_01>>"}`. The proxy hydrates it, so your client receives `{"host": "10.0.0.5"}` and runs the tool against the real host.
2. Your client sends the tool output back as a `role: "tool"` message. The proxy tokenises it before it reaches the model.

## API

| Endpoint | Description |
| --- | --- |
| `POST /v1/chat/completions` | OpenAI-compatible chat completions, with `stream: true` (SSE) or `stream: false`. Upstream error responses are passed through with their original status code. |
| `POST /{v1,v1beta,v1alpha}/models/{model}:{generateContent,streamGenerateContent,countTokens}` | Native Gemini API, streamed (`?alt=sse` or JSON array) or not. Upstream errors pass through unchanged. |
| `POST /v1internal:{method}` | Code Assist backend (`agy` signed in with a Google account). See [Antigravity CLI](#antigravity-cli-agy). `MOCK_UPSTREAM` does not emulate it. |
| `POST /v1/sanitize` | `{"session_id", "text"}` → `{"session_id", "sanitized_text", "tokens_created"}`. |
| `POST /v1/hydrate` | `{"session_id", "text"}` → `{"session_id", "hydrated_text"}`. |
| `GET /v1/vault/{session_id}` | `{"session_id", "count", "tokens"}` with each token's entity type and creation time. Plaintext is included only with `?include_plaintext=true`. |
| `GET /health` | `{"status": "ok", "db_path": "…"}`. Used by the container `HEALTHCHECK`. |

The OpenAI route forwards only `Content-Type` and `Authorization`; the Gemini route's forwarded headers are listed under [Antigravity CLI](#antigravity-cli-agy). Other client headers are dropped.

## Names, schools, and other entities

Names and organisations have no fixed format, so they are found by a local [GLiNER](https://github.com/urchade/GLiNER) model, a small zero-shot NER model that takes plain-English labels. The defaults look for `person`, `school`, and `university`. Add more types by extending `NER_LABELS`, for example:

```bash
NER_LABELS=person:PERSON,school:SCHOOL,university:SCHOOL,street address:ADDRESS,organization:ORG
```

How it behaves:

- **Every occurrence is replaced.** Once the model finds `Jane Doe` in a message, every whole-word `Jane Doe` in that text becomes `<<PERSON_01>>` (but `Janet` is untouched).
- **Long texts are scanned in overlapping 150-word windows**, because the model ignores anything past roughly 400 words.
- **Code-like false positives are filtered out.** The model tends to tag identifiers such as `name` or `User` as people. Entities that are all lowercase, contain code punctuation, or appear in code positions (`User.name`, `query(User)`) are dropped.
- **Results are cached per text**, so re-sent conversation history is not re-scanned every turn. Expect roughly 150 ms per new message on a 4-core CPU.
- **It runs fully offline.** The model is downloaded at build time and the container runs with the Hugging Face hub set to offline mode.

Watch the first few sessions with `GET /v1/vault/{session_id}`. If a common word is being replaced, add it to `NER_IGNORE`; if names are slipping through, lower `NER_THRESHOLD` (e.g. `0.4`).

To use a different model or library (Presidio, spaCy, a hosted-on-LAN service), pass any callable that takes text and returns `(entity_type, value)` pairs:

```python
from src.sanitizer import Sanitizer

def my_ner(text: str) -> list[tuple[str, str]]:
    return [("PERSON", "Jane Doe")] if "Jane Doe" in text else []

sanitizer = Sanitizer(vault, ner=my_ner)   # "Jane Doe" → <<PERSON_01>>
```

The app builds its NER hook in `build_ner()` in `src/ner.py`.

## How it works

| Module | Role |
| --- | --- |
| `src/vault.py` | `PIIVault`: SQLite store keyed by `(session_id, HMAC-SHA256(plaintext))`. `get_or_create_token` returns the existing token or allocates the next `<<TYPE_NN>>` for that session and type; `resolve_token` maps back, returning unknown tokens unchanged. |
| `src/sanitizer.py` | Regex detectors plus the NER hook. Overlapping matches resolve to the earliest; at the same position the more specific detector wins (an API key beats a generic credential, a URL password beats an email). Walks every text-bearing field of the request messages, and treats values under secret-named JSON keys as credentials. |
| `src/ner.py` | GLiNER loading, label mapping, text chunking, false-positive filtering, and result caching. |
| `src/hydrator.py` | `StreamHydrator`: a lookahead buffer (tokens up to 32 characters) that holds back a possible partial token until it can be resolved or ruled out. `ChatStreamHydrator` keeps one buffer per choice and per tool call and flushes on `finish_reason`; `GeminiStreamHydrator` keeps one per candidate for answer and thought text, hydrates `functionCall.args`, and preserves part order. |
| `src/tool_interceptor.py` | JSON-aware hydration of `tool_calls[].function.arguments`. |
| `src/openai_adapter.py` | Chat-completions session seed, response hydration, and mock upstream. |
| `src/gemini_adapter.py` | Gemini request scrubbing (`systemInstruction`, `contents[].parts[]` text, `functionCall.args`, `functionResponse.response`, including inside the Code Assist `request` envelope), header forwarding, response hydration, and mock upstream. |
| `src/main.py` | FastAPI routes and upstream forwarding with `httpx`. |

## Security notes and limitations

- **The vault holds plaintext.** HMAC is used for lookups, not encryption, so `data/vault.db` contains every value it has seen. Protect it like a secret store, and don't commit or share it.
- **Port 8000 has no authentication.** Anyone who can reach it can send requests through your upstream key (if `UPSTREAM_API_KEY` is set), read vault plaintext with `?include_plaintext=true`, or recover values through `/v1/hydrate`. Keep it on localhost or a trusted network.
- **Detection is best-effort.** Regexes only catch known formats, and the NER model can miss entities: names written in lowercase, lone surnames, single-word names inside parentheses (`(Liam)`), or anything below `NER_THRESHOLD`. Secrets in prose without a field name ("my password is hunter2") are not detected. Treat the proxy as a strong safety net, not a guarantee.
- **Only message text is scanned.** Image and file inputs, tool definitions, and other request fields are forwarded as-is.
- **Only chat completions, Gemini `generateContent`/`streamGenerateContent`/`countTokens`, and Code Assist `/v1internal` are proxied.** Embeddings, the Responses API, and other endpoints are not supported.
- **Vault entries are never deleted.** The database grows with each new value; delete the file to reset all sessions.

## Development

Requires Python 3.12+.

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'
pytest -v
```

The tests use a fake NER model, so they don't need GLiNER. To run the real model locally, install CPU-only PyTorch first (the default PyPI wheel pulls in several GB of CUDA libraries):

```bash
pip install torch --index-url https://download.pytorch.org/whl/cpu
pip install -e '.[ner]'
NER_BACKEND=gliner DB_PATH=./data/vault.db MOCK_UPSTREAM=true uvicorn src.main:app
```

Run locally without Docker:

```bash
DB_PATH=./data/vault.db MOCK_UPSTREAM=true uvicorn src.main:app --reload
```

The test suite covers deterministic token reuse, every detector (including code that must not be redacted), NER chunking and false-positive filtering, tokens split across arbitrary chunk boundaries (fixed, random, and exhaustive splits), JSON safety of hydrated tool arguments, the bridge endpoints, and end-to-end checks for both the OpenAI and Gemini (`agy`) routes that the upstream request contains none of the original sensitive values.
