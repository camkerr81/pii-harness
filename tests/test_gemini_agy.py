"""The Gemini APIs as the agy CLI uses them: /v1beta with an API key (GOOGLE_GEMINI_BASE_URL) and the
Code Assist /v1internal backend when signed in with a Google account (CLOUD_CODE_URL)."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from src.config import Settings
from src.main import create_app
from src.vault import TOKEN_RE

IP, KEY, EMAIL = "192.168.8.177", "sk-proj1234567890abcdef", "ops@corp.example"
MODEL_PATH = "/v1beta/models/gemini-3.1-pro-preview"
CLIENT_HEADERS = {
    "Authorization": "Bearer ya29.mock_oauth_token",
    "X-Goog-Api-Key": "AIzaClientKey",
    "X-Goog-User-Project": "my-project",
    "X-Goog-Api-Client": "google-genai-sdk/1.77.0",
    "Cookie": "session=not-for-google",
    "X-Session-ID": "agy-1",
}


def agy_request(envelope=False):
    """A second agy turn: the model ran a shell command and agy returns its output."""
    request = {
        "systemInstruction": {"parts": [{"text": f"You are Antigravity. Escalate to {EMAIL}."}]},
        "contents": [
            {"role": "user", "parts": [{"text": f"<USER_REQUEST>Check the server at {IP}</USER_REQUEST>"}]},
            {"role": "model", "parts": [{"functionCall": {"id": "f1", "name": "run_shell_command", "args": {"command": f"ip addr | grep {IP}"}}, "thoughtSignature": "c2lnbmF0dXJl"}]},
            {"role": "user", "parts": [{"functionResponse": {"id": "f1", "name": "run_shell_command", "response": {"output": f"inet {IP}/24\nexport KEY={KEY}"}}}]},
        ],
        "tools": [{"functionDeclarations": [{"name": "run_shell_command", "parametersJsonSchema": {"type": "object"}}]}],
        "generationConfig": {"thinkingConfig": {"includeThoughts": True}},
    }
    if envelope:  # Code Assist wraps the Gemini request
        return {"project": "test-proj", "model": "antigravity-gemini-3-pro", "request": {**request, "sessionId": "s-1"}}
    return request


class FakeGemini:
    """Stands in for generativelanguage.googleapis.com and answers using only the tokens it received."""

    def __init__(self, status=200):
        self.requests: list[httpx.Request] = []
        self.status = status

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.status != 200:
            return httpx.Response(self.status, json={"error": {"code": self.status, "message": "denied", "status": "PERMISSION_DENIED"}})
        method = request.url.path.rsplit(":", 1)[-1]
        if method not in ("generateContent", "streamGenerateContent", "countTokens"):  # Code Assist control plane
            return httpx.Response(200, json={"cloudaicompanionProject": "test-proj", "echo": json.loads(request.content)})
        wrap = (lambda e: {"response": e, "traceId": "t"}) if "/v1internal" in request.url.path else (lambda e: e)
        ip = next(t for t in TOKEN_RE.findall(request.content.decode()) if t.startswith("<<IPV4"))
        if request.url.path.endswith(":countTokens"):
            return httpx.Response(200, json={"totalTokens": 42})
        call = {"functionCall": {"name": "run_shell_command", "args": {"command": f"ssh root@{ip}", "env": {"HOST": ip}}}}
        frames = [
            {"text": "Thinking about " + ip[:6], "thought": True},
            {"text": ip[6:], "thought": True},
            {"text": "Connected to <<IP"},
            {"text": ip[4:]},
            call,
        ]
        events = [{"candidates": [{"content": {"role": "model", "parts": [p]}, "index": 0}]} for p in frames]
        events[-1]["candidates"][0]["finishReason"] = "STOP"
        events[-1]["usageMetadata"] = {"totalTokenCount": 15}
        if request.url.params.get("alt") == "sse":
            body = "".join(f"data: {json.dumps(wrap(e))}\r\n\r\n" for e in events)
            return httpx.Response(200, headers={"content-type": "text/event-stream"}, content=body.encode())
        if method == "streamGenerateContent":
            return httpx.Response(200, json=[wrap(e) for e in events])
        merged = [p for e in events for p in e["candidates"][0]["content"]["parts"] if not p.get("thought")]
        return httpx.Response(200, json=wrap({"candidates": [{"content": {"role": "model", "parts": merged}, "finishReason": "STOP", "index": 0}]}))


def make_client(upstream=None, **overrides):
    settings = Settings(
        DB_PATH=":memory:", VAULT_HMAC_SECRET="test-secret",
        UPSTREAM_GEMINI_URL="http://gemini.test/", UPSTREAM_CODE_ASSIST_URL="http://codeassist.test/", **overrides,
    )
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream)) if upstream else None
    return TestClient(create_app(settings, http_client=http_client))


def response_parts(response) -> list[dict]:
    if "event-stream" in response.headers["content-type"]:
        events = [json.loads(line[6:]) for line in response.iter_lines() if line.startswith("data: ")]
    else:
        body = json.loads(response.read())
        events = body if isinstance(body, list) else [body]
    events = [e.get("response", e) for e in events]
    return [p for e in events for c in e.get("candidates", []) for p in c["content"]["parts"]]


def text_of(parts, thought=False):
    return "".join(p["text"] for p in parts if "text" in p and bool(p.get("thought")) == thought)


@pytest.mark.parametrize(
    "path",
    [
        MODEL_PATH + ":streamGenerateContent?alt=sse",
        MODEL_PATH + "%3AstreamGenerateContent?alt=sse",  # how agy actually encodes the colon
        MODEL_PATH + ":streamGenerateContent",  # JSON array stream
        MODEL_PATH + ":generateContent",
        "/v1internal:streamGenerateContent?alt=sse",  # signed in with a Google account
        "/v1internal%3AstreamGenerateContent?alt=sse",
        "/v1internal:generateContent",
    ],
)
def test_agy_turn_is_scrubbed_upstream_and_hydrated_for_agy(path):
    upstream = FakeGemini()
    code_assist = path.startswith("/v1internal")
    with make_client(upstream) as client:
        with client.stream("POST", path, json=agy_request(code_assist), headers=CLIENT_HEADERS) as response:
            assert response.status_code == 200, response.read()
            assert response.headers["x-session-id"] == "agy-1"
            parts = response_parts(response)

    (sent,) = upstream.requests
    assert str(sent.url) == ("http://codeassist.test" if code_assist else "http://gemini.test") + path.replace("%3A", ":")
    # The client's credentials reach Google untouched; unrelated headers do not.
    assert sent.headers["authorization"] == "Bearer ya29.mock_oauth_token"
    assert sent.headers["x-goog-api-key"] == "AIzaClientKey"
    assert sent.headers["x-goog-user-project"] == "my-project"
    assert sent.headers["x-goog-api-client"] == "google-genai-sdk/1.77.0"
    assert "cookie" not in sent.headers
    raw = sent.content.decode()
    assert IP not in raw and KEY not in raw and EMAIL not in raw
    body = json.loads(raw)
    if code_assist:
        assert {k: v for k, v in body.items() if k != "request"} == {"project": "test-proj", "model": "antigravity-gemini-3-pro"}
        body = body["request"]
        assert body["sessionId"] == "s-1"
    assert body["systemInstruction"]["parts"][0]["text"] == "You are Antigravity. Escalate to <<EMAIL_01>>."
    assert body["contents"][1]["parts"][0]["functionCall"]["args"] == {"command": "ip addr | grep <<IPV4_01>>"}
    assert body["contents"][1]["parts"][0]["thoughtSignature"] == "c2lnbmF0dXJl"
    assert body["contents"][2]["parts"][0]["functionResponse"]["response"] == {"output": "inet <<IPV4_01>>/24\nexport KEY=<<API_KEY_01>>"}
    assert body["tools"] == agy_request()["tools"]

    call = next(p["functionCall"] for p in parts if "functionCall" in p)
    assert call == {"name": "run_shell_command", "args": {"command": f"ssh root@{IP}", "env": {"HOST": IP}}}
    assert text_of(parts) == f"Connected to {IP}"
    if not path.endswith(":generateContent"):
        assert text_of(parts, thought=True) == f"Thinking about {IP}"


def test_count_tokens_is_scrubbed_too():
    upstream = FakeGemini()
    with make_client(upstream) as client:
        response = client.post(MODEL_PATH + ":countTokens", json={"contents": agy_request()["contents"]})
    assert response.json() == {"totalTokens": 42}
    assert IP not in upstream.requests[0].content.decode()


def test_unsupported_methods_are_refused_without_contacting_google():
    upstream = FakeGemini()
    with make_client(upstream) as client:
        response = client.post(MODEL_PATH + ":embedContent", json={"content": {"parts": [{"text": IP}]}})
    assert response.status_code == 404
    assert upstream.requests == []


def test_google_errors_pass_through():
    with make_client(FakeGemini(status=403)) as client:
        response = client.post(MODEL_PATH + ":streamGenerateContent?alt=sse", json=agy_request())
    assert response.status_code == 403
    assert response.json()["error"]["status"] == "PERMISSION_DENIED"


@pytest.mark.parametrize("query", ["?alt=sse", ""])
def test_mock_upstream_answers_gemini_offline(query):
    with make_client(MOCK_UPSTREAM=True) as client:
        with client.stream("POST", MODEL_PATH + ":streamGenerateContent" + query, json=agy_request()) as response:
            text = text_of(response_parts(response))
    assert text.startswith("[mock upstream]") and "<<" not in text
    for value in (IP, KEY, EMAIL):
        assert value in text


def test_code_assist_control_plane_passes_through_with_the_oauth_token():
    upstream = FakeGemini()
    body = {"metadata": {"ideType": "ANTIGRAVITY"}}
    headers = {"Authorization": "Bearer ya29.pro_oauth_token", "User-Agent": "antigravity/cli/1.5.0", "Cookie": "x=1"}
    with make_client(upstream) as client:
        response = client.post("/v1internal:loadCodeAssist", json=body, headers=headers)
    assert response.json() == {"cloudaicompanionProject": "test-proj", "echo": body}
    (sent,) = upstream.requests
    assert str(sent.url) == "http://codeassist.test/v1internal:loadCodeAssist"
    assert sent.headers["authorization"] == "Bearer ya29.pro_oauth_token"
    assert sent.headers["user-agent"] == "antigravity/cli/1.5.0"
    assert "cookie" not in sent.headers
    assert json.loads(sent.content) == body


def test_code_assist_conversation_uploads_are_not_forwarded_and_other_methods_are_scrubbed():
    upstream = FakeGemini()
    trajectory = {"trajectory": {"steps": [{"userInput": f"Check the server at {IP}"}]}}
    with make_client(upstream) as client:
        assert client.post("/v1internal:recordTrajectoryAnalytics", json=trajectory).json() == {}
        assert upstream.requests == []
        client.post("/v1internal:someFutureMethod", json={"project": "test-proj", "note": f"host {IP}, key {KEY}"})
    assert json.loads(upstream.requests[0].content) == {"project": "test-proj", "note": "host <<IPV4_01>>, key <<API_KEY_01>>"}
