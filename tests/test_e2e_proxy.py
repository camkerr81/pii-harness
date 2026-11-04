import json

import httpx
import pytest
from fastapi.testclient import TestClient

from src.config import Settings
from src.main import create_app
from src.vault import TOKEN_RE

IP, EMAIL, KEY, PHONE, GH = (
    "10.20.30.40",
    "jane.doe@corp.example",
    "sk-proj-ABCDEF1234567890abcd",
    "+61 412 345 678",
    "ghp_ZYXWVUTSRQPONMLK9876",
)
SENSITIVE = [IP, EMAIL, KEY, PHONE, GH]
IMAGE = {"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBORw0KGgo="}}


def conversation(stream):
    return {
        "model": "gpt-test",
        "stream": stream,
        "tools": [{"type": "function", "function": {"name": "ssh", "parameters": {"type": "object"}}}],
        "messages": [
            {"role": "system", "content": f"You administer {IP}. Escalate to {EMAIL}."},
            {"role": "user", "content": [{"type": "text", "text": f"Call me on {PHONE}; key {KEY}"}, IMAGE]},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [{"id": "c1", "type": "function", "function": {"name": "ssh", "arguments": json.dumps({"host": IP, "user": EMAIL})}}],
            },
            {"role": "tool", "tool_call_id": "c1", "content": f"connected to {IP}\nGITHUB_TOKEN={GH}"},
            {"role": "user", "content": "Check the host again."},
        ],
    }


class FakeUpstream:
    """Stands in for the frontier API: records what it receives and answers using only the tokens it saw."""

    def __init__(self):
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        body = json.loads(request.content)
        tokens = {}  # entity type -> first token of that type
        for token in TOKEN_RE.findall(request.content.decode()):
            tokens.setdefault(token.strip("<>").rsplit("_", 1)[0], token)
        text = f"Host {tokens['IPV4']} is up; mailed {tokens['EMAIL']} <3"
        args = json.dumps({"host": tokens["IPV4"], "note": f"rotate {tokens['API_KEY']}"})
        if not body.get("stream"):
            message = {"role": "assistant", "content": text, "tool_calls": [{"id": "c2", "type": "function", "function": {"name": "ssh", "arguments": args}}]}
            return httpx.Response(200, json={"id": "x", "object": "chat.completion", "choices": [{"index": 0, "message": message, "finish_reason": "tool_calls"}]})

        def event(delta, finish=None):
            return "data: " + json.dumps({"id": "x", "object": "chat.completion.chunk", "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}) + "\n\n"

        sse = [event({"role": "assistant", "content": ""})]
        sse += [event({"content": text[i : i + 2]}) for i in range(0, len(text), 2)]
        sse.append(event({"tool_calls": [{"index": 0, "id": "c2", "type": "function", "function": {"name": "ssh", "arguments": ""}}]}))
        sse += [event({"tool_calls": [{"index": 0, "function": {"arguments": args[i : i + 3]}}]}) for i in range(0, len(args), 3)]
        sse += [event({}, "tool_calls"), "data: [DONE]\n\n"]
        return httpx.Response(200, headers={"content-type": "text/event-stream"}, content="".join(sse).encode())


def make_client(upstream=None, **overrides):
    settings = Settings(DB_PATH=":memory:", VAULT_HMAC_SECRET="test-secret", UPSTREAM_BASE_URL="http://upstream.test/v1/", **overrides)
    http_client = httpx.AsyncClient(transport=httpx.MockTransport(upstream)) if upstream else None
    return TestClient(create_app(settings, http_client=http_client))


def assert_no_leak(raw: bytes):
    text = raw.decode()
    for value in SENSITIVE:
        assert value not in text and json.dumps(value)[1:-1] not in text, value


def read_stream(response):
    content, args = "", ""
    for line in response.iter_lines():
        if not line.startswith("data: ") or line == "data: [DONE]":
            continue
        for choice in json.loads(line[6:])["choices"]:
            content += choice["delta"].get("content") or ""
            for call in choice["delta"].get("tool_calls") or []:
                args += call["function"].get("arguments") or ""
    return content, args


@pytest.mark.parametrize("stream", [True, False])
def test_upstream_sees_only_tokens_and_client_gets_plaintext(stream):
    upstream = FakeUpstream()
    with make_client(upstream) as client:
        with client.stream("POST", "/v1/chat/completions", json=conversation(stream), headers={"X-Session-ID": "sess-1", "Authorization": "Bearer client-key"}) as response:
            assert response.status_code == 200
            assert response.headers["x-session-id"] == "sess-1"
            if stream:
                content, args = read_stream(response)
            else:
                message = json.loads(response.read())["choices"][0]["message"]
                content, args = message["content"], message["tool_calls"][0]["function"]["arguments"]

    (sent,) = upstream.requests
    assert str(sent.url) == "http://upstream.test/v1/chat/completions"
    assert sent.headers["authorization"] == "Bearer client-key"
    assert_no_leak(sent.content)
    body = json.loads(sent.content)
    assert body["messages"][1]["content"][1] == IMAGE
    assert body["messages"][0]["content"] == "You administer <<IPV4_01>>. Escalate to <<EMAIL_01>>."
    assert json.loads(body["messages"][2]["tool_calls"][0]["function"]["arguments"]) == {"host": "<<IPV4_01>>", "user": "<<EMAIL_01>>"}

    assert content == f"Host {IP} is up; mailed {EMAIL} <3"
    assert json.loads(args) == {"host": IP, "note": f"rotate {KEY}"}


def test_tokens_stay_stable_across_turns_and_persist_in_vault():
    upstream = FakeUpstream()
    with make_client(upstream) as client:
        for _ in range(2):
            client.post("/v1/chat/completions", json=conversation(False), headers={"X-Session-ID": "sess-2"})
        listing = client.get("/v1/vault/sess-2").json()

    first, second = (json.loads(r.content)["messages"] for r in upstream.requests)
    assert first == second
    assert {t["token"] for t in listing["tokens"]} == {"<<IPV4_01>>", "<<EMAIL_01>>", "<<PHONE_01>>", "<<API_KEY_01>>", "<<API_KEY_02>>"}
    assert_no_leak(json.dumps(listing).encode())


def test_configured_upstream_key_replaces_client_authorization():
    upstream = FakeUpstream()
    with make_client(upstream, UPSTREAM_API_KEY="server-key") as client:
        client.post("/v1/chat/completions", json=conversation(False), headers={"Authorization": "Bearer client-key"})
    assert upstream.requests[0].headers["authorization"] == "Bearer server-key"


def test_session_falls_back_to_hash_of_first_prompt():
    upstream = FakeUpstream()
    with make_client(upstream) as client:
        a = client.post("/v1/chat/completions", json=conversation(False)).headers["x-session-id"]
        b = client.post("/v1/chat/completions", json=conversation(False)).headers["x-session-id"]
    assert a == b and a.startswith("auto-")


def test_upstream_errors_pass_through():
    with make_client(lambda request: httpx.Response(401, json={"error": {"message": "bad key"}})) as client:
        response = client.post("/v1/chat/completions", json=conversation(True))
    assert response.status_code == 401
    assert response.json() == {"error": {"message": "bad key"}}


@pytest.mark.parametrize("stream", [True, False])
def test_mock_upstream_mode_round_trips_offline(stream):
    with make_client(MOCK_UPSTREAM=True) as client:
        assert client.get("/health").json() == {"status": "ok", "db_path": ":memory:"}
        response = client.post("/v1/chat/completions", json=conversation(stream), headers={"X-Session-ID": "m"})
        if stream:
            content, args = read_stream(response)
        else:
            message = response.json()["choices"][0]["message"]
            content, args = message["content"], message["tool_calls"][0]["function"]["arguments"]
    assert "<<" not in content
    for value in SENSITIVE:
        assert value in content
    assert set(json.loads(args)["entities"]) == set(SENSITIVE)
