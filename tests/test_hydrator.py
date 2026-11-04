import json
import random

import pytest

from src.hydrator import ChatStreamHydrator, StreamHydrator
from src.sanitizer import Sanitizer
from src.tool_interceptor import hydrate_json_arguments
from src.vault import PIIVault

SESSION = "s1"
# Plaintext that mixes real entities with every kind of "<" look-alike, ending in a bare "<".
ORIGINAL = (
    "Host is 10.0.0.1 (ping < 50ms); x < 10, <<not_a_token>>, <<<nested>>, <div>, "
    "cout << 10.0.0.1 << admin@example.com; wrapped <10.0.0.1>; unknown <<EMAIL_99>> stays; "
    "heredoc <<EOF\nmail admin@example.com again. Ends with <"
)
SECRET = 'pa"ss\nwo\\rd'


@pytest.fixture
def vault():
    v = PIIVault(":memory:", "test-secret")
    yield v
    v.close()


@pytest.fixture
def tokenized(vault):
    text = Sanitizer(vault).sanitize_text(SESSION, ORIGINAL)
    assert "10.0.0.1" not in text and "admin@example.com" not in text
    assert text.count("<<IPV4_01>>") == 3 and text.count("<<EMAIL_01>>") == 2
    return text


def run(vault, chunks, json_escape=False):
    h = StreamHydrator(vault, SESSION, json_escape=json_escape)
    return "".join(h.process_chunk(c) for c in chunks) + h.flush()


def split_every(text, size):
    return [text[i : i + size] for i in range(0, len(text), size)]


@pytest.mark.parametrize("size", [1, 2, 3, 5, 7, 11, 1000])
def test_fixed_size_chunks_reconstruct_original(vault, tokenized, size):
    assert run(vault, split_every(tokenized, size)) == ORIGINAL


@pytest.mark.parametrize("seed", range(25))
def test_random_chunks_reconstruct_original(vault, tokenized, seed):
    rng = random.Random(seed)
    chunks, pos = [], 0
    while pos < len(tokenized):
        size = rng.choice([0, 1, 1, 2, 3, 4, 9, 13])
        chunks.append(tokenized[pos : pos + size])
        pos += size
    assert run(vault, chunks) == ORIGINAL


def test_every_three_way_split_of_a_token(vault):
    vault.get_or_create_token(SESSION, "IPV4", "10.0.0.1")
    text = "Host is <<IPV4_01>>."
    for i in range(len(text) + 1):
        for j in range(i, len(text) + 1):
            assert run(vault, [text[:i], text[i:j], text[j:]]) == "Host is 10.0.0.1.", (i, j)


def test_partial_token_is_held_back_not_leaked(vault):
    vault.get_or_create_token(SESSION, "IPV4", "10.0.0.1")
    h = StreamHydrator(vault, SESSION)
    assert [h.process_chunk(c) for c in ["Host is <<IP", "V4_0", "1>>."]] == ["Host is ", "", "10.0.0.1."]
    assert h.flush() == ""


def test_non_token_angle_brackets_are_released_immediately(vault):
    h = StreamHydrator(vault, SESSION)
    assert h.process_chunk("std::cout << x; a < b") == "std::cout << x; a < b"
    assert h.process_chunk("<<IPV4") == ""  # could still become a token
    assert h.process_chunk(" ") == "<<IPV4 "


def test_tokens_from_other_sessions_are_not_resolved(vault):
    vault.get_or_create_token("other", "IPV4", "10.9.9.9")
    assert run(vault, ["see <<IPV", "4_01>>"]) == "see <<IPV4_01>>"


def test_json_escaped_stream_keeps_tool_arguments_valid(vault):
    token = vault.get_or_create_token(SESSION, "SECRET", SECRET)
    args = json.dumps({"password": token, "note": f"use {token} twice: {token}"})
    out = run(vault, split_every(args, 1), json_escape=True)
    assert json.loads(out) == {"password": SECRET, "note": f"use {SECRET} twice: {SECRET}"}


def test_hydrate_json_arguments_with_quotes_and_newlines(vault):
    token = vault.get_or_create_token(SESSION, "SECRET", SECRET)
    ip = vault.get_or_create_token(SESSION, "IPV4", "10.0.0.1")
    raw = json.dumps({"password": token, "hosts": [ip, f"{ip}:22"], token: {"n": 1, "ok": True}})
    assert json.loads(hydrate_json_arguments(SESSION, raw, vault)) == {
        "password": SECRET,
        "hosts": ["10.0.0.1", "10.0.0.1:22"],
        SECRET: {"n": 1, "ok": True},
    }


def test_hydrate_malformed_json_arguments_still_escapes_plaintext(vault):
    token = vault.get_or_create_token(SESSION, "SECRET", SECRET)
    truncated = '{"password": "' + token + '"'  # model forgot the closing brace
    assert json.loads(hydrate_json_arguments(SESSION, truncated, vault) + "}") == {"password": SECRET}


def chunk(delta, finish_reason=None, index=0):
    return {"id": "c", "object": "chat.completion.chunk", "choices": [{"index": index, "delta": delta, "finish_reason": finish_reason}]}


def collect(events):
    content, args = "", ""
    for event in events:
        for choice in event["choices"]:
            content += choice["delta"].get("content") or ""
            for call in choice["delta"].get("tool_calls") or []:
                args += call.get("function", {}).get("arguments") or ""
    return content, args


def test_chat_stream_flushes_buffers_on_finish_reason(vault):
    ip = vault.get_or_create_token(SESSION, "IPV4", "10.0.0.1")
    h = ChatStreamHydrator(vault, SESSION)
    events = [
        chunk({"role": "assistant", "content": ""}),
        chunk({"content": "Host " + ip[:5]}),
        chunk({"content": ip[5:] + " ends <"}),
        chunk({"tool_calls": [{"index": 0, "id": "t", "function": {"name": "ping", "arguments": '{"h": "' + ip[:4]}}]}),
        chunk({"tool_calls": [{"index": 0, "function": {"arguments": ip[4:] + '", "x": "<<'}}]}),
        chunk({}, "tool_calls"),
    ]
    out = [h.process_event(e) for e in events]
    assert collect(out) == ("Host 10.0.0.1 ends <", '{"h": "10.0.0.1", "x": "<<')
    assert h.finish() is None


def test_chat_stream_finish_emits_leftovers_when_stream_is_cut(vault):
    h = ChatStreamHydrator(vault, SESSION)
    first = h.process_event(chunk({"content": "a <<IPV4_0"}))
    tail = h.finish()
    assert collect([first, tail]) == ("a <<IPV4_0", "")
    assert tail["id"] == "c"
