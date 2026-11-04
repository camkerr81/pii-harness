import json

import pytest

from src.sanitizer import Sanitizer
from src.vault import PIIVault


@pytest.fixture
def sanitizer():
    v = PIIVault(":memory:", "test-secret")
    yield Sanitizer(v)
    v.close()


def entities(sanitizer, text):
    return [(text[s:e], t) for s, e, t in sanitizer.find_entities(text)]


@pytest.mark.parametrize(
    ("text", "value", "entity_type"),
    [
        ("mail jane.o'neil+ops@mail.corp.example.com now", "jane.o'neil+ops@mail.corp.example.com", "EMAIL"),
        ("host 192.168.0.254.", "192.168.0.254", "IPV4"),
        ("key=sk-proj-AbC123_def-456ghi789", "sk-proj-AbC123_def-456ghi789", "API_KEY"),
        ("token ghp_abcdefghijklmnop1234 ok", "ghp_abcdefghijklmnop1234", "API_KEY"),
        ("slack xoxb-1234-5678-abcd", "xoxb-1234-5678-abcd", "API_KEY"),
        ("call +61 412 345 678 today", "+61 412 345 678", "PHONE"),
        ("call +61 2 9876 5432 today", "+61 2 9876 5432", "PHONE"),
        ("mobile 0412 345 678.", "0412 345 678", "PHONE"),
        ("office (02) 9876 5432", "(02) 9876 5432", "PHONE"),
        ("landline 03-9876-5432", "03-9876-5432", "PHONE"),
        ("support 1300 123 456", "1300 123 456", "PHONE"),
        ("london +44 20 7946 0958", "+44 20 7946 0958", "PHONE"),
        ("us (415) 555-0132", "(415) 555-0132", "PHONE"),
        # credentials: only the secret is replaced, the field name stays readable
        ("export OPENAI_API_KEY=sk-proj-AbC123_def-456ghi789", "sk-proj-AbC123_def-456ghi789", "API_KEY"),
        ("aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", "API_KEY"),
        ("pat github_pat_11ABCDEFG0123456789_abcdefghijklmnop", "github_pat_11ABCDEFG0123456789_abcdefghijklmnop", "API_KEY"),
        ("gitlab glpat-xY12_abCDefGHijKLmnOPqr", "glpat-xY12_abCDefGHijKLmnOPqr", "API_KEY"),
        ("maps AIzaSyD-1234567890abcdefghijklmnopqrstu", "AIzaSyD-1234567890abcdefghijklmnopqrstu", "API_KEY"),
        ("stripe sk_live_51HxYzAbCdEfGhIjKl", "sk_live_51HxYzAbCdEfGhIjKl", "API_KEY"),
        ("hf hf_abcdefghijklmnopqrstuvwxyz123456", "hf_abcdefghijklmnopqrstuvwxyz123456", "API_KEY"),
        ("aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "CREDENTIAL"),
        ("DB_PASSWORD=hunter2! # prod", "hunter2!", "CREDENTIAL"),
        ("login failed (password=Winter2026!)", "Winter2026!", "CREDENTIAL"),
        ('password: "correct horse battery"', "correct horse battery", "CREDENTIAL"),
        ('{"client_secret": "abc def 123"}', "abc def 123", "CREDENTIAL"),
        ("SECRET_KEY = 'django-insecure-x9'", "django-insecure-x9", "CREDENTIAL"),
        ("postgres://admin:s3cr3t@db.internal:5432/app", "s3cr3t", "CREDENTIAL"),
        ("Authorization: Bearer abcdefghijklmnop1234", "abcdefghijklmnop1234", "CREDENTIAL"),
        ("Authorization: Basic YWxhZGRpbjpvcGVuc2VzYW1l", "YWxhZGRpbjpvcGVuc2VzYW1l", "CREDENTIAL"),
        ("Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9P",
         "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9P", "JWT"),
        ("key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nq83+/=\n-----END RSA PRIVATE KEY-----\nok",
         "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\nq83+/=\n-----END RSA PRIVATE KEY-----", "PRIVATE_KEY"),
        ("cut off: -----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\nAAAABG5vbmU", 
         "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA\nAAAABG5vbmU", "PRIVATE_KEY"),
    ],
)
def test_detects_sensitive_values(sanitizer, text, value, entity_type):
    assert entities(sanitizer, text) == [(value, entity_type)]


@pytest.mark.parametrize(
    "text",
    [
        "latency < 50ms and x < 10",
        "version 1.2.3.400 and 999.1.1.1 and 1.2.3.4.5",
        "released 2026-11-04 at 10:30, order 123456789",
        "ask-me-anything-123456789012345",  # "sk-" inside a word is not an API key
        "already tokenised <<EMAIL_01>> and <<IPV4_02>>, password: \"<<CREDENTIAL_01>>\"",
        # code that mentions secrets without containing one
        "def login(password: str, token: Optional[str] = None, max_tokens=512):",
        "password = getpass.getpass(); token = os.environ['TOKEN']; secret = None",
        "password: ${DB_PASSWORD}  # the password is required",
        "input_tokens: 20, token_count = 5",
    ],
)
def test_ignores_lookalikes(sanitizer, text):
    assert entities(sanitizer, text) == []


def test_ner_hook_entities_are_tokenised_as_whole_words(sanitizer):
    sanitizer.ner = lambda text: [("PERSON", "Jane")] if "Jane" in text else []
    assert sanitizer.sanitize_text("s1", "Jane emailed jane@example.com; ask Jane, not Janet") == (
        "<<PERSON_01>> emailed <<EMAIL_01>>; ask <<PERSON_01>>, not Janet"
    )


def test_json_values_under_secret_keys_are_tokenised(sanitizer):
    raw = json.dumps({
        "password": "Tr0ub4dor&3", "secret": 4821, "user": "bob", "api_key": "sk-abcdefghijklmnop1234",
        "max_tokens": 50, "verbose": True, "nested": {"db.password": "Tr0ub4dor&3", "token": ""},
    })
    assert json.loads(sanitizer.sanitize_json_arguments("s1", raw)) == {
        "password": "<<CREDENTIAL_01>>", "secret": "<<CREDENTIAL_02>>", "user": "bob", "api_key": "<<API_KEY_01>>",
        "max_tokens": 50, "verbose": True, "nested": {"db.password": "<<CREDENTIAL_01>>", "token": ""},
    }


def test_payload_scrubs_every_text_field_but_leaves_other_parts(sanitizer):
    image = {"type": "image_url", "image_url": {"url": "data:image/png;base64,MDQxMiAzNDUgNjc4"}}
    payload = {
        "model": "gpt-x",
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "I am at 10.1.1.1"}, image]},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {"id": "c1", "type": "function", "function": {"name": "ssh", "arguments": '{"host": "10.1.1.1"}'}}
                ],
            },
            {"role": "tool", "tool_call_id": "c1", "content": "login ok for ops@example.com"},
        ],
    }
    out = sanitizer.sanitize_payload("s1", payload)
    assert out["messages"][0]["content"] == [{"type": "text", "text": "I am at <<IPV4_01>>"}, image]
    assert json.loads(out["messages"][1]["tool_calls"][0]["function"]["arguments"]) == {"host": "<<IPV4_01>>"}
    assert out["messages"][2]["content"] == "login ok for <<EMAIL_01>>"
    assert payload["messages"][2]["content"] == "login ok for ops@example.com"  # caller's payload untouched
