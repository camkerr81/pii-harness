"""Direct /v1/sanitize, /v1/hydrate, and vault endpoints for headless wrapper scripts."""

from fastapi.testclient import TestClient

from src.config import Settings
from src.main import create_app

TEXT = "ssh admin@10.1.2.3 with key sk-proj1234567890abcdef, then mail admin@corp.example about 10.1.2.3 on prod-db"


def make_client(**overrides):
    return TestClient(create_app(Settings(DB_PATH=":memory:", VAULT_HMAC_SECRET="test-secret", **overrides)))


def test_sanitize_then_hydrate_round_trips_losslessly():
    with make_client(CUSTOM_REDACT_TERMS="prod-db") as client:
        first = client.post("/v1/sanitize", json={"session_id": "b1", "text": TEXT}).json()
        again = client.post("/v1/sanitize", json={"session_id": "b1", "text": TEXT}).json()
        hydrated = client.post("/v1/hydrate", json={"session_id": "b1", "text": first["sanitized_text"]}).json()

    assert first["sanitized_text"] == (
        "ssh admin@<<IPV4_01>> with key <<API_KEY_01>>, then mail <<EMAIL_01>> about <<IPV4_01>> on <<CUSTOM_01>>"
    )
    assert first["tokens_created"] == 4
    assert again == {**first, "tokens_created": 0}
    assert hydrated == {"session_id": "b1", "hydrated_text": TEXT}


def test_vault_listing_hides_plaintext_unless_asked():
    with make_client() as client:
        client.post("/v1/sanitize", json={"session_id": "b2", "text": TEXT})
        masked = client.get("/v1/vault/b2").json()
        revealed = client.get("/v1/vault/b2", params={"include_plaintext": "true"}).json()

    assert masked["count"] == 3
    assert "10.1.2.3" not in str(masked) and all("plaintext" not in t for t in masked["tokens"])
    assert {t["token"]: t["plaintext"] for t in revealed["tokens"]} == {
        "<<IPV4_01>>": "10.1.2.3",
        "<<API_KEY_01>>": "sk-proj1234567890abcdef",
        "<<EMAIL_01>>": "admin@corp.example",
    }


def test_global_tokens_hydrate_in_any_session_only_when_configured():
    for fallback, expected in (("global", "10.1.2.3"), ("", "<<IPV4_01>>")):
        with make_client(VAULT_FALLBACK_SESSION=fallback) as client:
            client.post("/v1/sanitize", json={"session_id": "global", "text": "host 10.1.2.3"})
            hydrated = client.post("/v1/hydrate", json={"session_id": "other", "text": "<<IPV4_01>>"}).json()
        assert hydrated["hydrated_text"] == expected
