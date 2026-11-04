import hashlib
import hmac
import sqlite3

import pytest

from src.sanitizer import Sanitizer
from src.vault import PIIVault


@pytest.fixture
def vault():
    v = PIIVault(":memory:", "test-secret")
    yield v
    v.close()


def test_repeated_plaintext_reuses_its_token(vault):
    text = "Contact admin@example.com or backup@example.com, then CC admin@example.com"
    assert Sanitizer(vault).sanitize_text("s1", text) == "Contact <<EMAIL_01>> or <<EMAIL_02>>, then CC <<EMAIL_01>>"


def test_numbering_is_per_session_and_entity_type(vault):
    assert vault.get_or_create_token("a", "EMAIL", "x@example.com") == "<<EMAIL_01>>"
    assert vault.get_or_create_token("a", "IPV4", "10.0.0.1") == "<<IPV4_01>>"
    assert vault.get_or_create_token("a", "EMAIL", "y@example.com") == "<<EMAIL_02>>"
    # A different session starts its own numbering, so tokens never resolve across sessions.
    assert vault.get_or_create_token("b", "EMAIL", "y@example.com") == "<<EMAIL_01>>"
    assert vault.resolve_token("a", "<<EMAIL_01>>") == "x@example.com"
    assert vault.resolve_token("b", "<<EMAIL_01>>") == "y@example.com"
    assert vault.resolve_token("b", "<<IPV4_01>>") == "<<IPV4_01>>"


def test_unknown_token_resolves_to_itself(vault):
    assert vault.resolve_token("s1", "<<EMAIL_07>>") == "<<EMAIL_07>>"


def test_fallback_session_resolves_tokens_missing_from_the_session():
    v = PIIVault(":memory:", "test-secret", fallback_session="global")
    v.get_or_create_token("global", "EMAIL", "shared@example.com")
    v.get_or_create_token("global", "IPV4", "10.9.9.9")
    v.get_or_create_token("s1", "EMAIL", "own@example.com")
    # The session's own token wins; only tokens it lacks fall back to "global".
    assert v.hydrate_text("s1", "<<EMAIL_01>> <<IPV4_01>> <<IPV4_02>>") == "own@example.com 10.9.9.9 <<IPV4_02>>"
    assert PIIVault(":memory:", "test-secret").hydrate_text("s1", "<<IPV4_01>>") == "<<IPV4_01>>"
    v.close()


def test_entity_type_is_normalised_into_token_format(vault):
    assert vault.get_or_create_token("s1", "person name", "Jane Doe") == "<<PERSON_NAME_01>>"


def test_index_grows_past_two_digits(vault):
    tokens = [vault.get_or_create_token("s1", "EMAIL", f"u{i}@example.com") for i in range(100)]
    assert tokens[8] == "<<EMAIL_09>>"
    assert tokens[99] == "<<EMAIL_100>>"
    assert vault.resolve_token("s1", "<<EMAIL_100>>") == "u99@example.com"


def test_file_vault_uses_wal_hmac_and_persists(tmp_path):
    db = tmp_path / "nested" / "vault.db"
    v = PIIVault(str(db), "test-secret")
    token = v.get_or_create_token("s1", "IPV4", "192.168.1.10")
    v.close()

    conn = sqlite3.connect(db)
    assert conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    (stored_hash,) = conn.execute("SELECT hmac_hash FROM vault").fetchone()
    conn.close()
    assert stored_hash == hmac.new(b"test-secret", b"192.168.1.10", hashlib.sha256).hexdigest()

    reopened = PIIVault(str(db), "test-secret")
    assert reopened.get_or_create_token("s1", "IPV4", "192.168.1.10") == token
    assert reopened.resolve_token("s1", token) == "192.168.1.10"
    reopened.close()
