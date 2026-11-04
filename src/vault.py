import hashlib
import hmac
import re
import sqlite3
import threading
from pathlib import Path

# A semantic token anywhere inside a larger string, e.g. "Host is <<IPV4_01>>."
TOKEN_RE = re.compile(r"<<[A-Z0-9_]+_\d{2,}>>")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS vault (
    session_id  TEXT NOT NULL,
    hmac_hash   TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    token       TEXT NOT NULL,
    plaintext   TEXT NOT NULL,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (session_id, hmac_hash)
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_vault_session_token ON vault (session_id, token);
"""


class PIIVault:
    """Session-scoped, bidirectional plaintext <-> semantic token store backed by SQLite."""

    def __init__(self, db_path: str, hmac_secret: str, fallback_session: str = ""):
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._secret = hmac_secret.encode()
        # Tokens not found in the request's session are looked up here (e.g. "global" tokens
        # created through /v1/sanitize by a bridge script). Empty disables the fallback.
        self.fallback_session = fallback_session
        self._lock = threading.Lock()
        # Autocommit mode; writes use explicit BEGIN IMMEDIATE so token numbering stays
        # consistent even if several processes share the same database file.
        self._conn = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None, timeout=30)
        self._conn.execute("PRAGMA journal_mode=WAL;")
        self._conn.execute("PRAGMA synchronous=NORMAL;")
        self._conn.executescript(_SCHEMA)

    def close(self) -> None:
        self._conn.close()

    def _hash(self, plaintext: str) -> str:
        return hmac.new(self._secret, plaintext.encode(), hashlib.sha256).hexdigest()

    def get_or_create_token(self, session_id: str, entity_type: str, plaintext: str) -> str:
        entity_type = re.sub(r"[^A-Z0-9_]", "_", entity_type.upper())
        digest = self._hash(plaintext)
        with self._lock:
            row = self._conn.execute(
                "SELECT token FROM vault WHERE session_id = ? AND hmac_hash = ?", (session_id, digest)
            ).fetchone()
            if row:
                return row[0]
            self._conn.execute("BEGIN IMMEDIATE")
            try:
                row = self._conn.execute(
                    "SELECT token FROM vault WHERE session_id = ? AND hmac_hash = ?", (session_id, digest)
                ).fetchone()
                if row:
                    self._conn.execute("COMMIT")
                    return row[0]
                (count,) = self._conn.execute(
                    "SELECT COUNT(*) FROM vault WHERE session_id = ? AND entity_type = ?", (session_id, entity_type)
                ).fetchone()
                token = f"<<{entity_type}_{count + 1:02d}>>"
                self._conn.execute(
                    "INSERT INTO vault (session_id, hmac_hash, entity_type, token, plaintext) VALUES (?, ?, ?, ?, ?)",
                    (session_id, digest, entity_type, token, plaintext),
                )
                self._conn.execute("COMMIT")
                return token
            except BaseException:
                self._conn.execute("ROLLBACK")
                raise

    def resolve_token(self, session_id: str, token: str) -> str:
        sessions = (session_id, self.fallback_session) if self.fallback_session not in ("", session_id) else (session_id,)
        with self._lock:
            for session in sessions:
                row = self._conn.execute(
                    "SELECT plaintext FROM vault WHERE session_id = ? AND token = ?", (session, token)
                ).fetchone()
                if row:
                    return row[0]
        return token

    def hydrate_text(self, session_id: str, text: str) -> str:
        """Replace every semantic token in ``text`` with its plaintext for ``session_id``."""
        return TOKEN_RE.sub(lambda m: self.resolve_token(session_id, m.group()), text)

    def list_tokens(self, session_id: str, include_plaintext: bool = False) -> list[dict]:
        """Token metadata for a session; plaintext only when explicitly requested."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT token, entity_type, created_at, plaintext FROM vault WHERE session_id = ? ORDER BY rowid",
                (session_id,),
            ).fetchall()
        entries = [{"token": t, "entity_type": e, "created_at": c} for t, e, c, _ in rows]
        if include_plaintext:
            for entry, row in zip(entries, rows):
                entry["plaintext"] = row[3]
        return entries
