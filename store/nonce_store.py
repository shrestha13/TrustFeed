"""
TrustFeed — Nonce Store
SQLite-backed replay attack prevention.
Every nonce seen is stored permanently.
A second appearance of any nonce = replay attack, rejected immediately.
"""

import sqlite3
import logging
from pathlib import Path
from config import NONCE_DB_PATH

log = logging.getLogger(__name__)


class NonceStore:
    def __init__(self, db_path: Path = NONCE_DB_PATH):
        self.db_path = str(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS nonces (
                    nonce      TEXT PRIMARY KEY,
                    ioc_id     TEXT NOT NULL,
                    seen_at    TEXT NOT NULL
                )
            """)
            conn.commit()
        log.debug("Nonce store initialised at %s", self.db_path)

    def is_seen(self, nonce: str) -> bool:
        """Return True if this nonce has been seen before — replay detected."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM nonces WHERE nonce = ?", (nonce,)
            ).fetchone()
        return row is not None

    def mark_seen(self, nonce: str, ioc_id: str) -> None:
        """
        Record a nonce as seen. Called only after full verification passes.
        Raises sqlite3.IntegrityError if nonce already exists
        (shouldn't happen — always call is_seen first).
        """
        from datetime import datetime, timezone
        seen_at = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO nonces (nonce, ioc_id, seen_at) VALUES (?,?,?)",
                (nonce, ioc_id, seen_at)
            )
            conn.commit()
        log.debug("Nonce recorded: %s for IOC %s", nonce[:16], ioc_id)

    def count(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) as n FROM nonces").fetchone()
        return row["n"]