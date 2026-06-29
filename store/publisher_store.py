"""
TrustFeed — Publisher Registry
SQLite-backed registry of all certified publishers.
Stores Ed25519 public keys needed for IOC signature verification.
"""

import json
import sqlite3
import logging
from pathlib import Path
from typing import Optional
from config import PUBLISHER_DB_PATH
from store.models import PublisherModel

log = logging.getLogger(__name__)


class PublisherStore:
    def __init__(self, db_path: Path = PUBLISHER_DB_PATH):
        self.db_path = str(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS publishers (
                    publisher_id    TEXT PRIMARY KEY,
                    name            TEXT NOT NULL,
                    tier            INTEGER NOT NULL,
                    cert_path       TEXT NOT NULL,
                    ed25519_pub_key TEXT NOT NULL,
                    registered_at   TEXT NOT NULL,
                    is_active       INTEGER NOT NULL DEFAULT 1,
                    raw_json        TEXT NOT NULL
                )
            """)
            conn.commit()
        log.debug("Publisher registry initialised at %s", self.db_path)

    def register(self, publisher: PublisherModel) -> None:
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO publishers
                  (publisher_id, name, tier, cert_path, ed25519_pub_key,
                   registered_at, is_active, raw_json)
                VALUES (?,?,?,?,?,?,?,?)
            """, (
                publisher.publisher_id,
                publisher.name,
                publisher.tier,
                publisher.cert_path,
                publisher.ed25519_pub_key,
                publisher.registered_at,
                int(publisher.is_active),
                json.dumps(publisher.to_dict())
            ))
            conn.commit()
        log.info("Publisher registered: %s (tier %s)", publisher.publisher_id, publisher.tier)

    def get(self, publisher_id: str) -> Optional[PublisherModel]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT raw_json FROM publishers WHERE publisher_id = ? AND is_active = 1",
                (publisher_id,)
            ).fetchone()
        if row:
            return PublisherModel.from_dict(json.loads(row["raw_json"]))
        return None

    def revoke(self, publisher_id: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE publishers SET is_active = 0 WHERE publisher_id = ?",
                (publisher_id,)
            )
            conn.commit()
        revoked = cur.rowcount > 0
        if revoked:
            log.warning("Publisher revoked: %s", publisher_id)
        return revoked

    def get_all(self) -> list[PublisherModel]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT raw_json FROM publishers ORDER BY registered_at DESC"
            ).fetchall()
        return [PublisherModel.from_dict(json.loads(r["raw_json"])) for r in rows]