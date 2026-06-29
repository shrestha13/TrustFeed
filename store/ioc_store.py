"""
TrustFeed — IOC Store
SQLite-backed store for verified IOCs.
PostgreSQL-ready: all queries use standard SQL.
"""

import json
import sqlite3
import logging
from pathlib import Path
from typing import Optional
from config import IOC_DB_PATH
from store.models import IOCModel

log = logging.getLogger(__name__)


class IOCStore:
    def __init__(self, db_path: Path = IOC_DB_PATH):
        self.db_path = str(db_path)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS iocs (
                    ioc_id       TEXT PRIMARY KEY,
                    type         TEXT NOT NULL,
                    value        TEXT NOT NULL,
                    severity     TEXT NOT NULL,
                    ttl_seconds  INTEGER NOT NULL,
                    publisher_id TEXT NOT NULL,
                    nonce        TEXT NOT NULL UNIQUE,
                    timestamp    TEXT NOT NULL,
                    signature    TEXT NOT NULL,
                    stix_id      TEXT,
                    status       TEXT NOT NULL DEFAULT 'active',
                    raw_json     TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_status   ON iocs(status)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_publisher ON iocs(publisher_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_type      ON iocs(type)")
            conn.commit()
        log.debug("IOC store initialised at %s", self.db_path)

    def insert(self, ioc: IOCModel) -> None:
        """Store a verified IOC. Raises if ioc_id already exists."""
        with self._connect() as conn:
            conn.execute("""
                INSERT INTO iocs
                  (ioc_id, type, value, severity, ttl_seconds,
                   publisher_id, nonce, timestamp, signature, stix_id,
                   status, raw_json)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                ioc.ioc_id, ioc.type, ioc.value, ioc.severity,
                ioc.ttl_seconds, ioc.publisher_id, ioc.nonce,
                ioc.timestamp, ioc.signature, ioc.stix_id,
                "active", json.dumps(ioc.to_dict())
            ))
            conn.commit()
        log.info("IOC stored: %s (%s %s)", ioc.ioc_id, ioc.type, ioc.value)

    def get(self, ioc_id: str) -> Optional[IOCModel]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT raw_json FROM iocs WHERE ioc_id = ?", (ioc_id,)
            ).fetchone()
        if row:
            return IOCModel.from_dict(json.loads(row["raw_json"]))
        return None

    def retract(self, ioc_id: str) -> bool:
        """Mark an IOC as retracted. Returns True if found and updated."""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE iocs SET status = 'retracted' WHERE ioc_id = ?",
                (ioc_id,)
            )
            conn.commit()
        updated = cur.rowcount > 0
        if updated:
            log.info("IOC retracted: %s", ioc_id)
        return updated

    def get_active(self) -> list[IOCModel]:
        """Return all active, non-expired IOCs."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT raw_json FROM iocs WHERE status = 'active'"
            ).fetchall()
        iocs = [IOCModel.from_dict(json.loads(r["raw_json"])) for r in rows]
        # Filter out expired ones
        return [ioc for ioc in iocs if not ioc.is_expired()]

    def get_all(self) -> list[dict]:
        """Return all IOCs with status for dashboard display."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT raw_json, status FROM iocs ORDER BY timestamp DESC"
            ).fetchall()
        result = []
        for r in rows:
            data = json.loads(r["raw_json"])
            data["status"] = r["status"]
            result.append(data)
        return result

    def count(self) -> dict:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT status, COUNT(*) as n FROM iocs GROUP BY status"
            ).fetchall()
        return {r["status"]: r["n"] for r in rows}