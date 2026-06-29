"""
TrustFeed — Retraction Module
Allows publishers to cryptographically retract false positive IOCs.

Why this matters:
  Threat intel feeds regularly contain false positives.
  Without a retraction mechanism, a wrongly flagged legitimate IP
  stays in every SOC's blocklist until it manually expires.
  TrustFeed retractions are signed with the same Ed25519 key that
  signed the original IOC — proving the same publisher is retracting.

Flow:
  1. Publisher signs retraction with their Ed25519 private key
  2. Retraction is saved to retraction log (SQLite)
  3. IOC is marked 'retracted' in IOC store
  4. Any future verification of that IOC_id fails at retraction step
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import config
from crypto.signing import sign_retraction, verify_retraction, load_ed25519_public_from_b64
from store.models import RetractionModel
from store.ioc_store import IOCStore
from store.publisher_store import PublisherStore

log = logging.getLogger(__name__)


# ── Retraction log store ──────────────────────────────────────────────────────

class RetractionStore:
    """SQLite-backed log of all signed retractions."""

    def __init__(self, db_path=None):
        self.db_path = str(db_path or config.RETRACTION_DB_PATH)
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS retractions (
                    retraction_id TEXT PRIMARY KEY,
                    ioc_id        TEXT NOT NULL,
                    publisher_id  TEXT NOT NULL,
                    reason        TEXT NOT NULL,
                    timestamp     TEXT NOT NULL,
                    signature     TEXT NOT NULL,
                    raw_json      TEXT NOT NULL
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ioc ON retractions(ioc_id)")
            conn.commit()

    def save(self, retraction: RetractionModel):
        with self._connect() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO retractions
                (retraction_id, ioc_id, publisher_id, reason, timestamp, signature, raw_json)
                VALUES (?,?,?,?,?,?,?)
            """, (
                retraction.retraction_id, retraction.ioc_id,
                retraction.publisher_id, retraction.reason,
                retraction.timestamp, retraction.signature,
                json.dumps(retraction.to_dict())
            ))
            conn.commit()
        log.info("Retraction saved: %s for IOC %s", retraction.retraction_id, retraction.ioc_id)

    def get_by_ioc(self, ioc_id: str):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT raw_json FROM retractions WHERE ioc_id=?", (ioc_id,)
            ).fetchone()
        return RetractionModel.from_dict(json.loads(row["raw_json"])) if row else None

    def get_all(self) -> list:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT raw_json FROM retractions ORDER BY timestamp DESC"
            ).fetchall()
        return [RetractionModel.from_dict(json.loads(r["raw_json"])) for r in rows]

    def count(self) -> int:
        with self._connect() as conn:
            return conn.execute("SELECT COUNT(*) as n FROM retractions").fetchone()["n"]


# ── Retraction manager ────────────────────────────────────────────────────────

class RetractionManager:
    """
    Issues and verifies IOC retractions.

    Usage:
        rm = RetractionManager()
        rm.retract("ioc-uuid", "npcert-01", "False positive — legitimate NTC IP")
    """

    def __init__(self):
        self.ioc_store   = IOCStore()
        self.pub_store   = PublisherStore()
        self.ret_store   = RetractionStore()

    def retract(self, ioc_id: str, publisher_id: str, reason: str) -> dict:
        """
        Issue a signed retraction for an IOC.

        Steps:
          1. Verify IOC exists and belongs to this publisher
          2. Load publisher's Ed25519 private key
          3. Build and sign RetractionModel
          4. Save to retraction log
          5. Mark IOC as retracted in IOC store

        Returns retraction dict.
        """
        # Step 1 — IOC must exist
        ioc = self.ioc_store.get(ioc_id)
        if not ioc:
            raise ValueError(f"IOC not found: {ioc_id}")

        # Step 2 — publisher must own this IOC
        if ioc.publisher_id != publisher_id:
            raise PermissionError(
                f"Publisher '{publisher_id}' did not submit IOC '{ioc_id}' "
                f"(owned by '{ioc.publisher_id}')"
            )

        # Step 3 — publisher must be active
        publisher = self.pub_store.get(publisher_id)
        if not publisher:
            raise PermissionError(f"Publisher '{publisher_id}' not found or revoked")

        # Step 4 — load Ed25519 private key
        ed_priv_path = config.CERTS_DIR / f"{publisher_id}.ed25519.pem"
        if not ed_priv_path.exists():
            raise FileNotFoundError(f"Ed25519 key not found for: {publisher_id}")

        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        ed_priv = load_pem_private_key(ed_priv_path.read_bytes(), None)

        # Step 5 — build and sign retraction
        retraction = RetractionModel(
            ioc_id=ioc_id,
            publisher_id=publisher_id,
            reason=reason,
            timestamp=datetime.now(timezone.utc).isoformat(),
        )
        retraction.signature = sign_retraction(ed_priv, retraction)

        # Step 6 — save retraction and mark IOC
        self.ret_store.save(retraction)
        self.ioc_store.retract(ioc_id)

        log.warning("IOC RETRACTED: %s by %s — %s", ioc_id, publisher_id, reason)
        return retraction.to_dict()

    def verify_retraction(self, retraction_id_or_ioc_id: str) -> tuple[bool, str]:
        """
        Verify a retraction's signature.
        Confirms it genuinely came from the original publisher.
        """
        retraction = self.ret_store.get_by_ioc(retraction_id_or_ioc_id)
        if not retraction:
            return False, f"No retraction found for IOC: {retraction_id_or_ioc_id}"

        publisher = self.pub_store.get(retraction.publisher_id)
        if not publisher:
            return False, f"Publisher not found: {retraction.publisher_id}"

        ed_pub = load_ed25519_public_from_b64(publisher.ed25519_pub_key)
        valid  = verify_retraction(ed_pub, retraction)

        if valid:
            return True, f"Retraction valid — signed by {retraction.publisher_id}"
        return False, "Retraction signature INVALID"

    def is_retracted(self, ioc_id: str) -> bool:
        """Quick check — is this IOC retracted?"""
        return self.ret_store.get_by_ioc(ioc_id) is not None