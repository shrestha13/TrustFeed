"""
TrustFeed — Verifier Module
Full IOC verification pipeline.

For every .tfb bundle received, the verifier runs these checks in order:
  1. Decrypt bundle (RSA-OAEP unwrap AES key → AES-256-GCM decrypt)
  2. Validate publisher certificate chain → Intermediate CA → Root CA → CRL
  3. Verify Ed25519 signature on every IOC individually
  4. Check nonce against SQLite — replay attack detection
  5. Check IOC expiry timestamp
  6. Check retraction status

A single failure at any step = IOC rejected.
Only IOCs passing ALL checks are exported to SIEM.

Three demo scenarios covered here:
  Demo 1 — Normal verified ingestion  → all checks pass
  Demo 2 — Tampered feed detection    → step 3 fails (signature invalid)
  Demo 3 — Replay attack prevention   → step 4 fails (nonce seen before)
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import config
from ca.authority import CertificateAuthority
from crypto.signing import verify_ioc, load_ed25519_public_from_b64
from crypto.encryption import decrypt_feed
from crypto.nonce import check_and_store_nonce, is_replay
from store.models import IOCModel
from store.ioc_store import IOCStore
from store.nonce_store import NonceStore
from store.publisher_store import PublisherStore

log = logging.getLogger(__name__)


# ── Result dataclasses ────────────────────────────────────────────────────────

@dataclass
class IOCVerificationResult:
    """Result for a single IOC verification attempt."""
    ioc_id:    str
    value:     str
    type:      str
    passed:    bool
    reason:    str
    step:      str   # which step failed or "all_passed"


@dataclass
class FeedVerificationResult:
    """Aggregated result for a full .tfb bundle verification."""
    bundle_path:    str
    publisher_id:   str
    total:          int = 0
    accepted:       int = 0
    rejected:       int = 0
    ioc_results:    list = field(default_factory=list)
    error:          Optional[str] = None

    @property
    def success(self) -> bool:
        return self.error is None and self.accepted > 0

    def summary(self) -> dict:
        return {
            "bundle_path":  self.bundle_path,
            "publisher_id": self.publisher_id,
            "total":        self.total,
            "accepted":     self.accepted,
            "rejected":     self.rejected,
            "success":      self.success,
            "error":        self.error,
        }


# ── Verifier ──────────────────────────────────────────────────────────────────

class Verifier:
    """
    Verifies .tfb bundles and stores accepted IOCs.

    Usage:
        v = Verifier(recipient_rsa_priv=my_rsa_key)
        result = v.verify_bundle("data/feeds/abc123.tfb")
        print(result.summary())
    """

    def __init__(self, recipient_rsa_priv=None):
        """
        Args:
            recipient_rsa_priv: RSA private key for decrypting encrypted bundles.
                                None for signed-only bundles.
        """
        self.recipient_rsa_priv = recipient_rsa_priv
        self.ca          = CertificateAuthority()
        self.ioc_store   = IOCStore()
        self.nonce_store = NonceStore()
        self.pub_store   = PublisherStore()

    # ── Main entry point ──────────────────────────────────────────────────────

    def verify_bundle(self, bundle_path: str) -> FeedVerificationResult:
        """
        Full verification pipeline for a .tfb bundle file.
        Returns FeedVerificationResult with per-IOC breakdown.
        """
        path = Path(bundle_path)
        result = FeedVerificationResult(
            bundle_path=str(bundle_path),
            publisher_id="unknown",
        )

        # Load and parse bundle
        try:
            bundle = self._load_bundle(path)
        except Exception as e:
            result.error = f"Bundle load failed: {e}"
            log.error("Bundle load failed: %s — %s", bundle_path, e)
            return result

        result.publisher_id = bundle.get("publisher_id", "unknown")

        # Validate publisher certificate — applies to whole bundle
        cert_ok, cert_reason = self._validate_publisher(result.publisher_id)
        if not cert_ok:
            result.error = f"Publisher certificate invalid: {cert_reason}"
            log.warning("Bundle rejected — cert invalid: %s", cert_reason)
            return result

        # Get Ed25519 public key for this publisher
        try:
            ed_pub = self._get_ed25519_pub(result.publisher_id)
        except Exception as e:
            result.error = f"Could not load publisher Ed25519 key: {e}"
            return result

        # Verify each IOC individually
        iocs = bundle.get("iocs", [])
        result.total = len(iocs)

        for ioc_dict in iocs:
            ioc_result = self._verify_single_ioc(ioc_dict, ed_pub)
            result.ioc_results.append(ioc_result)
            if ioc_result.passed:
                result.accepted += 1
            else:
                result.rejected += 1

        log.info(
            "Bundle verified: %s — %d/%d accepted",
            bundle_path, result.accepted, result.total
        )
        return result

    # ── Single IOC verification ───────────────────────────────────────────────

    def _verify_single_ioc(self, ioc_dict: dict, ed_pub) -> IOCVerificationResult:
        """
        Verify one IOC through all five checks.
        Returns immediately on first failure — fail fast.
        """
        ioc_id = ioc_dict.get("ioc_id", "unknown")
        value  = ioc_dict.get("value",  "unknown")
        type_  = ioc_dict.get("type",   "unknown")

        def fail(step, reason):
            log.warning("IOC REJECTED [%s] %s — %s", step, ioc_id, reason)
            return IOCVerificationResult(
                ioc_id=ioc_id, value=value, type=type_,
                passed=False, reason=reason, step=step,
            )

        # Build IOCModel
        try:
            ioc = IOCModel.from_dict(ioc_dict)
        except Exception as e:
            return fail("parse", f"Invalid IOC schema: {e}")

        # Step 1 — Signature verification (Ed25519)
        if not verify_ioc(ed_pub, ioc):
            return fail(
                "signature",
                f"Ed25519 signature INVALID — IOC may have been tampered"
            )

        # Step 2 — Replay detection (nonce check)
        if is_replay(ioc.nonce, self.nonce_store):
            return fail(
                "replay",
                f"REPLAY ATTACK — nonce already seen: {ioc.nonce[:16]}..."
            )

        # Step 3 — Expiry check
        if ioc.is_expired():
            return fail("expiry", f"IOC has expired (ttl={ioc.ttl_seconds}s)")

        # Step 4 — Retraction check
        stored = self.ioc_store.get(ioc_id)
        if stored and self.ioc_store.get(ioc_id):
            from store.ioc_store import IOCStore
            with IOCStore()._connect() as conn:
                row = conn.execute(
                    "SELECT status FROM iocs WHERE ioc_id=?", (ioc_id,)
                ).fetchone()
                if row and row["status"] == "retracted":
                    return fail("retraction", "IOC has been retracted by publisher")

        # All checks passed — commit nonce and store IOC
        check_and_store_nonce(ioc.nonce, ioc.ioc_id, self.nonce_store)

        # Store if not already present
        try:
            self.ioc_store.insert(ioc)
        except Exception:
            pass  # Already in store from publisher side — that's fine

        log.info("IOC ACCEPTED: %s (%s %s)", ioc_id, type_, value)
        return IOCVerificationResult(
            ioc_id=ioc_id, value=value, type=type_,
            passed=True, reason="All checks passed", step="all_passed",
        )

    # ── Bundle loading ────────────────────────────────────────────────────────

    def _load_bundle(self, path: Path) -> dict:
        """
        Load and parse a .tfb bundle.
        Handles both encrypted and signed-only bundles.
        """
        raw = json.loads(path.read_text())

        if raw.get("encrypted"):
            # Encrypted bundle — decrypt first
            if not self.recipient_rsa_priv:
                raise ValueError(
                    "Bundle is encrypted but no RSA private key was provided"
                )
            plaintext = decrypt_feed(raw["payload"], self.recipient_rsa_priv)
            return json.loads(plaintext)
        else:
            # Signed-only bundle
            return raw

    # ── Publisher validation ──────────────────────────────────────────────────

    def _validate_publisher(self, publisher_id: str) -> tuple[bool, str]:
        """
        Validate publisher:
          1. Must be in registry and active
          2. Certificate chain must be valid
        """
        publisher = self.pub_store.get(publisher_id)
        if not publisher:
            return False, f"Publisher '{publisher_id}' not found or revoked"
        return self.ca.validate_publisher_cert(publisher.cert_path)

    def _get_ed25519_pub(self, publisher_id: str):
        """Get Ed25519 public key for IOC signature verification."""
        publisher = self.pub_store.get(publisher_id)
        if not publisher:
            raise ValueError(f"Publisher not found: {publisher_id}")
        return load_ed25519_public_from_b64(publisher.ed25519_pub_key)

    # ── Convenience: verify from dict (for testing/API) ──────────────────────

    def verify_ioc_dict(self, ioc_dict: dict, publisher_id: str) -> IOCVerificationResult:
        """
        Verify a single IOC dict without a .tfb file.
        Used by the dashboard and API.
        """
        cert_ok, cert_reason = self._validate_publisher(publisher_id)
        if not cert_ok:
            return IOCVerificationResult(
                ioc_id=ioc_dict.get("ioc_id", "unknown"),
                value=ioc_dict.get("value", "unknown"),
                type=ioc_dict.get("type", "unknown"),
                passed=False,
                reason=f"Publisher cert invalid: {cert_reason}",
                step="certificate",
            )
        ed_pub = self._get_ed25519_pub(publisher_id)
        return self._verify_single_ioc(ioc_dict, ed_pub)