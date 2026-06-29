"""
TrustFeed — Publisher Module
Full IOC submission pipeline.

Flow:
  1. Authenticate publisher certificate (chain → Intermediate CA → Root CA → CRL)
  2. Load publisher's Ed25519 private key
  3. Accept IOC submission, attach nonce + timestamp
  4. Sign each IOC with Ed25519
  5. Encrypt feed bundle with AES-256-GCM + RSA-OAEP
  6. Save .tfb bundle to disk
  7. Store signed IOC in IOC store

Two modes (from architecture):
  Mode 1 — External feed: publisher submits pre-formed IOC list
  Mode 2 — Analyst submission: single IOC from local analyst
Both go through identical crypto pipeline.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import config
from ca.authority import CertificateAuthority
from ca.certificate import load_private_key, load_ed25519_private
from crypto.signing import sign_ioc
from crypto.encryption import encrypt_feed
from crypto.nonce import generate_nonce
from store.models import IOCModel
from store.ioc_store import IOCStore
from store.publisher_store import PublisherStore

log = logging.getLogger(__name__)


class Publisher:
    """
    Handles IOC submission for a single authenticated publisher.

    Usage:
        pub = Publisher("npcert-01")
        result = pub.submit_ioc(
            type="ipv4",
            value="185.220.101.45",
            severity="high",
            ttl_seconds=86400,
        )
    """

    def __init__(self, publisher_id: str):
        self.publisher_id  = publisher_id
        self.ca            = CertificateAuthority()
        self.ioc_store     = IOCStore()
        self.pub_store     = PublisherStore()
        self._publisher    = None
        self._ed25519_priv = None
        self._recipient_rsa_pub = None

    # ── Authentication ────────────────────────────────────────────────────────

    def authenticate(self) -> tuple[bool, str]:
        """
        Authenticate this publisher:
          1. Look up publisher in registry — must be active
          2. Validate their X.509 cert chain → Intermediate CA → Root CA
          3. Confirm cert not on CRL
          4. Load their Ed25519 private key

        Returns (success: bool, reason: str)
        """
        # Step 1 — publisher must be registered and active
        publisher = self.pub_store.get(self.publisher_id)
        if not publisher:
            return False, f"Publisher '{self.publisher_id}' not found or inactive"
        self._publisher = publisher

        # Step 2 — validate certificate chain
        valid, reason = self.ca.validate_publisher_cert(publisher.cert_path)
        if not valid:
            return False, f"Certificate validation failed: {reason}"

        # Step 3 — load Ed25519 signing key
        ed_priv_path = config.CERTS_DIR / f"{self.publisher_id}.ed25519.pem"
        if not ed_priv_path.exists():
            return False, f"Ed25519 private key not found: {ed_priv_path}"

        from cryptography.hazmat.primitives.serialization import load_pem_private_key
        self._ed25519_priv = load_pem_private_key(ed_priv_path.read_bytes(), None)

        log.info("Publisher authenticated: %s (tier %s)", self.publisher_id, publisher.tier)
        return True, "Authenticated"

    # ── Single IOC submission (Mode 2 — analyst) ──────────────────────────────

    def submit_ioc(
        self,
        type: str,
        value: str,
        severity: str,
        ttl_seconds: int = None,
        recipient_rsa_pub=None,
    ) -> dict:
        """
        Submit a single IOC. Authenticates, signs, stores, and returns bundle.

        Args:
            type:              IOC type — ipv4, domain, url, hash, email
            value:             The IOC value
            severity:          critical, high, medium, low
            ttl_seconds:       Time to live (default from config)
            recipient_rsa_pub: RSA public key to encrypt bundle for.
                               If None, bundle is signed-only (no encryption).

        Returns dict with ioc_id, bundle_path, and status.
        """
        # Authenticate first
        ok, reason = self.authenticate()
        if not ok:
            raise PermissionError(f"Authentication failed: {reason}")

        ttl = ttl_seconds or config.DEFAULT_TTL_SECS

        # Build IOC with nonce and timestamp
        ioc = IOCModel(
            type=type,
            value=value,
            severity=severity,
            ttl_seconds=ttl,
            publisher_id=self.publisher_id,
            nonce=generate_nonce(),
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Sign with Ed25519
        ioc.signature = sign_ioc(self._ed25519_priv, ioc)
        log.info("IOC signed: %s (%s %s)", ioc.ioc_id, ioc.type, ioc.value)

        # Store in IOC store
        self.ioc_store.insert(ioc)

        # Create feed bundle (list of one IOC)
        bundle_path = self._create_bundle([ioc], recipient_rsa_pub)

        return {
            "ioc_id":      ioc.ioc_id,
            "type":        ioc.type,
            "value":       ioc.value,
            "severity":    ioc.severity,
            "nonce":       ioc.nonce,
            "timestamp":   ioc.timestamp,
            "signature":   ioc.signature,
            "bundle_path": str(bundle_path),
            "status":      "published",
        }

    # ── Batch feed submission (Mode 1 — external feed) ────────────────────────

    def submit_feed(
        self,
        ioc_list: list[dict],
        recipient_rsa_pub=None,
    ) -> dict:
        """
        Submit a batch of IOCs as a single feed.
        Each IOC is signed individually — per-IOC signing from technical diagram.
        All are bundled into one encrypted .tfb file.

        Args:
            ioc_list: List of dicts with keys: type, value, severity, ttl_seconds
            recipient_rsa_pub: RSA public key for encryption

        Returns dict with count, ioc_ids, and bundle_path.
        """
        ok, reason = self.authenticate()
        if not ok:
            raise PermissionError(f"Authentication failed: {reason}")

        signed_iocs = []
        ioc_ids     = []

        for item in ioc_list:
            ioc = IOCModel(
                type=item["type"],
                value=item["value"],
                severity=item.get("severity", "medium"),
                ttl_seconds=item.get("ttl_seconds", config.DEFAULT_TTL_SECS),
                publisher_id=self.publisher_id,
                nonce=generate_nonce(),
                timestamp=datetime.now(timezone.utc).isoformat(),
            )
            # Sign each IOC individually
            ioc.signature = sign_ioc(self._ed25519_priv, ioc)
            self.ioc_store.insert(ioc)
            signed_iocs.append(ioc)
            ioc_ids.append(ioc.ioc_id)
            log.debug("IOC signed and stored: %s", ioc.ioc_id)

        bundle_path = self._create_bundle(signed_iocs, recipient_rsa_pub)
        log.info("Feed published: %d IOCs → %s", len(signed_iocs), bundle_path)

        return {
            "count":       len(signed_iocs),
            "ioc_ids":     ioc_ids,
            "bundle_path": str(bundle_path),
            "status":      "published",
        }

    # ── Bundle creation ───────────────────────────────────────────────────────

    def _create_bundle(self, iocs: list[IOCModel], recipient_rsa_pub=None) -> Path:
        """
        Create a .tfb (TrustFeed Bundle) file.

        Bundle structure:
        {
          "version":      "1.0",
          "publisher_id": "...",
          "issued_at":    "ISO-8601",
          "ioc_count":    N,
          "iocs":         [ {signed IOC dicts} ],
          "encrypted":    true/false
        }

        If recipient_rsa_pub is provided:
          → full JSON is AES-256-GCM encrypted, RSA-OAEP key wrapped
          → bundle file contains base64 encrypted payload

        If no key provided:
          → bundle is signed-only JSON (for local use / testing)
        """
        bundle_id = str(uuid.uuid4())
        bundle_data = {
            "version":      "1.0",
            "bundle_id":    bundle_id,
            "publisher_id": self.publisher_id,
            "issued_at":    datetime.now(timezone.utc).isoformat(),
            "ioc_count":    len(iocs),
            "iocs":         [ioc.to_dict() for ioc in iocs],
        }

        config.FEEDS_DIR.mkdir(parents=True, exist_ok=True)
        bundle_path = config.FEEDS_DIR / f"{bundle_id}{config.BUNDLE_EXTENSION}"

        if recipient_rsa_pub:
            # Encrypted bundle — AES-256-GCM + RSA-OAEP
            plaintext       = json.dumps(bundle_data, separators=(",", ":")).encode()
            encrypted_b64   = encrypt_feed(plaintext, recipient_rsa_pub)
            output = {
                "encrypted": True,
                "payload":   encrypted_b64,
            }
            bundle_path.write_text(json.dumps(output))
            log.debug("Bundle encrypted: %s", bundle_path)
        else:
            # Signed-only bundle (no recipient key)
            bundle_data["encrypted"] = False
            bundle_path.write_text(json.dumps(bundle_data, indent=2))
            log.debug("Bundle (unencrypted): %s", bundle_path)

        return bundle_path