"""
TrustFeed — Certificate Authority
Orchestrates the two-tier CA hierarchy and publisher onboarding.

Hierarchy (from technical diagram):
  Root CA (RSA-4096, offline, self-signed)
    └── Intermediate CA (ECDSA P-384, signed by Root)
          └── Publisher cert (ECDSA P-256, signed by Intermediate)
                └── Ed25519 keypair (IOC signing — separate from cert)

Usage:
    ca = CertificateAuthority()
    ca.init()                             # first-time setup
    pub = ca.issue_publisher("npcert-01", "NPCERT", tier=1)
    ca.revoke_publisher("npcert-01")
"""

import logging
import datetime
from pathlib import Path
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding as apadding

import sys, os
# FIX: Go up ONE level to the project root (CW/trustfeed/)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# FIX: Import config directly, do not use "from trustfeed import config"
import config 

from ca.certificate import (
    gen_rsa_4096, gen_ecdsa_p384, gen_ecdsa_p256, gen_ed25519,
    build_subject, build_root_ca_cert, build_intermediate_ca_cert,
    build_publisher_cert, save_private_key, save_cert,
    load_private_key, load_cert, save_ed25519_private,
    save_ed25519_public, load_ed25519_private, load_ed25519_public,
    ed25519_pub_b64,
)

from store.models import PublisherModel
from store.publisher_store import PublisherStore

log = logging.getLogger(__name__)


class CertificateAuthority:
    """
    Manages the full TrustFeed PKI lifecycle.
    All file paths come from config.py — never hardcoded here.
    """

    def __init__(self):
        self.pub_store = PublisherStore()

    # ── Initialisation ────────────────────────────────────────────────────────

    def is_initialized(self) -> bool:
        return (
            config.ROOT_CA_CERT_PATH.exists() and
            config.INT_CA_CERT_PATH.exists()
        )

    def init(self) -> dict:
        """
        Generate the full CA hierarchy from scratch.
        Call once. Raises if already initialized.
        Returns paths to generated files.
        """
        if self.is_initialized():
            raise RuntimeError(
                "CA already initialized. "
                "Delete data/ca/ to reinitialize."
            )

        log.info("Initializing TrustFeed CA hierarchy...")

        # 1. Root CA — RSA-4096, self-signed
        log.info("  Generating Root CA (RSA-4096)...")
        root_key = gen_rsa_4096()
        root_subject = build_subject(
            cn=config.CA_ROOT_CN,
            org=config.CA_ORGANIZATION,
            country=config.CA_COUNTRY,
        )
        root_cert = build_root_ca_cert(
            root_key, root_subject, config.ROOT_CA_VALIDITY_DAYS
        )
        save_private_key(root_key, config.ROOT_CA_KEY_PATH)
        save_cert(root_cert, config.ROOT_CA_CERT_PATH)
        log.info("  Root CA saved: %s", config.ROOT_CA_CERT_PATH)

        # 2. Intermediate CA — ECDSA P-384, signed by Root
        log.info("  Generating Intermediate CA (ECDSA P-384)...")
        int_key = gen_ecdsa_p384()
        int_subject = build_subject(
            cn=config.CA_INT_CN,
            org=config.CA_ORGANIZATION,
            country=config.CA_COUNTRY,
        )
        int_cert = build_intermediate_ca_cert(
            int_key, root_key, root_cert,
            int_subject, config.INT_CA_VALIDITY_DAYS
        )
        save_private_key(int_key, config.INT_CA_KEY_PATH)
        save_cert(int_cert, config.INT_CA_CERT_PATH)
        log.info("  Intermediate CA saved: %s", config.INT_CA_CERT_PATH)

        # 3. Empty CRL from Intermediate CA
        self._write_crl(int_key, int_cert, revoked_serials=[])
        log.info("  CRL initialized: %s", config.CRL_PATH)

        log.info("CA initialization complete.")
        return {
            "root_ca_cert":  str(config.ROOT_CA_CERT_PATH),
            "int_ca_cert":   str(config.INT_CA_CERT_PATH),
            "crl":           str(config.CRL_PATH),
        }

    # ── Publisher issuance ────────────────────────────────────────────────────

    def issue_publisher(
        self,
        publisher_id: str,
        name: str,
        tier: int = 2,
    ) -> dict:
        """
        Issue a full publisher credential set:
          - ECDSA P-256 certificate (identity, signed by Intermediate CA)
          - Ed25519 keypair (IOC signing)
          - Register in publisher store

        Returns paths and publisher_id.
        """
        self._require_initialized()

        int_key  = load_private_key(config.INT_CA_KEY_PATH)
        int_cert = load_cert(config.INT_CA_CERT_PATH)

        # ECDSA P-256 publisher certificate
        pub_key  = gen_ecdsa_p256()
        subject  = build_subject(cn=publisher_id, org=name, country=config.CA_COUNTRY)
        pub_cert = build_publisher_cert(
            pub_key, int_key, int_cert,
            subject, config.PUBLISHER_CERT_VALIDITY_DAYS
        )

        # Save publisher cert + key
        cert_path    = config.CERTS_DIR / f"{publisher_id}.cert.pem"
        key_path     = config.CERTS_DIR / f"{publisher_id}.key.pem"
        save_cert(pub_cert, cert_path)
        save_private_key(pub_key, key_path)

        # Ed25519 signing keypair
        ed_key       = gen_ed25519()
        ed_priv_path = config.CERTS_DIR / f"{publisher_id}.ed25519.pem"
        ed_pub_path  = config.CERTS_DIR / f"{publisher_id}.ed25519.pub.pem"
        save_ed25519_private(ed_key, ed_priv_path)
        save_ed25519_public(ed_key, ed_pub_path)

        # Register in publisher store
        from datetime import timezone
        publisher = PublisherModel(
            publisher_id=publisher_id,
            name=name,
            tier=tier,
            cert_path=str(cert_path),
            ed25519_pub_key=ed25519_pub_b64(ed_key),
            registered_at=datetime.datetime.now(timezone.utc).isoformat(),
            is_active=True,
        )
        self.pub_store.register(publisher)

        log.info("Publisher issued: %s (tier %s)", publisher_id, tier)
        return {
            "publisher_id":   publisher_id,
            "cert":           str(cert_path),
            "key":            str(key_path),
            "ed25519_priv":   str(ed_priv_path),
            "ed25519_pub":    str(ed_pub_path),
            "tier":           tier,
        }

    # ── Revocation ────────────────────────────────────────────────────────────

    def revoke_publisher(self, publisher_id: str) -> bool:
        """
        Revoke a publisher:
          1. Add their cert serial to the CRL
          2. Mark as inactive in publisher store
        """
        self._require_initialized()

        cert_path = config.CERTS_DIR / f"{publisher_id}.cert.pem"
        if not cert_path.exists():
            log.warning("Revoke: cert not found for %s", publisher_id)
            return False

        pub_cert  = load_cert(cert_path)
        int_key   = load_private_key(config.INT_CA_KEY_PATH)
        int_cert  = load_cert(config.INT_CA_CERT_PATH)

        # Load existing revoked serials from CRL
        revoked = self._load_revoked_serials()
        revoked.append(pub_cert.serial_number)

        self._write_crl(int_key, int_cert, revoked)
        self.pub_store.revoke(publisher_id)

        log.warning("Publisher REVOKED: %s", publisher_id)
        return True

    # ── Certificate validation ────────────────────────────────────────────────

    def validate_publisher_cert(self, cert_path: str) -> tuple[bool, str]:
        """
        Validate a publisher certificate:
          1. Signature chains to Intermediate CA
          2. Intermediate CA chains to Root CA
          3. Certificate not expired
          4. Serial not on CRL

        Returns (is_valid: bool, reason: str)
        """
        self._require_initialized()

        try:
            pub_cert  = load_cert(Path(cert_path))
            int_cert  = load_cert(config.INT_CA_CERT_PATH)
            root_cert = load_cert(config.ROOT_CA_CERT_PATH)
        except Exception as e:
            return False, f"Failed to load certificates: {e}"

        # 1. Check publisher cert not expired
        now = datetime.datetime.now(datetime.timezone.utc)
        if now > pub_cert.not_valid_after_utc:
            return False, "Publisher certificate has expired"
        if now < pub_cert.not_valid_before_utc:
            return False, "Publisher certificate not yet valid"

        # 2. Verify publisher cert signed by Intermediate CA
        try:
            int_cert.public_key().verify(
                pub_cert.signature,
                pub_cert.tbs_certificate_bytes,
                ec.ECDSA(pub_cert.signature_hash_algorithm),
            )
        except Exception:
            return False, "Publisher cert signature invalid — not signed by Intermediate CA"

        # 3. Verify Intermediate CA signed by Root CA
        try:
            root_cert.public_key().verify(
                int_cert.signature,
                int_cert.tbs_certificate_bytes,
                apadding.PKCS1v15(),
                int_cert.signature_hash_algorithm,
            )
        except Exception:
            return False, "Intermediate CA cert invalid — not signed by Root CA"

        # 4. Check CRL
        revoked = self._load_revoked_serials()
        if pub_cert.serial_number in revoked:
            return False, f"Certificate REVOKED (serial {pub_cert.serial_number})"

        return True, "Certificate valid"

    # ── CRL helpers ───────────────────────────────────────────────────────────

    def _write_crl(self, int_key, int_cert: x509.Certificate, revoked_serials: list) -> None:
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(int_cert.subject)
            .last_update(now)
            .next_update(now + datetime.timedelta(days=30))
        )
        for serial in revoked_serials:
            builder = builder.add_revoked_certificate(
                x509.RevokedCertificateBuilder()
                .serial_number(serial)
                .revocation_date(now)
                .build()
            )
        crl = builder.sign(int_key, hashes.SHA256())
        config.CRL_PATH.write_bytes(crl.public_bytes(serialization.Encoding.PEM))

    def _load_revoked_serials(self) -> list:
        if not config.CRL_PATH.exists():
            return []
        from cryptography.x509 import load_pem_x509_crl
        crl = load_pem_x509_crl(config.CRL_PATH.read_bytes())
        return [r.serial_number for r in crl]

    def _require_initialized(self) -> None:
        if not self.is_initialized():
            raise RuntimeError("CA not initialized. Run: trustfeed ca init")

    # ── Info ──────────────────────────────────────────────────────────────────

    def info(self) -> dict:
        """Return CA status summary."""
        if not self.is_initialized():
            return {"initialized": False}
        root_cert = load_cert(config.ROOT_CA_CERT_PATH)
        int_cert  = load_cert(config.INT_CA_CERT_PATH)
        revoked   = self._load_revoked_serials()
        return {
            "initialized":       True,
            "root_ca_cn":        root_cert.subject.get_attributes_for_oid(
                                    x509.oid.NameOID.COMMON_NAME)[0].value,
            "root_ca_expires":   root_cert.not_valid_after_utc.isoformat(),
            "int_ca_cn":         int_cert.subject.get_attributes_for_oid(
                                    x509.oid.NameOID.COMMON_NAME)[0].value,
            "int_ca_expires":    int_cert.not_valid_after_utc.isoformat(),
            "revoked_count":     len(revoked),
            "publishers":        len(self.pub_store.get_all()),
        }