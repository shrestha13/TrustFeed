"""
TrustFeed — Trust Store
Loads and caches CA certificates for fast verification.
The verifier calls TrustStore to get root/intermediate certs
without reading disk on every IOC.
"""

import logging
from functools import cached_property

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

import config
from ca.certificate import load_cert, load_ed25519_public

log = logging.getLogger(__name__)


class TrustStore:
    """
    Thin cache over the on-disk CA certificates.
    Call invalidate() if CA is re-initialized.
    """

    @cached_property
    def root_cert(self):
        if not config.ROOT_CA_CERT_PATH.exists():
            raise RuntimeError("Root CA cert not found. Run: trustfeed ca init")
        cert = load_cert(config.ROOT_CA_CERT_PATH)
        log.debug("Root CA loaded: %s", cert.subject)
        return cert

    @cached_property
    def int_cert(self):
        if not config.INT_CA_CERT_PATH.exists():
            raise RuntimeError("Intermediate CA cert not found. Run: trustfeed ca init")
        cert = load_cert(config.INT_CA_CERT_PATH)
        log.debug("Intermediate CA loaded: %s", cert.subject)
        return cert

    def get_ed25519_pub(self, publisher_id: str):
        """Load Ed25519 public key for a publisher from disk."""
        path = config.CERTS_DIR / f"{publisher_id}.ed25519.pub.pem"
        if not path.exists():
            raise FileNotFoundError(
                f"Ed25519 public key not found for publisher: {publisher_id}"
            )
        return load_ed25519_public(path)

    def invalidate(self) -> None:
        """Clear cached certs — call after CA re-init."""
        self.__dict__.pop("root_cert", None)
        self.__dict__.pop("int_cert", None)
        log.debug("Trust store cache invalidated")