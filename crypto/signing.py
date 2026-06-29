"""
TrustFeed — Ed25519 Signing Module
Algorithm: Ed25519 (from technical diagram)

Why Ed25519:
  - Faster than RSA signatures
  - 64-byte signatures (vs 512 bytes RSA-4096)
  - Deterministic — no random number dependency
  - Side-channel resistant by design

Argument order: sign_ioc(private_key, ioc) — key first, data second.
"""

import base64
import logging
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.exceptions import InvalidSignature

log = logging.getLogger(__name__)


def sign(private_key: Ed25519PrivateKey, data: bytes) -> str:
    """Sign bytes with Ed25519. Returns base64 signature string."""
    raw_sig = private_key.sign(data)
    return base64.b64encode(raw_sig).decode("utf-8")


def verify(public_key: Ed25519PublicKey, data: bytes, signature_b64: str) -> bool:
    """Verify Ed25519 signature. Returns True if valid, False if tampered."""
    try:
        raw_sig = base64.b64decode(signature_b64)
        public_key.verify(raw_sig, data)
        return True
    except InvalidSignature:
        log.warning("Ed25519 signature verification FAILED — data tampered or wrong key")
        return False
    except Exception as e:
        log.error("Signature verification error: %s", e)
        return False


def sign_ioc(private_key: Ed25519PrivateKey, ioc) -> str:
    """
    Sign an IOCModel. Key first, IOC second.
    Calls ioc.canonical_bytes() for deterministic byte representation.
    Returns base64 signature — store as ioc.signature.
    """
    canonical = ioc.canonical_bytes()
    sig = sign(private_key, canonical)
    log.debug("IOC signed: %s", ioc.ioc_id)
    return sig


def verify_ioc(public_key: Ed25519PublicKey, ioc) -> bool:
    """
    Verify an IOCModel signature. Key first, IOC second.
    Recomputes canonical_bytes() and checks against ioc.signature.
    Returns False immediately if signature field is missing.
    """
    if not ioc.signature:
        log.warning("IOC %s has no signature field", ioc.ioc_id)
        return False
    canonical = ioc.canonical_bytes()
    result = verify(public_key, canonical, ioc.signature)
    if result:
        log.debug("IOC signature valid: %s", ioc.ioc_id)
    else:
        log.warning("IOC signature INVALID: %s", ioc.ioc_id)
    return result


def sign_retraction(private_key: Ed25519PrivateKey, retraction) -> str:
    """
    Sign a RetractionModel. Key first, retraction second.
    Same pattern as sign_ioc.
    """
    canonical = retraction.canonical_bytes()
    sig = sign(private_key, canonical)
    log.debug("Retraction signed: %s", retraction.retraction_id)
    return sig


def verify_retraction(public_key: Ed25519PublicKey, retraction) -> bool:
    """
    Verify a RetractionModel signature. Key first, retraction second.
    Confirms it came from the original publisher.
    """
    if not retraction.signature:
        log.warning("Retraction %s has no signature", retraction.retraction_id)
        return False
    canonical = retraction.canonical_bytes()
    result = verify(public_key, canonical, retraction.signature)
    if result:
        log.debug("Retraction signature valid: %s", retraction.retraction_id)
    else:
        log.warning("Retraction signature INVALID: %s", retraction.retraction_id)
    return result


def load_ed25519_private(path: str) -> Ed25519PrivateKey:
    """Load Ed25519 private key from PEM file path."""
    from pathlib import Path
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(Path(path).read_bytes(), None)


def load_ed25519_public_from_b64(b64_raw: str) -> Ed25519PublicKey:
    """
    Load Ed25519 public key from base64-encoded raw bytes.
    This is the format stored in the publisher registry.
    """
    raw = base64.b64decode(b64_raw)
    return Ed25519PublicKey.from_public_bytes(raw)