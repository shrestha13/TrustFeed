"""
TrustFeed — Nonce Generation and Replay Detection
Algorithm: 96-bit random nonce (from technical diagram: "base64(96-bit random)")

The nonce serves two purposes:
  1. AES-GCM nonce — ensures ciphertext uniqueness per encryption
  2. IOC nonce     — replay attack prevention stored in SQLite

Replay attack flow:
  Publisher sends feed → verifier checks nonce → not seen → store nonce → process
  Attacker replays same feed → verifier checks nonce → SEEN → REJECT immediately
"""

import os
import base64
import logging
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import config
from store.nonce_store import NonceStore

log = logging.getLogger(__name__)


def generate_nonce() -> str:
    """
    Generate a cryptographically random 96-bit nonce.
    Returns base64-encoded string for JSON serialization.
    This is the format stored in IOC.nonce field.
    """
    raw = os.urandom(config.NONCE_SIZE_BYTES)  # 12 bytes = 96 bits
    return base64.b64encode(raw).decode("utf-8")


def check_and_store_nonce(nonce: str, ioc_id: str, store: NonceStore = None) -> bool:
    """
    Replay detection — atomic check-then-store.

    Returns True if nonce is fresh (first time seen) and stores it.
    Returns False if nonce was already seen — REPLAY ATTACK detected.

    Args:
        nonce:  The IOC nonce field value (base64 string)
        ioc_id: The IOC uuid — stored alongside nonce for audit trail
        store:  NonceStore instance (creates new one if not provided)

    Call this ONLY after all other verification passes.
    A nonce is only committed once a fully verified IOC is accepted.
    """
    if store is None:
        store = NonceStore()

    if store.is_seen(nonce):
        log.warning(
            "REPLAY ATTACK DETECTED — nonce already seen: %s (IOC: %s)",
            nonce[:16], ioc_id
        )
        return False

    store.mark_seen(nonce, ioc_id)
    log.debug("Nonce recorded for IOC: %s", ioc_id)
    return True


def is_replay(nonce: str, store: NonceStore = None) -> bool:
    """
    Check only — does not store. Use for pre-flight checks.
    Returns True if this is a replay (nonce seen before).
    """
    if store is None:
        store = NonceStore()
    return store.is_seen(nonce)