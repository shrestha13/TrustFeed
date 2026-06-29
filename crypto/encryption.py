"""
TrustFeed — Hybrid Encryption Module
Algorithm: AES-256-GCM + RSA-OAEP (from technical diagram)

Flow:
  Encrypt:
    1. Generate random 256-bit AES session key
    2. Encrypt plaintext with AES-256-GCM → ciphertext + auth tag
    3. Encrypt AES key with recipient RSA public key (OAEP+SHA-256)
    4. Bundle: {ciphertext, nonce, tag, encrypted_key} → JSON → base64

  Decrypt:
    1. Decode and parse bundle
    2. Decrypt AES key with RSA private key (OAEP+SHA-256)
    3. Decrypt ciphertext with AES-256-GCM
    4. GCM auth tag verified automatically — tamper detected here

Why AES-256-GCM:
  - Authenticated encryption: confidentiality + integrity in one pass
  - GCM auth tag catches any ciphertext tampering before decryption
  - CBC requires separate HMAC and is vulnerable to padding oracle attacks

Why RSA-OAEP:
  - Provably secure padding
  - PKCS#1 v1.5 is vulnerable to Bleichenbacher attacks
"""

import os
import json
import base64
import logging

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey, RSAPublicKey

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import config

log = logging.getLogger(__name__)


def encrypt_feed(plaintext: bytes, recipient_rsa_pub: RSAPublicKey) -> str:
    """
    Encrypt a feed payload using AES-256-GCM + RSA-OAEP hybrid scheme.

    Args:
        plaintext:         Raw bytes to encrypt (JSON-serialized IOC list)
        recipient_rsa_pub: Recipient's RSA public key for key wrapping

    Returns:
        base64-encoded JSON bundle string (the .tfb payload)

    Bundle structure:
        {
          "ciphertext":     base64(AES-GCM encrypted data),
          "nonce":          base64(96-bit GCM nonce),
          "encrypted_key":  base64(RSA-OAEP wrapped AES key)
        }
    Note: GCM auth tag is appended to ciphertext automatically by AESGCM.
    """
    # Step 1 — Generate random AES-256 session key (32 bytes = 256 bits)
    aes_key = os.urandom(config.AES_KEY_SIZE)

    # Step 2 — Generate random 96-bit nonce (12 bytes) for GCM
    nonce = os.urandom(config.AES_NONCE_SIZE)

    # Step 3 — AES-256-GCM encrypt
    # AESGCM appends the 128-bit auth tag to the ciphertext automatically
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    # Step 4 — RSA-OAEP wrap the AES session key
    encrypted_key = recipient_rsa_pub.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        )
    )

    # Step 5 — Bundle as base64 JSON
    bundle = {
        "ciphertext":    base64.b64encode(ciphertext).decode(),
        "nonce":         base64.b64encode(nonce).decode(),
        "encrypted_key": base64.b64encode(encrypted_key).decode(),
    }
    bundle_json = json.dumps(bundle, separators=(",", ":")).encode()
    log.debug("Feed encrypted: %d bytes plaintext → %d bytes bundle",
              len(plaintext), len(bundle_json))
    return base64.b64encode(bundle_json).decode()


def decrypt_feed(bundle_b64: str, recipient_rsa_priv: RSAPrivateKey) -> bytes:
    """
    Decrypt a feed bundle using RSA-OAEP + AES-256-GCM.

    Args:
        bundle_b64:        base64-encoded bundle string from encrypt_feed()
        recipient_rsa_priv: Recipient's RSA private key

    Returns:
        Original plaintext bytes

    Raises:
        ValueError: if bundle is malformed
        cryptography.exceptions.InvalidTag: if GCM auth tag fails
                                            (ciphertext was tampered)
    """
    # Step 1 — Decode bundle
    try:
        bundle_json = base64.b64decode(bundle_b64)
        bundle = json.loads(bundle_json)
        ciphertext    = base64.b64decode(bundle["ciphertext"])
        nonce         = base64.b64decode(bundle["nonce"])
        encrypted_key = base64.b64decode(bundle["encrypted_key"])
    except Exception as e:
        raise ValueError(f"Malformed feed bundle: {e}")

    # Step 2 — RSA-OAEP unwrap AES session key
    try:
        aes_key = recipient_rsa_priv.decrypt(
            encrypted_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )
    except Exception as e:
        raise ValueError(f"RSA-OAEP key decryption failed: {e}")

    # Step 3 — AES-256-GCM decrypt
    # AESGCM verifies the auth tag automatically.
    # If ciphertext was tampered, cryptography.exceptions.InvalidTag is raised.
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    log.debug("Feed decrypted: %d bytes", len(plaintext))
    return plaintext


def load_rsa_private(path: str) -> RSAPrivateKey:
    """Load RSA private key from PEM file."""
    from pathlib import Path
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(Path(path).read_bytes(), None)


def load_rsa_public_from_cert(cert_path: str) -> RSAPublicKey:
    """
    Extract RSA public key from an X.509 certificate PEM file.
    Used when encrypting feeds for a specific SOC recipient.
    """
    from pathlib import Path
    from cryptography.x509 import load_pem_x509_certificate
    cert = load_pem_x509_certificate(Path(cert_path).read_bytes())
    return cert.public_key()