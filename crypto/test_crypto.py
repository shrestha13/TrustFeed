"""
TrustFeed — Crypto module tests
Covers: Ed25519 signing, AES-256-GCM encryption, RSA-OAEP key wrap, nonce replay.
Run from CW/trustfeed/: python -m pytest crypto/test_crypto.py -v
"""

import sys, os, pytest, base64
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import config


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "DB_DIR", tmp_path / "db")
    config.DB_DIR.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "NONCE_DB_PATH", config.DB_DIR / "nonce_store.db")


@pytest.fixture
def ed25519_keypair():
    from ca.certificate import gen_ed25519
    priv = gen_ed25519()
    pub  = priv.public_key()
    return priv, pub


@pytest.fixture
def rsa_keypair():
    from ca.certificate import gen_rsa_4096
    priv = gen_rsa_4096()
    pub  = priv.public_key()
    return priv, pub


@pytest.fixture
def sample_ioc():
    from datetime import datetime, timezone
    from store.models import IOCModel
    from crypto.nonce import generate_nonce
    return IOCModel(
        type="ipv4",
        value="185.220.101.45",
        severity="high",
        publisher_id="test-publisher",
        nonce=generate_nonce(),
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


@pytest.fixture
def sample_retraction(sample_ioc):
    from datetime import datetime, timezone
    from store.models import RetractionModel
    return RetractionModel(
        ioc_id=sample_ioc.ioc_id,
        publisher_id=sample_ioc.publisher_id,
        reason="False positive — legitimate NTC IP",
        timestamp=datetime.now(timezone.utc).isoformat(),
    )


# ── Nonce tests ───────────────────────────────────────────────────────────────

def test_nonce_is_base64(tmp_db):
    from crypto.nonce import generate_nonce
    nonce = generate_nonce()
    decoded = base64.b64decode(nonce)
    assert len(decoded) == 12, "Nonce must be 96 bits (12 bytes)"


def test_nonce_is_unique(tmp_db):
    from crypto.nonce import generate_nonce
    nonces = {generate_nonce() for _ in range(100)}
    assert len(nonces) == 100, "Nonces must be unique"


def test_replay_detection_blocks_second_use(tmp_db):
    from crypto.nonce import generate_nonce, check_and_store_nonce
    from store.nonce_store import NonceStore
    store = NonceStore()
    nonce = generate_nonce()
    assert check_and_store_nonce(nonce, "ioc-001", store) is True
    assert check_and_store_nonce(nonce, "ioc-001", store) is False


def test_different_nonces_both_accepted(tmp_db):
    from crypto.nonce import generate_nonce, check_and_store_nonce
    from store.nonce_store import NonceStore
    store = NonceStore()
    n1 = generate_nonce()
    n2 = generate_nonce()
    assert check_and_store_nonce(n1, "ioc-001", store) is True
    assert check_and_store_nonce(n2, "ioc-002", store) is True


# ── Ed25519 signing tests ─────────────────────────────────────────────────────

def test_sign_and_verify_ioc(ed25519_keypair, sample_ioc):
    from crypto.signing import sign_ioc, verify_ioc
    priv, pub = ed25519_keypair
    sample_ioc.signature = sign_ioc(priv, sample_ioc)
    assert sample_ioc.signature is not None
    assert verify_ioc(pub, sample_ioc) is True


def test_tampered_ioc_fails_verification(ed25519_keypair, sample_ioc):
    """
    Attack simulation: attacker modifies IOC value after signing.
    Signature verification must fail.
    """
    from crypto.signing import sign_ioc, verify_ioc
    priv, pub = ed25519_keypair
    sample_ioc.signature = sign_ioc(priv, sample_ioc)

    # Attacker tampers with the IOC value
    sample_ioc.value = "8.8.8.8"

    assert verify_ioc(pub, sample_ioc) is False, \
        "SECURITY FAIL: tampered IOC passed verification"


def test_wrong_key_fails_verification(ed25519_keypair, sample_ioc):
    """
    Attack simulation: attacker uses wrong public key to verify.
    Must fail — ensures publisher identity is checked correctly.
    """
    from crypto.signing import sign_ioc, verify_ioc
    from ca.certificate import gen_ed25519
    priv, pub = ed25519_keypair
    wrong_priv = gen_ed25519()
    wrong_pub  = wrong_priv.public_key()

    sample_ioc.signature = sign_ioc(priv, sample_ioc)
    assert verify_ioc(wrong_pub, sample_ioc) is False, \
        "SECURITY FAIL: wrong key accepted as valid"


def test_missing_signature_fails(ed25519_keypair, sample_ioc):
    from crypto.signing import verify_ioc
    _, pub = ed25519_keypair
    assert verify_ioc(pub, sample_ioc) is False


def test_sign_and_verify_retraction(ed25519_keypair, sample_retraction):
    from crypto.signing import sign_retraction, verify_retraction
    priv, pub = ed25519_keypair
    sample_retraction.signature = sign_retraction(priv, sample_retraction)
    assert verify_retraction(pub, sample_retraction) is True


def test_tampered_retraction_fails(ed25519_keypair, sample_retraction):
    from crypto.signing import sign_retraction, verify_retraction
    priv, pub = ed25519_keypair
    sample_retraction.signature = sign_retraction(priv, sample_retraction)
    sample_retraction.reason = "INJECTED REASON"
    assert verify_retraction(pub, sample_retraction) is False


def test_canonical_bytes_deterministic(sample_ioc):
    """Same IOC must always produce same bytes — signing depends on this."""
    b1 = sample_ioc.canonical_bytes()
    b2 = sample_ioc.canonical_bytes()
    assert b1 == b2


def test_load_ed25519_from_b64(ed25519_keypair, sample_ioc):
    """Round-trip: raw b64 → Ed25519PublicKey → verify."""
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    from crypto.signing import sign_ioc, load_ed25519_public_from_b64
    priv, pub = ed25519_keypair
    sample_ioc.signature = sign_ioc(priv, sample_ioc)
    raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    b64 = base64.b64encode(raw).decode()
    loaded_pub = load_ed25519_public_from_b64(b64)
    from crypto.signing import verify_ioc
    assert verify_ioc(loaded_pub, sample_ioc) is True


# ── AES-256-GCM + RSA-OAEP encryption tests ──────────────────────────────────

def test_encrypt_and_decrypt(rsa_keypair):
    from crypto.encryption import encrypt_feed, decrypt_feed
    priv, pub = rsa_keypair
    plaintext = b'{"iocs": [{"value": "185.220.101.45"}]}'
    bundle    = encrypt_feed(plaintext, pub)
    recovered = decrypt_feed(bundle, priv)
    assert recovered == plaintext


def test_encrypted_bundle_is_base64(rsa_keypair):
    from crypto.encryption import encrypt_feed
    _, pub = rsa_keypair
    bundle = encrypt_feed(b"test payload", pub)
    decoded = base64.b64decode(bundle)
    import json
    parsed = json.loads(decoded)
    assert "ciphertext" in parsed
    assert "nonce" in parsed
    assert "encrypted_key" in parsed


def test_tampered_ciphertext_fails_decryption(rsa_keypair):
    """
    Attack simulation: attacker flips bits in ciphertext.
    AES-GCM auth tag must catch this.
    """
    import json
    from crypto.encryption import encrypt_feed, decrypt_feed
    from cryptography.exceptions import InvalidTag
    priv, pub = rsa_keypair
    bundle_b64 = encrypt_feed(b"sensitive feed data", pub)

    # Decode, tamper with ciphertext, re-encode
    bundle = json.loads(base64.b64decode(bundle_b64))
    ct     = base64.b64decode(bundle["ciphertext"])
    tampered = ct[:-1] + bytes([ct[-1] ^ 0xFF])  # flip last byte
    bundle["ciphertext"] = base64.b64encode(tampered).decode()
    tampered_b64 = base64.b64encode(
        json.dumps(bundle, separators=(",", ":")).encode()
    ).decode()

    with pytest.raises(Exception):  # InvalidTag or similar
        decrypt_feed(tampered_b64, priv)


def test_wrong_rsa_key_fails_decryption(rsa_keypair):
    """
    Attack simulation: wrong RSA private key cannot unwrap AES key.
    """
    from crypto.encryption import encrypt_feed, decrypt_feed
    priv, pub = rsa_keypair
    from ca.certificate import gen_rsa_4096
    wrong_priv = gen_rsa_4096()

    bundle = encrypt_feed(b"secret feed", pub)
    with pytest.raises(Exception):
        decrypt_feed(bundle, wrong_priv)


def test_encrypt_decrypt_large_payload(rsa_keypair):
    """AES-GCM handles bulk data — test with realistic feed size."""
    from crypto.encryption import encrypt_feed, decrypt_feed
    import json
    priv, pub = rsa_keypair
    iocs = [{"value": f"192.168.1.{i}", "type": "ipv4"} for i in range(200)]
    plaintext = json.dumps(iocs).encode()
    bundle    = encrypt_feed(plaintext, pub)
    recovered = decrypt_feed(bundle, priv)
    assert recovered == plaintext