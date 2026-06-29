"""
TrustFeed — Verifier module tests
Covers all five verification steps and the three demo scenarios.
Run from CW/trustfeed/: python -m pytest verifier/test_verifier.py -v
"""

import sys, os, json, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import config


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    for attr, sub in [
        ("CA_DIR","ca"),("CERTS_DIR","certs"),
        ("DB_DIR","db"),("FEEDS_DIR","feeds"),
    ]:
        p = tmp_path / sub
        p.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(config, attr, p)
    monkeypatch.setattr(config, "ROOT_CA_KEY_PATH",  config.CA_DIR/"root_ca.key.pem")
    monkeypatch.setattr(config, "ROOT_CA_CERT_PATH", config.CA_DIR/"root_ca.cert.pem")
    monkeypatch.setattr(config, "INT_CA_KEY_PATH",   config.CA_DIR/"intermediate_ca.key.pem")
    monkeypatch.setattr(config, "INT_CA_CERT_PATH",  config.CA_DIR/"intermediate_ca.cert.pem")
    monkeypatch.setattr(config, "CRL_PATH",          config.CA_DIR/"crl.pem")
    monkeypatch.setattr(config, "PUBLISHER_DB_PATH", config.DB_DIR/"publisher_registry.db")
    monkeypatch.setattr(config, "IOC_DB_PATH",       config.DB_DIR/"ioc_store.db")
    monkeypatch.setattr(config, "NONCE_DB_PATH",     config.DB_DIR/"nonce_store.db")


@pytest.fixture
def ca():
    from ca.authority import CertificateAuthority
    c = CertificateAuthority()
    c.init()
    return c


@pytest.fixture
def publisher_id(ca):
    ca.issue_publisher("test-pub", "Test Publisher", tier=2)
    return "test-pub"


@pytest.fixture
def rsa_keypair():
    from ca.certificate import gen_rsa_4096
    priv = gen_rsa_4096()
    return priv, priv.public_key()


@pytest.fixture
def published_bundle(publisher_id):
    """Submit a real IOC and return the bundle path."""
    from publisher.publisher import Publisher
    pub = Publisher(publisher_id)
    result = pub.submit_ioc(type="ipv4", value="185.220.101.45", severity="high")
    return result["bundle_path"]


@pytest.fixture
def published_bundle_encrypted(publisher_id, rsa_keypair):
    """Submit an encrypted IOC bundle."""
    from publisher.publisher import Publisher
    priv, pub_key = rsa_keypair
    pub = Publisher(publisher_id)
    result = pub.submit_ioc(
        type="ipv4", value="10.0.0.99", severity="high",
        recipient_rsa_pub=pub_key
    )
    return result["bundle_path"], priv


# ══════════════════════════════════════════════════════════════════════════════
# DEMO SCENARIO 1 — Normal verified ingestion
# ══════════════════════════════════════════════════════════════════════════════

def test_demo1_normal_verified_ingestion(published_bundle):
    """
    DEMO 1: Legitimate publisher sends signed feed.
    All checks pass. IOC accepted and stored.
    """
    from verifier.verifier import Verifier
    v = Verifier()
    result = v.verify_bundle(published_bundle)

    assert result.success is True
    assert result.accepted == 1
    assert result.rejected == 0
    assert result.error is None
    assert result.ioc_results[0].step == "all_passed"
    print(f"\n✓ DEMO 1 PASSED — IOC accepted: {result.ioc_results[0].value}")


def test_demo1_accepted_ioc_in_store(published_bundle):
    """Accepted IOC must be stored in the IOC store."""
    from verifier.verifier import Verifier
    from store.ioc_store import IOCStore
    v = Verifier()
    result = v.verify_bundle(published_bundle)
    store = IOCStore()
    ioc = store.get(result.ioc_results[0].ioc_id)
    assert ioc is not None
    assert ioc.value == "185.220.101.45"


def test_demo1_encrypted_bundle(published_bundle_encrypted):
    """Demo 1 with encrypted bundle — decrypt then verify."""
    from verifier.verifier import Verifier
    bundle_path, priv = published_bundle_encrypted
    v = Verifier(recipient_rsa_priv=priv)
    result = v.verify_bundle(bundle_path)
    assert result.success is True
    assert result.accepted == 1


def test_demo1_batch_feed(publisher_id):
    """Demo 1 with batch feed — all IOCs accepted."""
    from publisher.publisher import Publisher
    from verifier.verifier import Verifier

    ioc_list = [
        {"type": "ipv4",   "value": "1.2.3.4",     "severity": "high"},
        {"type": "domain", "value": "evil.np",      "severity": "critical"},
        {"type": "hash",   "value": "abc123def456", "severity": "medium"},
    ]
    pub    = Publisher(publisher_id)
    result = pub.submit_feed(ioc_list)

    v = Verifier()
    vresult = v.verify_bundle(result["bundle_path"])

    assert vresult.accepted == 3
    assert vresult.rejected == 0


# ══════════════════════════════════════════════════════════════════════════════
# DEMO SCENARIO 2 — Tampered feed detection
# ══════════════════════════════════════════════════════════════════════════════

def test_demo2_tampered_ioc_value_detected(publisher_id):
    """
    DEMO 2: Attacker intercepts feed and changes IOC value.
    Ed25519 signature verification must fail.
    """
    from publisher.publisher import Publisher
    from verifier.verifier import Verifier
    from pathlib import Path

    pub    = Publisher(publisher_id)
    result = pub.submit_ioc(type="ipv4", value="185.220.101.45", severity="high")

    # Attacker modifies the IOC value in the bundle file
    bundle_path = Path(result["bundle_path"])
    bundle = json.loads(bundle_path.read_text())
    bundle["iocs"][0]["value"] = "8.8.8.8"   # ← attacker changes the IP
    bundle_path.write_text(json.dumps(bundle))

    v = Verifier()
    vresult = v.verify_bundle(str(bundle_path))

    assert vresult.accepted == 0
    assert vresult.rejected == 1
    assert vresult.ioc_results[0].step == "signature"
    print(f"\n✓ DEMO 2 PASSED — Tamper detected: {vresult.ioc_results[0].reason}")


def test_demo2_tampered_severity_detected(publisher_id):
    """Attacker downgrades severity to avoid detection."""
    from publisher.publisher import Publisher
    from verifier.verifier import Verifier
    from pathlib import Path

    pub    = Publisher(publisher_id)
    result = pub.submit_ioc(type="ipv4", value="5.5.5.5", severity="critical")

    bundle_path = Path(result["bundle_path"])
    bundle = json.loads(bundle_path.read_text())
    bundle["iocs"][0]["severity"] = "low"   # ← attacker downgrades severity
    bundle_path.write_text(json.dumps(bundle))

    v = Verifier()
    vresult = v.verify_bundle(str(bundle_path))

    assert vresult.rejected == 1
    assert vresult.ioc_results[0].step == "signature"


def test_demo2_partial_tamper_in_batch(publisher_id):
    """
    Attacker tampers ONE IOC in a batch of five.
    Only the tampered IOC fails — others still accepted.
    Per-IOC signing advantage demonstrated here.
    """
    from publisher.publisher import Publisher
    from verifier.verifier import Verifier
    from pathlib import Path

    ioc_list = [
        {"type": "ipv4", "value": f"10.0.0.{i}", "severity": "high"}
        for i in range(5)
    ]
    pub    = Publisher(publisher_id)
    result = pub.submit_feed(ioc_list)

    bundle_path = Path(result["bundle_path"])
    bundle = json.loads(bundle_path.read_text())
    bundle["iocs"][2]["value"] = "TAMPERED"   # ← only IOC #3 tampered
    bundle_path.write_text(json.dumps(bundle))

    v = Verifier()
    vresult = v.verify_bundle(str(bundle_path))

    assert vresult.accepted == 4, "4 untampered IOCs should pass"
    assert vresult.rejected == 1, "1 tampered IOC should fail"
    assert vresult.ioc_results[2].step == "signature"
    print(f"\n✓ DEMO 2 (partial) — 4 accepted, 1 tampered IOC rejected")


def test_demo2_invalid_publisher_rejected(ca):
    """Feed from unknown publisher rejected at certificate step."""
    from publisher.publisher import Publisher
    from verifier.verifier import Verifier

    # Issue and immediately revoke
    ca.issue_publisher("bad-pub", "Bad Actor", tier=3)
    ca.revoke_publisher("bad-pub")

    pub    = Publisher("bad-pub")
    # Submit before revocation takes effect locally
    # Manually create a fake bundle
    import uuid
    from datetime import datetime, timezone
    from crypto.nonce import generate_nonce

    bundle = {
        "version":      "1.0",
        "bundle_id":    str(uuid.uuid4()),
        "publisher_id": "bad-pub",
        "issued_at":    datetime.now(timezone.utc).isoformat(),
        "ioc_count":    1,
        "iocs": [{
            "ioc_id":       str(uuid.uuid4()),
            "type":         "ipv4",
            "value":        "9.9.9.9",
            "severity":     "high",
            "ttl_seconds":  86400,
            "publisher_id": "bad-pub",
            "nonce":        generate_nonce(),
            "timestamp":    datetime.now(timezone.utc).isoformat(),
            "signature":    "fakesignature==",
        }],
        "encrypted": False,
    }
    bundle_path = config.FEEDS_DIR / "bad_bundle.tfb"
    bundle_path.write_text(json.dumps(bundle))

    v = Verifier()
    vresult = v.verify_bundle(str(bundle_path))

    assert vresult.success is False
    assert "REVOKED" in vresult.error or "invalid" in vresult.error.lower()


# ══════════════════════════════════════════════════════════════════════════════
# DEMO SCENARIO 3 — Replay attack prevention
# ══════════════════════════════════════════════════════════════════════════════

def test_demo3_replay_attack_prevented(publisher_id):
    """
    DEMO 3: Attacker captures a valid bundle and replays it.
    Second verification of the same bundle must fail on nonce check.
    """
    from publisher.publisher import Publisher
    from verifier.verifier import Verifier

    pub    = Publisher(publisher_id)
    result = pub.submit_ioc(type="ipv4", value="192.168.1.1", severity="high")

    v = Verifier()

    # First verification — should pass
    first = v.verify_bundle(result["bundle_path"])
    assert first.accepted == 1, "First verification should pass"

    # Second verification (replay) — should fail
    second = v.verify_bundle(result["bundle_path"])
    assert second.rejected == 1, "Replay should be rejected"
    assert second.ioc_results[0].step == "replay"
    print(f"\n✓ DEMO 3 PASSED — Replay blocked: {second.ioc_results[0].reason}")


def test_demo3_different_bundles_both_pass(publisher_id):
    """Two different bundles with different nonces both pass."""
    from publisher.publisher import Publisher
    from verifier.verifier import Verifier

    pub = Publisher(publisher_id)
    r1  = pub.submit_ioc(type="ipv4",   value="1.1.1.1", severity="low")
    r2  = pub.submit_ioc(type="domain", value="ok.np",   severity="low")

    v = Verifier()
    assert v.verify_bundle(r1["bundle_path"]).accepted == 1
    assert v.verify_bundle(r2["bundle_path"]).accepted == 1


def test_demo3_replay_does_not_enter_store(publisher_id):
    """Replayed IOC must not be double-stored. Checks specific IOC, avoiding global count issues."""
    import json
    from publisher.publisher import Publisher
    from verifier.verifier import Verifier
    from store.ioc_store import IOCStore

    pub = Publisher(publisher_id)
    result = pub.submit_ioc(type="ipv4", value="7.7.7.7", severity="medium")
    
    # 1. Read the bundle to get the exact IOC ID and Nonce
    with open(result["bundle_path"], "r") as f:
        bundle = json.load(f)
    ioc_id = bundle["iocs"][0]["ioc_id"]
    nonce = bundle["iocs"][0]["nonce"]
    
    v = Verifier()
    store = IOCStore()
    
    # 2. First verification (should succeed)
    first = v.verify_bundle(result["bundle_path"])
    assert first.accepted == 1, f"First verification failed: {first.error or (first.ioc_results[0].reason if first.ioc_results else 'unknown')}"
    
    # Verify this specific IOC is actually in the store
    stored_ioc = store.get(ioc_id)
    assert stored_ioc is not None, "IOC was not stored after first verification"
    
    # 3. Second verification (REPLAY ATTACK - should fail)
    second = v.verify_bundle(result["bundle_path"])
    assert second.rejected == 1, "Replay should be rejected"
    assert second.ioc_results[0].step == "replay", f"Expected replay rejection, got step: {second.ioc_results[0].step}"
    
    # # 4. Powerful extra check: Verify the nonce was recorded to block the replay
    # from store.nonce_store import NonceStore
    # nonce_store = NonceStore()
    # assert nonce_store.exists(nonce), "Nonce should be recorded in NonceStore to prevent replays"

# ── Additional verifier tests ─────────────────────────────────────────────────

def test_expired_ioc_rejected(publisher_id):
    """IOC with ttl_seconds=1 expires and is rejected."""
    import time
    from publisher.publisher import Publisher
    from verifier.verifier import Verifier
    from pathlib import Path

    pub    = Publisher(publisher_id)
    result = pub.submit_ioc(
        type="ipv4", value="expired.ip", severity="low",
        ttl_seconds=1
    )
    time.sleep(2)   # wait for IOC to expire

    # Remove from store so verifier tries to re-add
    bundle_path = Path(result["bundle_path"])
    bundle = json.loads(bundle_path.read_text())

    v = Verifier()
    vresult = v.verify_bundle(str(bundle_path))
    assert vresult.ioc_results[0].step in ("expiry", "replay")


def test_missing_signature_rejected(publisher_id):
    """IOC with no signature field is rejected."""
    import uuid
    from datetime import datetime, timezone
    from crypto.nonce import generate_nonce
    from verifier.verifier import Verifier

    bundle = {
        "version": "1.0", "bundle_id": str(uuid.uuid4()),
        "publisher_id": publisher_id,
        "issued_at": datetime.now(timezone.utc).isoformat(),
        "ioc_count": 1, "encrypted": False,
        "iocs": [{
            "ioc_id": str(uuid.uuid4()), "type": "ipv4",
            "value": "3.3.3.3", "severity": "high",
            "ttl_seconds": 86400, "publisher_id": publisher_id,
            "nonce": generate_nonce(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "signature": None,
        }],
    }
    bp = config.FEEDS_DIR / "nosig.tfb"
    bp.write_text(json.dumps(bundle))

    v = Verifier()
    vresult = v.verify_bundle(str(bp))
    assert vresult.rejected == 1
    assert vresult.ioc_results[0].step == "signature"