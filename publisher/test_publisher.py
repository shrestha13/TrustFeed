"""
TrustFeed — Publisher module tests
Run from CW/trustfeed/: python -m pytest publisher/test_publisher.py -v
"""

import sys, os, json, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import config


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    """Redirect all paths to tmp for each test."""
    for attr, sub in [
        ("CA_DIR", "ca"), ("CERTS_DIR", "certs"),
        ("DB_DIR", "db"), ("FEEDS_DIR", "feeds"),
    ]:
        p = tmp_path / sub
        p.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(config, attr, p)

    monkeypatch.setattr(config, "ROOT_CA_KEY_PATH",  config.CA_DIR / "root_ca.key.pem")
    monkeypatch.setattr(config, "ROOT_CA_CERT_PATH", config.CA_DIR / "root_ca.cert.pem")
    monkeypatch.setattr(config, "INT_CA_KEY_PATH",   config.CA_DIR / "intermediate_ca.key.pem")
    monkeypatch.setattr(config, "INT_CA_CERT_PATH",  config.CA_DIR / "intermediate_ca.cert.pem")
    monkeypatch.setattr(config, "CRL_PATH",          config.CA_DIR / "crl.pem")
    monkeypatch.setattr(config, "PUBLISHER_DB_PATH", config.DB_DIR / "publisher_registry.db")
    monkeypatch.setattr(config, "IOC_DB_PATH",       config.DB_DIR / "ioc_store.db")
    monkeypatch.setattr(config, "NONCE_DB_PATH",     config.DB_DIR / "nonce_store.db")


@pytest.fixture
def ca(isolated):
    from ca.authority import CertificateAuthority
    ca = CertificateAuthority()
    ca.init()
    return ca


@pytest.fixture
def publisher_id(ca):
    ca.issue_publisher("test-pub", "Test Publisher", tier=2)
    return "test-pub"


@pytest.fixture
def rsa_keypair():
    from ca.certificate import gen_rsa_4096
    priv = gen_rsa_4096()
    return priv, priv.public_key()


# ── Authentication tests ──────────────────────────────────────────────────────

def test_authenticate_valid_publisher(publisher_id):
    from publisher.publisher import Publisher
    pub = Publisher(publisher_id)
    ok, reason = pub.authenticate()
    assert ok is True, f"Expected authenticated, got: {reason}"


def test_authenticate_unknown_publisher(ca):
    from publisher.publisher import Publisher
    pub = Publisher("does-not-exist")
    ok, reason = pub.authenticate()
    assert ok is False
    assert "not found" in reason


def test_authenticate_revoked_publisher(ca):
    ca.issue_publisher("revoked-pub", "Revoked", tier=2)
    ca.revoke_publisher("revoked-pub")
    from publisher.publisher import Publisher
    pub = Publisher("revoked-pub")
    ok, reason = pub.authenticate()
    assert ok is False


# ── Single IOC submission tests ───────────────────────────────────────────────

def test_submit_single_ioc(publisher_id):
    from publisher.publisher import Publisher
    pub    = Publisher(publisher_id)
    result = pub.submit_ioc(type="ipv4", value="185.220.101.45", severity="high")

    assert result["status"] == "published"
    assert result["ioc_id"] is not None
    assert result["signature"] is not None
    assert result["bundle_path"].endswith(".tfb")


def test_submitted_ioc_in_store(publisher_id):
    from publisher.publisher import Publisher
    from store.ioc_store import IOCStore
    pub    = Publisher(publisher_id)
    result = pub.submit_ioc(type="domain", value="malicious.np", severity="critical")

    store = IOCStore()
    ioc   = store.get(result["ioc_id"])
    assert ioc is not None
    assert ioc.value == "malicious.np"
    assert ioc.publisher_id == publisher_id


def test_submitted_ioc_has_valid_signature(publisher_id):
    """
    End-to-end: submit IOC then verify its signature with the
    publisher's Ed25519 public key from the registry.
    """
    from publisher.publisher import Publisher
    from store.ioc_store import IOCStore
    from store.publisher_store import PublisherStore
    from crypto.signing import verify_ioc, load_ed25519_public_from_b64

    pub    = Publisher(publisher_id)
    result = pub.submit_ioc(type="hash", value="abc123def456", severity="medium")

    ioc        = IOCStore().get(result["ioc_id"])
    pub_record = PublisherStore().get(publisher_id)
    ed_pub     = load_ed25519_public_from_b64(pub_record.ed25519_pub_key)

    assert verify_ioc(ed_pub, ioc) is True, "Stored IOC signature must be valid"


def test_bundle_file_created(publisher_id):
    from publisher.publisher import Publisher
    from pathlib import Path
    pub    = Publisher(publisher_id)
    result = pub.submit_ioc(type="ipv4", value="10.0.0.1", severity="low")
    assert Path(result["bundle_path"]).exists()


def test_bundle_contains_correct_ioc(publisher_id):
    from publisher.publisher import Publisher
    from pathlib import Path
    pub    = Publisher(publisher_id)
    result = pub.submit_ioc(type="ipv4", value="192.168.1.100", severity="high")

    bundle = json.loads(Path(result["bundle_path"]).read_text())
    assert bundle["encrypted"] is False
    assert bundle["ioc_count"] == 1
    assert bundle["iocs"][0]["value"] == "192.168.1.100"
    assert bundle["publisher_id"] == publisher_id


# ── Batch feed submission tests ───────────────────────────────────────────────

def test_submit_batch_feed(publisher_id):
    from publisher.publisher import Publisher
    ioc_list = [
        {"type": "ipv4",   "value": "1.2.3.4",      "severity": "high"},
        {"type": "domain", "value": "evil.np",       "severity": "critical"},
        {"type": "hash",   "value": "deadbeef1234",  "severity": "medium"},
    ]
    pub    = Publisher(publisher_id)
    result = pub.submit_feed(ioc_list)

    assert result["count"] == 3
    assert len(result["ioc_ids"]) == 3
    assert result["status"] == "published"


def test_batch_all_iocs_signed_and_stored(publisher_id):
    from publisher.publisher import Publisher
    from store.ioc_store import IOCStore
    from store.publisher_store import PublisherStore
    from crypto.signing import verify_ioc, load_ed25519_public_from_b64

    ioc_list = [
        {"type": "ipv4", "value": f"10.0.0.{i}", "severity": "high"}
        for i in range(5)
    ]
    pub    = Publisher(publisher_id)
    result = pub.submit_feed(ioc_list)

    store      = IOCStore()
    pub_record = PublisherStore().get(publisher_id)
    ed_pub     = load_ed25519_public_from_b64(pub_record.ed25519_pub_key)

    for ioc_id in result["ioc_ids"]:
        ioc = store.get(ioc_id)
        assert ioc is not None
        assert verify_ioc(ed_pub, ioc) is True, f"IOC {ioc_id} signature invalid"


# ── Encrypted bundle tests ────────────────────────────────────────────────────

def test_encrypted_bundle(publisher_id, rsa_keypair):
    from publisher.publisher import Publisher
    from pathlib import Path
    priv, pub_key = rsa_keypair
    pub    = Publisher(publisher_id)
    result = pub.submit_ioc(
        type="ipv4", value="5.5.5.5", severity="high",
        recipient_rsa_pub=pub_key
    )
    bundle = json.loads(Path(result["bundle_path"]).read_text())
    assert bundle["encrypted"] is True
    assert "payload" in bundle


def test_encrypted_bundle_decryptable(publisher_id, rsa_keypair):
    """
    Full pipeline: submit → encrypt → decrypt → IOC intact.
    """
    from publisher.publisher import Publisher
    from crypto.encryption import decrypt_feed
    from pathlib import Path
    import base64

    priv, pub_key = rsa_keypair
    pub    = Publisher(publisher_id)
    result = pub.submit_ioc(
        type="domain", value="c2.evil.np", severity="critical",
        recipient_rsa_pub=pub_key
    )
    bundle    = json.loads(Path(result["bundle_path"]).read_text())
    plaintext = decrypt_feed(bundle["payload"], priv)
    inner     = json.loads(plaintext)

    assert inner["ioc_count"] == 1
    assert inner["iocs"][0]["value"] == "c2.evil.np"
    assert inner["publisher_id"] == publisher_id


# ── Security tests ────────────────────────────────────────────────────────────

def test_unauthenticated_publisher_cannot_submit(ca):
    """Publisher not in registry cannot submit IOCs."""
    from publisher.publisher import Publisher
    pub = Publisher("ghost-publisher")
    with pytest.raises(PermissionError):
        pub.submit_ioc(type="ipv4", value="1.1.1.1", severity="low")


def test_each_ioc_gets_unique_nonce(publisher_id):
    """Every IOC must have a unique nonce — prevents replay."""
    from publisher.publisher import Publisher
    from store.ioc_store import IOCStore
    pub = Publisher(publisher_id)
    ioc_list = [
        {"type": "ipv4", "value": f"10.0.1.{i}", "severity": "low"}
        for i in range(10)
    ]
    result = pub.submit_feed(ioc_list)
    store  = IOCStore()
    nonces = [store.get(ioc_id).nonce for ioc_id in result["ioc_ids"]]
    assert len(set(nonces)) == 10, "All nonces must be unique"