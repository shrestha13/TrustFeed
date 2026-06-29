"""
TrustFeed — CA module tests
Flat import structure matching CW/trustfeed/ layout.
Run from CW/trustfeed/: python -m pytest ca/test_ca.py -v
"""

import sys, os, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import config


@pytest.fixture(autouse=True)
def clean_ca(tmp_path, monkeypatch):
    monkeypatch.setattr(config, "CA_DIR",    tmp_path / "ca")
    monkeypatch.setattr(config, "CERTS_DIR", tmp_path / "certs")
    monkeypatch.setattr(config, "DB_DIR",    tmp_path / "db")
    for d in [config.CA_DIR, config.CERTS_DIR, config.DB_DIR]:
        d.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(config, "ROOT_CA_KEY_PATH",  config.CA_DIR / "root_ca.key.pem")
    monkeypatch.setattr(config, "ROOT_CA_CERT_PATH", config.CA_DIR / "root_ca.cert.pem")
    monkeypatch.setattr(config, "INT_CA_KEY_PATH",   config.CA_DIR / "intermediate_ca.key.pem")
    monkeypatch.setattr(config, "INT_CA_CERT_PATH",  config.CA_DIR / "intermediate_ca.cert.pem")
    monkeypatch.setattr(config, "CRL_PATH",          config.CA_DIR / "crl.pem")
    monkeypatch.setattr(config, "PUBLISHER_DB_PATH", config.DB_DIR / "publisher_registry.db")
    yield


def make_ca():
    from ca.authority import CertificateAuthority
    ca = CertificateAuthority()
    ca.init()
    return ca


def test_ca_init_creates_files():
    make_ca()
    assert config.ROOT_CA_CERT_PATH.exists(), "Root CA cert missing"
    assert config.ROOT_CA_KEY_PATH.exists(),  "Root CA key missing"
    assert config.INT_CA_CERT_PATH.exists(),  "Intermediate CA cert missing"
    assert config.INT_CA_KEY_PATH.exists(),   "Intermediate CA key missing"
    assert config.CRL_PATH.exists(),          "CRL missing"


def test_ca_double_init_raises():
    ca = make_ca()
    with pytest.raises(RuntimeError, match="already initialized"):
        ca.init()


def test_ca_info():
    ca = make_ca()
    info = ca.info()
    assert info["initialized"] is True
    assert "TrustFeed Root CA" in info["root_ca_cn"]
    assert "TrustFeed Intermediate CA" in info["int_ca_cn"]
    assert info["revoked_count"] == 0
    assert info["publishers"] == 0


def test_issue_publisher():
    ca = make_ca()
    result = ca.issue_publisher("npcert-01", "NPCERT Nepal", tier=1)
    assert result["publisher_id"] == "npcert-01"
    assert result["tier"] == 1
    from pathlib import Path
    assert Path(result["cert"]).exists(),         "Publisher cert missing"
    assert Path(result["key"]).exists(),          "Publisher key missing"
    assert Path(result["ed25519_priv"]).exists(), "Ed25519 private key missing"
    assert Path(result["ed25519_pub"]).exists(),  "Ed25519 public key missing"


def test_publisher_in_registry():
    ca = make_ca()
    ca.issue_publisher("analyst-01", "SOC Analyst", tier=2)
    from store.publisher_store import PublisherStore
    pub = PublisherStore().get("analyst-01")
    assert pub is not None
    assert pub.tier == 2
    assert pub.is_active is True
    assert len(pub.ed25519_pub_key) > 0


def test_cert_validation_passes():
    ca = make_ca()
    result = ca.issue_publisher("valid-pub", "Valid Publisher", tier=2)
    valid, reason = ca.validate_publisher_cert(result["cert"])
    assert valid is True, f"Expected valid cert, got: {reason}"


def test_cert_validation_fails_after_revocation():
    ca = make_ca()
    result = ca.issue_publisher("to-revoke", "Bad Actor", tier=3)
    assert ca.revoke_publisher("to-revoke") is True
    valid, reason = ca.validate_publisher_cert(result["cert"])
    assert valid is False
    assert "REVOKED" in reason


def test_publisher_inactive_after_revocation():
    ca = make_ca()
    ca.issue_publisher("inactive-pub", "Inactive", tier=2)
    ca.revoke_publisher("inactive-pub")
    from store.publisher_store import PublisherStore
    assert PublisherStore().get("inactive-pub") is None


def test_trust_store_loads():
    make_ca()
    from ca.trust_store import TrustStore
    ts = TrustStore()
    assert ts.root_cert is not None
    assert ts.int_cert is not None


def test_ed25519_key_loadable():
    ca = make_ca()
    result = ca.issue_publisher("ed-pub", "Ed25519 Test", tier=2)
    from ca.trust_store import TrustStore
    assert TrustStore().get_ed25519_pub("ed-pub") is not None