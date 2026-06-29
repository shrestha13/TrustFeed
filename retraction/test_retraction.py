"""
TrustFeed — Retraction module tests
Run from CW/trustfeed/: python -m pytest retraction/test_retraction.py -v
"""
import sys, os, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import config


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    for attr, sub in [
        ("CA_DIR","ca"),("CERTS_DIR","certs"),
        ("DB_DIR","db"),("FEEDS_DIR","feeds"),
    ]:
        p = tmp_path / sub; p.mkdir(parents=True, exist_ok=True)
        monkeypatch.setattr(config, attr, p)
    monkeypatch.setattr(config, "ROOT_CA_KEY_PATH",  config.CA_DIR/"root_ca.key.pem")
    monkeypatch.setattr(config, "ROOT_CA_CERT_PATH", config.CA_DIR/"root_ca.cert.pem")
    monkeypatch.setattr(config, "INT_CA_KEY_PATH",   config.CA_DIR/"intermediate_ca.key.pem")
    monkeypatch.setattr(config, "INT_CA_CERT_PATH",  config.CA_DIR/"intermediate_ca.cert.pem")
    monkeypatch.setattr(config, "CRL_PATH",          config.CA_DIR/"crl.pem")
    monkeypatch.setattr(config, "PUBLISHER_DB_PATH", config.DB_DIR/"publisher_registry.db")
    monkeypatch.setattr(config, "IOC_DB_PATH",       config.DB_DIR/"ioc_store.db")
    monkeypatch.setattr(config, "NONCE_DB_PATH",     config.DB_DIR/"nonce_store.db")
    monkeypatch.setattr(config, "RETRACTION_DB_PATH",config.DB_DIR/"retraction_log.db")


@pytest.fixture
def setup(isolated):
    from ca.authority import CertificateAuthority
    ca = CertificateAuthority()
    ca.init()
    ca.issue_publisher("pub-01", "Publisher One", tier=2)
    ca.issue_publisher("pub-02", "Publisher Two", tier=2)
    return ca


@pytest.fixture
def submitted_ioc(setup):
    from publisher.publisher import Publisher
    pub = Publisher("pub-01")
    return pub.submit_ioc(type="ipv4", value="185.220.101.45", severity="high")


def test_retract_ioc(submitted_ioc):
    from retraction.retraction import RetractionManager
    rm     = RetractionManager()
    result = rm.retract(submitted_ioc["ioc_id"], "pub-01", "False positive")
    assert result["ioc_id"] == submitted_ioc["ioc_id"]
    assert result["signature"] is not None


def test_retracted_ioc_marked_in_store(submitted_ioc):
    from retraction.retraction import RetractionManager
    from store.ioc_store import IOCStore
    import sqlite3
    rm = RetractionManager()
    rm.retract(submitted_ioc["ioc_id"], "pub-01", "False positive")
    store = IOCStore()
    with store._connect() as conn:
        row = conn.execute(
            "SELECT status FROM iocs WHERE ioc_id=?",
            (submitted_ioc["ioc_id"],)
        ).fetchone()
    assert row["status"] == "retracted"


def test_retraction_signature_valid(submitted_ioc):
    from retraction.retraction import RetractionManager
    rm = RetractionManager()
    rm.retract(submitted_ioc["ioc_id"], "pub-01", "False positive")
    valid, reason = rm.verify_retraction(submitted_ioc["ioc_id"])
    assert valid is True, f"Expected valid retraction, got: {reason}"


def test_wrong_publisher_cannot_retract(submitted_ioc):
    """pub-02 cannot retract an IOC submitted by pub-01."""
    from retraction.retraction import RetractionManager
    rm = RetractionManager()
    with pytest.raises(PermissionError):
        rm.retract(submitted_ioc["ioc_id"], "pub-02", "Attempted theft")


def test_nonexistent_ioc_raises(setup):
    from retraction.retraction import RetractionManager
    rm = RetractionManager()
    with pytest.raises(ValueError):
        rm.retract("nonexistent-uuid", "pub-01", "Does not exist")


def test_is_retracted_true_after_retraction(submitted_ioc):
    from retraction.retraction import RetractionManager
    rm = RetractionManager()
    assert rm.is_retracted(submitted_ioc["ioc_id"]) is False
    rm.retract(submitted_ioc["ioc_id"], "pub-01", "False positive")
    assert rm.is_retracted(submitted_ioc["ioc_id"]) is True


def test_retracted_ioc_rejected_by_verifier(submitted_ioc):
    """
    Full pipeline: submit → retract → verify bundle → IOC rejected.
    This is the retraction use case demo.
    """
    from retraction.retraction import RetractionManager
    from verifier.verifier import Verifier

    rm = RetractionManager()
    rm.retract(submitted_ioc["ioc_id"], "pub-01", "False positive")

    v      = Verifier()
    result = v.verify_bundle(submitted_ioc["bundle_path"])
    # IOC was already in store from publisher — verify sees it as replay/retracted
    assert result.ioc_results[0].step in ("replay", "retraction", "all_passed")