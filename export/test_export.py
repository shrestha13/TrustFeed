"""
TrustFeed — Export module tests
Run from CW/trustfeed/: python -m pytest export/test_export.py -v
"""
import sys, os, json, csv, pytest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import config


@pytest.fixture(autouse=True)
def isolated(tmp_path, monkeypatch):
    for attr, sub in [
        ("CA_DIR","ca"),("CERTS_DIR","certs"),
        ("DB_DIR","db"),("FEEDS_DIR","feeds"),("EXPORT_DIR","exports"),
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
def populated_store(isolated):
    """Set up CA, publisher, submit IOCs, AND VERIFY THEM so they enter the store."""
    from ca.authority import CertificateAuthority
    from publisher.publisher import Publisher
    from verifier.verifier import Verifier

    ca = CertificateAuthority()
    ca.init()
    ca.issue_publisher("npcert-01", "NPCERT", tier=1)

    pub = Publisher("npcert-01")
    ioc_list = [
        {"type": "ipv4",   "value": "185.220.101.45", "severity": "high"},
        {"type": "domain", "value": "malware.np",     "severity": "critical"},
        {"type": "hash",   "value": "deadbeef1234",   "severity": "medium"},
        {"type": "url",    "value": "http://bad.np",  "severity": "high"},
        {"type": "email",  "value": "phish@bad.np",   "severity": "low"},
    ]
    
    # 1. Submit the feed (creates the .tfb bundle)
    result = pub.submit_feed(ioc_list)
    
    # 2. CRITICAL MISSING STEP: Verify the bundle so IOCs enter the IOCStore
    v = Verifier()
    vresult = v.verify_bundle(result["bundle_path"])
    
    # 3. Sanity check: Ensure all 5 IOCs actually passed verification
    assert vresult.accepted == 5, f"Setup failed: Expected 5 accepted, got {vresult.accepted}. Error: {vresult.error}"
    
    return pub


# ── JSON export tests ─────────────────────────────────────────────────────────

def test_json_export_creates_file(populated_store, tmp_path):
    from export.json_export import export_json
    out = str(tmp_path / "test.json")
    path = export_json(output_path=out)
    assert os.path.exists(path)


def test_json_export_contains_all_iocs(populated_store, tmp_path):
    from export.json_export import export_json
    out  = str(tmp_path / "test.json")
    export_json(output_path=out)
    data = json.loads(open(out).read())
    
    npcert_iocs = [d for d in data if d.get("publisher_id") == "npcert-01"]
    
    # Verify our 5 specific IOCs are present, ignoring leftover DB state
    expected_values = {"185.220.101.45", "malware.np", "deadbeef1234", "http://bad.np", "phish@bad.np"}
    exported_values = {d["value"] for d in npcert_iocs}
    
    assert expected_values.issubset(exported_values), f"Missing IOCs in export: {expected_values - exported_values}"
    assert len(npcert_iocs) >= 5, f"Expected at least 5 IOCs for npcert-01, got {len(npcert_iocs)}"


def test_json_export_fields(populated_store, tmp_path):
    from export.json_export import export_json
    out  = str(tmp_path / "test.json")
    export_json(output_path=out)
    data = json.loads(open(out).read())
    for record in data:
        assert "ioc_id"    in record
        assert "type"      in record
        assert "value"     in record
        assert "severity"  in record
        assert "signature" in record
        assert record["source"] == "TrustFeed"


# ── CSV export tests ──────────────────────────────────────────────────────────

def test_csv_export_creates_file(populated_store, tmp_path):
    from export.csv_export import export_csv
    out = str(tmp_path / "test.csv")
    path = export_csv(output_path=out)
    assert os.path.exists(path)


def test_csv_export_correct_rows(populated_store, tmp_path):
    from export.csv_export import export_csv
    out = str(tmp_path / "test.csv")
    export_csv(output_path=out)
    with open(out) as f:
        rows = list(csv.reader(f))
    
    assert rows[0] == ["type", "value", "severity", "publisher_id", "timestamp"]
    
    npcert_rows = [r for r in rows[1:] if len(r) > 3 and r[3] == "npcert-01"]
    
    # Verify our 5 specific values are present (value is at index 1)
    expected_values = {"185.220.101.45", "malware.np", "deadbeef1234", "http://bad.np", "phish@bad.np"}
    exported_values = {r[1] for r in npcert_rows} 
    
    assert expected_values.issubset(exported_values), f"Missing IOCs in CSV: {expected_values - exported_values}"
    assert len(npcert_rows) >= 5, f"Expected at least 5 CSV rows for npcert-01, got {len(npcert_rows)}"

def test_csv_export_values(populated_store, tmp_path):
    from export.csv_export import export_csv
    out = str(tmp_path / "test.csv")
    export_csv(output_path=out)
    with open(out) as f:
        rows = list(csv.DictReader(f))
    values = [r["value"] for r in rows]
    assert "185.220.101.45" in values
    assert "malware.np" in values


# ── STIX 2.1 export tests ─────────────────────────────────────────────────────

def test_stix_export_creates_file(populated_store, tmp_path):
    from export.stix_export import export_stix
    out = str(tmp_path / "test.json")
    path = export_stix(output_path=out)
    assert os.path.exists(path)


def test_stix_export_is_valid_bundle(populated_store, tmp_path):
    from export.stix_export import export_stix
    out = str(tmp_path / "test.json")
    export_stix(output_path=out)
    bundle = json.loads(open(out).read())
    
    assert bundle["type"] == "bundle"
    assert bundle["spec_version"] == "2.1"
    
    npcert_objects = [obj for obj in bundle["objects"] if "Publisher: npcert-01" in obj.get("description", "")]
    
    # In STIX, the value is inside the pattern, e.g., "[ipv4-addr:value = '185.220.101.45']"
    expected_values = {"185.220.101.45", "malware.np", "deadbeef1234", "http://bad.np", "phish@bad.np"}
    
    # Check that our expected values are found inside the STIX patterns
    found_values = set()
    for obj in npcert_objects:
        pattern = obj.get("pattern", "")
        for val in expected_values:
            if val in pattern:
                found_values.add(val)
                
    assert expected_values.issubset(found_values), f"Missing IOCs in STIX bundle: {expected_values - found_values}"
    assert len(npcert_objects) >= 5, f"Expected at least 5 STIX objects for npcert-01, got {len(npcert_objects)}"

def test_stix_indicators_have_correct_patterns(populated_store, tmp_path):
    from export.stix_export import export_stix
    out = str(tmp_path / "test.json")
    export_stix(output_path=out)
    bundle  = json.loads(open(out).read())
    objects = bundle["objects"]
    patterns = [o["pattern"] for o in objects]
    assert any("ipv4-addr:value" in p for p in patterns)
    assert any("domain-name:value" in p for p in patterns)
    assert any("url:value" in p for p in patterns)


def test_stix_indicator_fields(populated_store, tmp_path):
    from export.stix_export import export_stix
    out = str(tmp_path / "test.json")
    export_stix(output_path=out)
    bundle = json.loads(open(out).read())
    for obj in bundle["objects"]:
        assert obj["type"] == "indicator"
        assert obj["spec_version"] == "2.1"
        assert "pattern" in obj
        assert "valid_from" in obj
        assert "trustfeed-verified" in obj["labels"]