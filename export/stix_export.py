"""
TrustFeed — STIX 2.1 Export
Industry-standard threat intelligence format.
Compatible with TAXII servers, MISP, OpenCTI, IBM QRadar, Microsoft Sentinel.

STIX type mapping:
  ipv4   → indicator with pattern [ipv4-addr:value = '...']
  domain → indicator with pattern [domain-name:value = '...']
  url    → indicator with pattern [url:value = '...']
  hash   → indicator with pattern [file:hashes.MD5 = '...']
  email  → indicator with pattern [email-addr:value = '...']
"""
import logging, uuid
from datetime import datetime, timezone
from pathlib import Path
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import config
from store.ioc_store import IOCStore

log = logging.getLogger(__name__)

STIX_PATTERNS = {
    "ipv4":   lambda v: f"[ipv4-addr:value = '{v}']",
    "domain": lambda v: f"[domain-name:value = '{v}']",
    "url":    lambda v: f"[url:value = '{v}']",
    "hash":   lambda v: f"[file:hashes.MD5 = '{v}']",
    "email":  lambda v: f"[email-addr:value = '{v}']",
}

SEVERITY_LABELS = {
    "critical": "high", "high": "high",
    "medium": "medium", "low": "low",
}


def export_stix(output_path: str = None, ioc_store: IOCStore = None) -> str:
    """
    Export active IOCs as a STIX 2.1 Bundle JSON file.
    Each IOC becomes a STIX Indicator object.
    Returns path to written file.
    """
    store  = ioc_store or IOCStore()
    iocs   = store.get_active()
    output = output_path or str(config.EXPORT_DIR / f"trustfeed_stix_{_ts()}.json")

    indicators = []
    for ioc in iocs:
        pattern_fn = STIX_PATTERNS.get(ioc.type)
        if not pattern_fn:
            continue
        indicators.append({
            "type":                "indicator",
            "spec_version":        "2.1",
            "id":                  f"indicator--{ioc.ioc_id}",
            "created":             ioc.timestamp,
            "modified":            ioc.timestamp,
            "name":                f"TrustFeed IOC: {ioc.value}",
            "description":         f"Publisher: {ioc.publisher_id} | Severity: {ioc.severity}",
            "indicator_types":     ["malicious-activity"],
            "pattern":             pattern_fn(ioc.value),
            "pattern_type":        "stix",
            "valid_from":          ioc.timestamp,
            "confidence":          _confidence(ioc.severity),
            "labels":              [ioc.severity, "trustfeed-verified"],
            "external_references": [{
                "source_name": "TrustFeed",
                "description": f"Cryptographically verified IOC | sig: {(ioc.signature or '')[:32]}...",
            }],
        })

    bundle = {
        "type":        "bundle",
        "id":          f"bundle--{uuid.uuid4()}",
        "spec_version": "2.1",
        "objects":     indicators,
    }

    import json
    Path(output).write_text(json.dumps(bundle, indent=2))
    log.info("STIX 2.1 export: %d indicators → %s", len(indicators), output)
    return output


def _confidence(severity: str) -> int:
    return {"critical": 95, "high": 80, "medium": 60, "low": 40}.get(severity, 50)


def _ts():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")