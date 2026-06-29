"""
TrustFeed — JSON Export (Splunk / Wazuh / OpenSearch compatible)
Exports verified IOCs as structured JSON for SIEM ingestion.
"""
import json, logging
from datetime import datetime, timezone
from pathlib import Path
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import config
from store.ioc_store import IOCStore

log = logging.getLogger(__name__)


def export_json(output_path: str = None, ioc_store: IOCStore = None) -> str:
    """
    Export all active verified IOCs as a JSON array.
    Format compatible with Splunk Threat Intelligence Management
    and Wazuh/OpenSearch indicator index.

    Returns path to written file.
    """
    store  = ioc_store or IOCStore()
    iocs   = store.get_active()
    output = output_path or str(config.EXPORT_DIR / f"trustfeed_export_{_ts()}.json")

    records = []
    for ioc in iocs:
        records.append({
            "ioc_id":       ioc.ioc_id,
            "type":         ioc.type,
            "value":        ioc.value,
            "severity":     ioc.severity,
            "publisher_id": ioc.publisher_id,
            "timestamp":    ioc.timestamp,
            "ttl_seconds":  ioc.ttl_seconds,
            "signature":    ioc.signature,
            "source":       "TrustFeed",
        })

    Path(output).write_text(json.dumps(records, indent=2))
    log.info("JSON export: %d IOCs → %s", len(records), output)
    return output


def _ts():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")