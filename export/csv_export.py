"""
TrustFeed — CSV Export (Firewall / EDR / pfSense / Suricata)
Simple blocklist format for network security tools.
"""
import csv, logging
from datetime import datetime, timezone
from pathlib import Path
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
import config
from store.ioc_store import IOCStore

log = logging.getLogger(__name__)


def export_csv(output_path: str = None, ioc_store: IOCStore = None) -> str:
    """
    Export active IOCs as CSV blocklist.
    Columns: type, value, severity, publisher_id, timestamp

    Compatible with pfSense IP blocklists, Suricata rules generators,
    and any firewall that accepts CSV threat feeds.
    """
    store  = ioc_store or IOCStore()
    iocs   = store.get_active()
    output = output_path or str(config.EXPORT_DIR / f"trustfeed_blocklist_{_ts()}.csv")

    with open(output, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["type", "value", "severity", "publisher_id", "timestamp"])
        for ioc in iocs:
            writer.writerow([
                ioc.type, ioc.value, ioc.severity,
                ioc.publisher_id, ioc.timestamp,
            ])

    log.info("CSV export: %d IOCs → %s", len(iocs), output)
    return output


def _ts():
    return datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")