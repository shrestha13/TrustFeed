"""
TrustFeed — Central Configuration
All paths, algorithm parameters, and constants live here.
Traceable to technical diagram throughout.
"""
 
import os
from pathlib import Path
 
# ── Base paths ────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).parent
DATA_DIR   = BASE_DIR / "data"
CA_DIR     = DATA_DIR / "ca"
CERTS_DIR  = DATA_DIR / "certs"
DB_DIR     = DATA_DIR / "db"
FEEDS_DIR  = DATA_DIR / "feeds"
 
# Ensure runtime dirs exist
for _dir in [CA_DIR, CERTS_DIR, DB_DIR, FEEDS_DIR]:
    _dir.mkdir(parents=True, exist_ok=True)
 
# ── CA file paths ─────────────────────────────────────────────────────────────
ROOT_CA_KEY_PATH   = CA_DIR / "root_ca.key.pem"
ROOT_CA_CERT_PATH  = CA_DIR / "root_ca.cert.pem"
INT_CA_KEY_PATH    = CA_DIR / "intermediate_ca.key.pem"
INT_CA_CERT_PATH   = CA_DIR / "intermediate_ca.cert.pem"
CRL_PATH           = CA_DIR / "crl.pem"
 
# ── Database paths ────────────────────────────────────────────────────────────
IOC_DB_PATH        = DB_DIR / "ioc_store.db"
NONCE_DB_PATH      = DB_DIR / "nonce_store.db"
PUBLISHER_DB_PATH  = DB_DIR / "publisher_registry.db"
RETRACTION_DB_PATH = DB_DIR / "retraction_log.db"
 
# ── Algorithm parameters ──────────────────────────────────────────────────────
# These match the technical diagram exactly. Do not change.
 
# Root CA — RSA-4096 (technical diagram: "OpenSSL RSA-4096 · self-signed · 20 yr")
ROOT_CA_KEY_SIZE      = 4096
ROOT_CA_VALIDITY_DAYS = 7300  # 20 years
 
# Intermediate CA — ECDSA P-384 (technical diagram: "Step-CA ECDSA P-384 · 5 yr")
INT_CA_VALIDITY_DAYS  = 1825  # 5 years
 
# Publisher certs — ECDSA P-256 (technical diagram: "ECDSA P-256 · 90 day")
PUBLISHER_CERT_VALIDITY_DAYS = 90
 
# IOC signing — Ed25519 (technical diagram: "Ed25519 keypair per publisher")
# Ed25519 has no parameters — key size is fixed at 256 bits
 
# Symmetric encryption — AES-256-GCM (technical diagram: "AES-256-GCM")
AES_KEY_SIZE   = 32   # 256 bits
AES_NONCE_SIZE = 12   # 96 bits — GCM standard
 
# Nonce — 96-bit random (technical diagram: "base64(96-bit random)")
NONCE_SIZE_BYTES = 12  # 96 bits
 
# Session key wrapping — RSA-OAEP
# Recipient RSA key size matches Root CA: 4096 bits
 
# ── IOC settings ──────────────────────────────────────────────────────────────
IOC_TYPES         = ["ipv4", "domain", "url", "hash", "email"]
IOC_SEVERITIES    = ["critical", "high", "medium", "low"]
DEFAULT_TTL_SECS  = 86400  # 24 hours
 
# ── Feed bundle ───────────────────────────────────────────────────────────────
BUNDLE_EXTENSION  = ".tfb"   # TrustFeed Bundle
 
# ── CA subject defaults ───────────────────────────────────────────────────────
CA_COUNTRY        = "NP"
CA_ORGANIZATION   = "TrustFeed"
CA_ROOT_CN        = "TrustFeed Root CA"
CA_INT_CN         = "TrustFeed Intermediate CA"
 
# ── Export ────────────────────────────────────────────────────────────────────
EXPORT_DIR        = DATA_DIR / "exports"
EXPORT_DIR.mkdir(parents=True, exist_ok=True)
 
# ── Dashboard ─────────────────────────────────────────────────────────────────
DASHBOARD_HOST    = "127.0.0.1"
DASHBOARD_PORT    = 5000
DASHBOARD_DEBUG   = False
 
# ── Misc ──────────────────────────────────────────────────────────────────────
LOG_LEVEL         = os.environ.get("TRUSTFEED_LOG_LEVEL", "INFO")