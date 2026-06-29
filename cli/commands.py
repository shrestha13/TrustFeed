"""
TrustFeed — CLI Commands
All commands wired to the core modules.

Usage:
    python trustfeed.py ca init
    python trustfeed.py ca issue --id npcert-01 --name "NPCERT" --tier 1
    python trustfeed.py ca info
    python trustfeed.py ca revoke --id npcert-01

    python trustfeed.py submit --publisher npcert-01 --type ipv4 --value 185.220.101.45 --severity high

    python trustfeed.py verify --bundle data/feeds/abc.tfb

    python trustfeed.py retract --publisher npcert-01 --ioc-id <uuid> --reason "False positive"

    python trustfeed.py export --format json
    python trustfeed.py export --format csv
    python trustfeed.py export --format stix

    python trustfeed.py status
"""

import click
import json
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


# ── Helpers ───────────────────────────────────────────────────────────────────

def ok(msg):
    click.echo(click.style(f"✓ {msg}", fg="green"))

def err(msg):
    click.echo(click.style(f"✗ {msg}", fg="red"), err=True)

def info(msg):
    click.echo(click.style(f"  {msg}", fg="cyan"))

def warn(msg):
    click.echo(click.style(f"⚠ {msg}", fg="yellow"))

def header(msg):
    click.echo(click.style(f"\n{'─'*60}", fg="blue"))
    click.echo(click.style(f"  {msg}", fg="blue", bold=True))
    click.echo(click.style(f"{'─'*60}", fg="blue"))


# ── CA commands ───────────────────────────────────────────────────────────────

@click.group()
def ca():
    """Certificate Authority management."""
    pass


@ca.command("init")
def ca_init():
    """Initialize the TrustFeed CA hierarchy (run once)."""
    header("Initializing TrustFeed CA")
    from ca.authority import CertificateAuthority
    authority = CertificateAuthority()
    try:
        result = authority.init()
        ok("Root CA generated (RSA-4096)")
        ok("Intermediate CA generated (ECDSA P-384)")
        ok("CRL initialized")
        info(f"Root CA cert:         {result['root_ca_cert']}")
        info(f"Intermediate CA cert: {result['int_ca_cert']}")
        info(f"CRL:                  {result['crl']}")
        click.echo()
        ok("CA initialization complete. You can now issue publisher certificates.")
    except RuntimeError as e:
        err(str(e))
        sys.exit(1)


@ca.command("issue")
@click.option("--id",   "publisher_id", required=True, help="Publisher ID (e.g. npcert-01)")
@click.option("--name", required=True,                 help="Publisher display name")
@click.option("--tier", default=2, type=click.Choice(["1","2","3"]), help="Trust tier (1=Gov, 2=SOC, 3=Community)")
def ca_issue(publisher_id, name, tier):
    """Issue a publisher certificate and Ed25519 signing keypair."""
    header(f"Issuing publisher certificate: {publisher_id}")
    from ca.authority import CertificateAuthority
    authority = CertificateAuthority()
    try:
        result = authority.issue_publisher(publisher_id, name, tier=int(tier))
        ok(f"Publisher issued: {publisher_id} (Tier {tier})")
        info(f"Certificate:    {result['cert']}")
        info(f"Private key:    {result['key']}")
        info(f"Ed25519 priv:   {result['ed25519_priv']}")
        info(f"Ed25519 pub:    {result['ed25519_pub']}")
        click.echo()
        ok(f"'{publisher_id}' can now submit and sign IOCs.")
    except Exception as e:
        err(str(e))
        sys.exit(1)


@ca.command("revoke")
@click.option("--id", "publisher_id", required=True, help="Publisher ID to revoke")
def ca_revoke(publisher_id):
    """Revoke a publisher certificate (adds to CRL)."""
    header(f"Revoking publisher: {publisher_id}")
    from ca.authority import CertificateAuthority
    authority = CertificateAuthority()
    try:
        revoked = authority.revoke_publisher(publisher_id)
        if revoked:
            warn(f"Publisher REVOKED: {publisher_id}")
            warn("All future submissions from this publisher will be rejected.")
        else:
            err(f"Publisher not found: {publisher_id}")
            sys.exit(1)
    except Exception as e:
        err(str(e))
        sys.exit(1)


@ca.command("info")
def ca_info():
    """Show CA status and publisher registry."""
    header("TrustFeed CA Status")
    from ca.authority import CertificateAuthority
    authority = CertificateAuthority()
    info_data = authority.info()
    if not info_data.get("initialized"):
        err("CA not initialized. Run: python trustfeed.py ca init")
        sys.exit(1)
    ok(f"Root CA:           {info_data['root_ca_cn']}")
    info(f"  Expires:         {info_data['root_ca_expires']}")
    ok(f"Intermediate CA:   {info_data['int_ca_cn']}")
    info(f"  Expires:         {info_data['int_ca_expires']}")
    info(f"Revoked certs:     {info_data['revoked_count']}")
    info(f"Publishers:        {info_data['publishers']}")


# ── Submit command ────────────────────────────────────────────────────────────

@click.command()
@click.option("--publisher", required=True, help="Publisher ID")
@click.option("--type",      "ioc_type", required=True,
              type=click.Choice(["ipv4","domain","url","hash","email"]),
              help="IOC type")
@click.option("--value",     required=True, help="IOC value (e.g. 185.220.101.45)")
@click.option("--severity",  default="medium",
              type=click.Choice(["critical","high","medium","low"]),
              help="Severity level")
@click.option("--ttl",       default=86400, help="Time-to-live in seconds (default: 86400)")
def submit(publisher, ioc_type, value, severity, ttl):
    """Submit and sign a single IOC as a verified publisher."""
    header(f"Submitting IOC: {ioc_type} {value}")
    from publisher.publisher import Publisher
    try:
        pub    = Publisher(publisher)
        result = pub.submit_ioc(
            type=ioc_type, value=value,
            severity=severity, ttl_seconds=ttl
        )
        ok(f"IOC signed and published")
        info(f"IOC ID:     {result['ioc_id']}")
        info(f"Type:       {result['type']}")
        info(f"Value:      {result['value']}")
        info(f"Severity:   {result['severity']}")
        info(f"Nonce:      {result['nonce']}")
        info(f"Signature:  {result['signature'][:32]}...")
        info(f"Bundle:     {result['bundle_path']}")
    except PermissionError as e:
        err(str(e))
        sys.exit(1)
    except Exception as e:
        err(str(e))
        sys.exit(1)


# ── Verify command ────────────────────────────────────────────────────────────

@click.command()
@click.option("--bundle", required=True, help="Path to .tfb bundle file")
def verify(bundle):
    """Verify a .tfb feed bundle — cert, signatures, nonces, expiry."""
    header(f"Verifying bundle: {bundle}")
    from verifier.verifier import Verifier
    v      = Verifier()
    result = v.verify_bundle(bundle)

    if result.error:
        err(f"Bundle rejected: {result.error}")
        sys.exit(1)

    info(f"Publisher:  {result.publisher_id}")
    info(f"Total IOCs: {result.total}")
    click.echo()

    for r in result.ioc_results:
        if r.passed:
            ok(f"ACCEPTED  [{r.type:6}] {r.value}")
        else:
            err(f"REJECTED  [{r.type:6}] {r.value}")
            click.echo(click.style(f"           → {r.step}: {r.reason}", fg="red"))

    click.echo()
    if result.accepted == result.total:
        ok(f"All {result.accepted} IOCs verified and accepted.")
    else:
        warn(f"{result.accepted} accepted, {result.rejected} rejected.")


# ── Retract command ───────────────────────────────────────────────────────────

@click.command()
@click.option("--publisher", required=True, help="Publisher ID (must own the IOC)")
@click.option("--ioc-id",   required=True, help="IOC UUID to retract")
@click.option("--reason",   required=True, help="Reason for retraction")
def retract(publisher, ioc_id, reason):
    """Issue a signed retraction for a false positive IOC."""
    header(f"Retracting IOC: {ioc_id}")
    from retraction.retraction import RetractionManager
    rm = RetractionManager()
    try:
        result = rm.retract(ioc_id, publisher, reason)
        warn(f"IOC RETRACTED: {ioc_id}")
        info(f"Retraction ID: {result['retraction_id']}")
        info(f"Publisher:     {result['publisher_id']}")
        info(f"Reason:        {result['reason']}")
        info(f"Signature:     {result['signature'][:32]}...")
        ok("Retraction signed and logged. IOC marked as retracted in store.")
    except (ValueError, PermissionError) as e:
        err(str(e))
        sys.exit(1)


# ── Export command ────────────────────────────────────────────────────────────

@click.command()
@click.option("--format", "fmt", default="json",
              type=click.Choice(["json","csv","stix"]),
              help="Export format")
@click.option("--output", default=None, help="Output file path (optional)")
def export(fmt, output):
    """Export verified IOCs to SIEM-compatible format."""
    header(f"Exporting IOCs — format: {fmt.upper()}")
    try:
        if fmt == "json":
            from export.json_export import export_json
            path = export_json(output_path=output)
        elif fmt == "csv":
            from export.csv_export import export_csv
            path = export_csv(output_path=output)
        elif fmt == "stix":
            from export.stix_export import export_stix
            path = export_stix(output_path=output)
        ok(f"Exported → {path}")
    except Exception as e:
        err(str(e))
        sys.exit(1)


# ── Status command ────────────────────────────────────────────────────────────

@click.command()
def status():
    """Show TrustFeed system status — IOC counts, CA info, publishers."""
    header("TrustFeed System Status")
    from ca.authority import CertificateAuthority
    from store.ioc_store import IOCStore
    from store.nonce_store import NonceStore
    from store.publisher_store import PublisherStore
    from retraction.retraction import RetractionStore

    # CA
    ca       = CertificateAuthority()
    ca_info  = ca.info()
    if ca_info.get("initialized"):
        ok(f"CA initialized")
        info(f"  Root CA:         {ca_info['root_ca_cn']}")
        info(f"  Intermediate CA: {ca_info['int_ca_cn']}")
        info(f"  Revoked certs:   {ca_info['revoked_count']}")
    else:
        warn("CA not initialized")

    # Publishers
    publishers = PublisherStore().get_all()
    info(f"Publishers registered: {len(publishers)}")
    for p in publishers:
        status_str = "active" if p.is_active else "REVOKED"
        info(f"  [{p.tier}] {p.publisher_id} ({p.name}) — {status_str}")

    # IOCs
    counts = IOCStore().count()
    click.echo()
    info(f"IOC store:")
    info(f"  Active:    {counts.get('active', 0)}")
    info(f"  Retracted: {counts.get('retracted', 0)}")
    info(f"Nonces seen:    {NonceStore().count()}")
    info(f"Retractions:    {RetractionStore().count()}")


# ── Dashboard command ─────────────────────────────────────────────────────────

@click.command()
@click.option("--host", default="127.0.0.1", help="Host to bind (default: 127.0.0.1)")
@click.option("--port", default=5000,        help="Port to bind (default: 5000)")
def dashboard(host, port):
    """Launch the TrustFeed web dashboard."""
    header(f"Starting TrustFeed Dashboard")
    info(f"Open in browser: http://{host}:{port}")
    info("Press Ctrl+C to stop.")
    click.echo()
    from dashboard.app import app
    import config
    config.DASHBOARD_HOST = host
    config.DASHBOARD_PORT = port
    app.run(host=host, port=port, debug=False)