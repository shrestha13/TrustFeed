"""
TrustFeed — Flask Web Dashboard
Provides a visual interface for:
  - CA status and publisher management
  - IOC submission (Mode 2 — analyst)
  - Feed verification
  - IOC feed view with status
  - Retraction management
  - Export downloads
  - Audit log
"""

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from flask import Flask, render_template, request, redirect, url_for, flash, send_file
import json, io
from datetime import datetime, timezone

app = Flask(__name__, template_folder="templates")
app.secret_key = "trustfeed-dashboard-secret"

import config
from ca.authority import CertificateAuthority
from publisher.publisher import Publisher
from verifier.verifier import Verifier
from retraction.retraction import RetractionManager
from store.ioc_store import IOCStore
from store.publisher_store import PublisherStore
from store.nonce_store import NonceStore
from retraction.retraction import RetractionStore
from export.json_export import export_json
from export.csv_export import export_csv
from export.stix_export import export_stix


# ── Index ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    ca       = CertificateAuthority()
    ca_info  = ca.info()
    ioc_counts = IOCStore().count()
    publishers = PublisherStore().get_all()
    nonce_count = NonceStore().count()
    retraction_count = RetractionStore().count()
    return render_template("index.html",
        ca_info=ca_info,
        ioc_counts=ioc_counts,
        publishers=publishers,
        nonce_count=nonce_count,
        retraction_count=retraction_count,
    )


# ── IOC Feed ──────────────────────────────────────────────────────────────────

@app.route("/feed")
def feed():
    store = IOCStore()
    iocs  = store.get_all()
    return render_template("feed.html", iocs=iocs)


# ── Submit IOC ────────────────────────────────────────────────────────────────

@app.route("/submit", methods=["GET", "POST"])
def submit():
    publishers = [p for p in PublisherStore().get_all() if p.is_active]
    if request.method == "POST":
        publisher_id = request.form.get("publisher_id")
        ioc_type     = request.form.get("type")
        value        = request.form.get("value", "").strip()
        severity     = request.form.get("severity")
        ttl          = int(request.form.get("ttl", 86400))

        if not value:
            flash("IOC value is required.", "error")
            return render_template("submit.html", publishers=publishers)

        try:
            pub    = Publisher(publisher_id)
            result = pub.submit_ioc(
                type=ioc_type, value=value,
                severity=severity, ttl_seconds=ttl
            )
            flash(f"IOC submitted and signed. ID: {result['ioc_id']}", "success")
            return redirect(url_for("feed"))
        except PermissionError as e:
            flash(f"Authentication failed: {e}", "error")
        except Exception as e:
            flash(f"Submission failed: {e}", "error")

    return render_template("submit.html", publishers=publishers)


# ── Verify bundle ─────────────────────────────────────────────────────────────

@app.route("/verify", methods=["GET", "POST"])
def verify():
    result = None
    if request.method == "POST":
        bundle_path = request.form.get("bundle_path", "").strip()
        if not bundle_path:
            flash("Bundle path is required.", "error")
        else:
            try:
                v      = Verifier()
                result = v.verify_bundle(bundle_path)
            except Exception as e:
                flash(f"Verification error: {e}", "error")
    return render_template("verify.html", result=result)


# ── Retract IOC ───────────────────────────────────────────────────────────────

@app.route("/retract", methods=["GET", "POST"])
def retract():
    publishers = [p for p in PublisherStore().get_all() if p.is_active]
    active_iocs = IOCStore().get_active()
    if request.method == "POST":
        publisher_id = request.form.get("publisher_id")
        ioc_id       = request.form.get("ioc_id")
        reason       = request.form.get("reason", "").strip()
        if not reason:
            flash("Retraction reason is required.", "error")
        else:
            try:
                rm = RetractionManager()
                rm.retract(ioc_id, publisher_id, reason)
                flash(f"IOC retracted successfully: {ioc_id}", "warning")
                return redirect(url_for("feed"))
            except (ValueError, PermissionError) as e:
                flash(str(e), "error")
    return render_template("retract.html",
        publishers=publishers, active_iocs=active_iocs)


# ── Publishers ────────────────────────────────────────────────────────────────

@app.route("/publishers")
def publishers():
    pubs = PublisherStore().get_all()
    return render_template("publishers.html", publishers=pubs)


@app.route("/publishers/issue", methods=["POST"])
def issue_publisher():
    publisher_id = request.form.get("publisher_id", "").strip()
    name         = request.form.get("name", "").strip()
    tier         = int(request.form.get("tier", 2))
    if not publisher_id or not name:
        flash("Publisher ID and name are required.", "error")
    else:
        try:
            ca = CertificateAuthority()
            ca.issue_publisher(publisher_id, name, tier=tier)
            flash(f"Publisher issued: {publisher_id}", "success")
        except Exception as e:
            flash(str(e), "error")
    return redirect(url_for("publishers"))


@app.route("/publishers/revoke/<publisher_id>", methods=["POST"])
def revoke_publisher(publisher_id):
    try:
        ca = CertificateAuthority()
        ca.revoke_publisher(publisher_id)
        flash(f"Publisher revoked: {publisher_id}", "warning")
    except Exception as e:
        flash(str(e), "error")
    return redirect(url_for("publishers"))


# ── Export ────────────────────────────────────────────────────────────────────

@app.route("/export/<fmt>")
def export(fmt):
    try:
        if fmt == "json":
            path = export_json()
        elif fmt == "csv":
            path = export_csv()
        elif fmt == "stix":
            path = export_stix()
        else:
            flash("Unknown format.", "error")
            return redirect(url_for("index"))
        return send_file(path, as_attachment=True)
    except Exception as e:
        flash(f"Export failed: {e}", "error")
        return redirect(url_for("index"))


# ── Audit log ─────────────────────────────────────────────────────────────────

@app.route("/audit")
def audit():
    iocs        = IOCStore().get_all()
    retractions = RetractionStore().get_all()
    return render_template("audit.html",
        iocs=iocs, retractions=retractions)


def run():
    app.run(
        host=config.DASHBOARD_HOST,
        port=config.DASHBOARD_PORT,
        debug=config.DASHBOARD_DEBUG,
    )