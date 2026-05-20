#!/usr/bin/env python3
"""ClamAV Antivirus Addon - Flask Web GUI"""
import json
import os
import threading

from flask import Flask, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

import scanner

app = Flask(__name__)
app.secret_key = os.urandom(32)

WEB_PORT               = int(os.environ.get("WEB_PORT", "8200"))
ADMIN_PASSWORD_ENABLED = os.environ.get("ADMIN_PASSWORD_ENABLED", "false").lower() in ("true", "1")
ADMIN_USERNAME         = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD         = os.environ.get("ADMIN_PASSWORD", "")

_pw_hash = generate_password_hash(ADMIN_PASSWORD) if ADMIN_PASSWORD_ENABLED and ADMIN_PASSWORD else None


def _auth_required():
    if not ADMIN_PASSWORD_ENABLED or not _pw_hash:
        return False
    return not session.get("logged_in")


# ── Auth ──────────────────────────────────────────────────────

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        if (request.form.get("username") == ADMIN_USERNAME and
                check_password_hash(_pw_hash, request.form.get("password", ""))):
            session["logged_in"] = True
            return redirect(url_for("index"))
        error = "Invalid credentials"
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ── Pages ─────────────────────────────────────────────────────

@app.route("/")
def index():
    if _auth_required():
        return redirect(url_for("login"))
    history = scanner._load_history()
    last_scan = history[-1] if history else None
    sig_info  = scanner.get_signature_info()
    quarantine = scanner.list_quarantine()
    scan_paths = json.loads(os.environ.get("SCAN_PATHS", '["/share","/media"]'))
    return render_template(
        "index.html",
        last_scan=last_scan,
        history=list(reversed(history)),
        sig_info=sig_info,
        quarantine=quarantine,
        scan_paths=scan_paths,
        schedule=os.environ.get("SCAN_SCHEDULE", "daily"),
        scan_hour=os.environ.get("SCAN_HOUR", "2"),
        auto_quarantine=os.environ.get("AUTO_QUARANTINE", "true"),
        notify_ha=os.environ.get("NOTIFY_HA", "true"),
    )


# ── API ───────────────────────────────────────────────────────

@app.route("/api/scan/start", methods=["POST"])
def api_scan_start():
    if _auth_required():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    paths = data.get("paths") or None

    if scanner._scan_running:
        return jsonify({"error": "Scan already running"}), 409

    def _run():
        scanner.run_scan(paths=paths, triggered_by="manual")

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "started"})


@app.route("/api/scan/progress")
def api_scan_progress():
    if _auth_required():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(scanner.get_progress())


@app.route("/api/history")
def api_history():
    if _auth_required():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(list(reversed(scanner._load_history())))


@app.route("/api/history/clear", methods=["POST"])
def api_history_clear():
    if _auth_required():
        return jsonify({"error": "Unauthorized"}), 401
    scanner._save_history([])
    return jsonify({"status": "cleared"})


@app.route("/api/signatures/update", methods=["POST"])
def api_signatures_update():
    if _auth_required():
        return jsonify({"error": "Unauthorized"}), 401

    def _run():
        scanner.update_signatures()

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "updating"})


@app.route("/api/quarantine")
def api_quarantine():
    if _auth_required():
        return jsonify({"error": "Unauthorized"}), 401
    return jsonify(scanner.list_quarantine())


@app.route("/api/quarantine/delete", methods=["POST"])
def api_quarantine_delete():
    if _auth_required():
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    filename = data.get("filename", "")
    if not filename:
        return jsonify({"error": "No filename"}), 400
    ok = scanner.delete_quarantine_file(filename)
    return jsonify({"deleted": ok})


@app.route("/api/status")
def api_status():
    import subprocess
    clamd_ok = False
    try:
        r = subprocess.run(["clamdscan", "--version"], capture_output=True, timeout=5)
        clamd_ok = r.returncode == 0
    except Exception:
        pass
    history = scanner._load_history()
    last = history[-1] if history else None
    return jsonify({
        "clamd": clamd_ok,
        "last_scan": last,
        "sig_info": scanner.get_signature_info(),
        "progress": scanner.get_progress(),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=WEB_PORT, debug=False)
