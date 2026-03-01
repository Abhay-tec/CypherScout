import threading
from datetime import datetime

from flask import Blueprint, current_app, jsonify, request, session

from app.db import get_db
from app.ml import neural_engine
from app.services.intel import NeuralAnalyzer, deep_scan_file, get_url_intel, normalize_url
from app.services.notify import send_security_alert

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _require_email():
    email = session.get("user_email")
    if not email:
        return None, (jsonify({"status": "unauthorized"}), 401)
    return email, None


def _refresh_user_metrics(conn, email: str):
    total_scans = conn.execute("SELECT COUNT(*) FROM history WHERE email = ?", (email,)).fetchone()[0]
    total_threats = conn.execute(
        'SELECT COUNT(*) FROM history WHERE email = ? AND status LIKE "MALICIOUS%"',
        (email,),
    ).fetchone()[0]
    conn.execute("UPDATE users SET scans = ?, threats = ? WHERE email = ?", (total_scans, total_threats, email))


@api_bp.route("/analyze", methods=["POST"])
def analyze_api():
    email, err = _require_email()
    if err:
        return err

    payload = request.get_json(silent=True) or {}
    url = normalize_url(payload.get("url", ""))
    conn = get_db()
    exact = conn.execute("SELECT manual_status FROM feedback WHERE url = ?", (url,)).fetchone()
    exact_status = exact["manual_status"] if exact else None

    analyzer = NeuralAnalyzer(url, vt_api_key=current_app.config["VT_API_KEY"])
    is_threat, status, vendors, stats = analyzer.analyze(exact_status)

    conn.execute(
        "INSERT OR REPLACE INTO history (email, url, status, timestamp) VALUES (?, ?, ?, ?)",
        (email, url, status, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
    )
    _refresh_user_metrics(conn, email)
    conn.commit()
    if status.startswith("MALICIOUS") or status.startswith("SUSPICIOUS"):
        send_security_alert(
            current_app._get_current_object(),
            email=email,
            title="URL Threat Detected",
            details=f"URL: {url}<br>Status: {status}",
        )
    return jsonify({"status": status, "is_threat": is_threat, "vendors": vendors, "stats": stats})


@api_bp.route("/deep-scan", methods=["POST"])
def deep_scan_api():
    email, err = _require_email()
    if err:
        return err

    uploaded = request.files.get("file")
    if not uploaded or uploaded.filename == "":
        return jsonify({"status": "error", "message": "No file provided"}), 400

    result = deep_scan_file(uploaded)
    marker = f"FILE::{result['filename']}::{result['sha256'][:12]}"

    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO history (email, url, status, timestamp) VALUES (?, ?, ?, ?)",
        (email, marker, result["status"], datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
    )
    _refresh_user_metrics(conn, email)
    conn.commit()
    if result["status"].startswith("MALICIOUS") or result["status"].startswith("SUSPICIOUS"):
        send_security_alert(
            current_app._get_current_object(),
            email=email,
            title="File Scan Alert",
            details=f"File: {result['filename']}<br>Status: {result['status']}<br>Risk Score: {result['risk_score']}",
        )
    return jsonify(result)


@api_bp.route("/url-intel", methods=["POST"])
def url_intel_api():
    email, err = _require_email()
    if err:
        return err

    payload = request.get_json(silent=True) or {}
    intel = get_url_intel(payload.get("url", ""))
    if intel.get("status") != "ok":
        return jsonify(intel), 400
    return jsonify(intel)


@api_bp.route("/reset-all", methods=["POST"])
def reset_all():
    email, err = _require_email()
    if err:
        return err

    conn = get_db()
    conn.execute("DELETE FROM history WHERE email = ?", (email,))
    conn.execute("DELETE FROM feedback")
    conn.execute("UPDATE users SET scans = 0, threats = 0 WHERE email = ?", (email,))
    conn.commit()
    neural_engine.train_from_db(current_app.config["DATABASE_PATH"])
    return jsonify({"success": True})


@api_bp.route("/report-scam", methods=["POST"])
def report_scam():
    email, err = _require_email()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    url = normalize_url(data.get("url", ""))
    new_status = "MALICIOUS (User Trained)"

    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO feedback (url, manual_status) VALUES (?, ?)", (url, new_status))
    conn.execute("UPDATE history SET status = ? WHERE url = ? AND email = ?", (new_status, url, email))
    _refresh_user_metrics(conn, email)
    conn.commit()

    threading.Thread(
        target=neural_engine.train_from_db,
        args=(current_app.config["DATABASE_PATH"],),
        daemon=True,
    ).start()
    send_security_alert(
        current_app._get_current_object(),
        email=email,
        title="Manual Scam Report Recorded",
        details=f"A reported URL has been marked as malicious and used for model retraining.<br>URL: {url}",
    )
    return jsonify({"status": "Learned"})
