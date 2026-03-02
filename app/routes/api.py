import threading
from datetime import datetime

from flask import Blueprint, current_app, jsonify, request, session

from app.db import get_db
from app.ml import neural_engine
from app.services.intel import NeuralAnalyzer, deep_scan_file, get_url_intel, normalize_url
from app.services.notify import send_security_alert
from app.services.trusted_apps import is_sensitive_permission, normalize_source_key, normalize_source_type

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


def _feedback_source_key(source_type: str, source_key: str) -> str:
    return f"{source_type}::{source_key}"


def _is_source_feedback_malicious(conn, source_type: str, source_key: str, source_raw: str = "") -> bool:
    marker = _feedback_source_key(source_type, source_key)
    row = conn.execute("SELECT manual_status FROM feedback WHERE url = ?", (marker,)).fetchone()
    if row and "MALICIOUS" in (row["manual_status"] or ""):
        return True
    if source_type == "LINK" and source_raw:
        normalized = normalize_url(source_raw)
        row = conn.execute("SELECT manual_status FROM feedback WHERE url = ?", (normalized,)).fetchone()
        if row and "MALICIOUS" in (row["manual_status"] or ""):
            return True
    return False


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
    conn.execute("UPDATE users SET scans = 0, threats = 0 WHERE email = ?", (email,))
    conn.commit()
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


@api_bp.route("/permissions-vault/check", methods=["POST"])
def permissions_vault_check():
    email, err = _require_email()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    source = (data.get("source") or "").strip()
    permission = (data.get("permission") or "").strip().lower()
    source_type = normalize_source_type(data.get("source_type", "app"))
    source_key = normalize_source_key(source, source_type)

    if not source_key:
        return jsonify({"status": "error", "message": "Invalid app/link provided"}), 400

    conn = get_db()
    if _is_source_feedback_malicious(conn, source_type, source_key, source):
        return jsonify(
            {
                "status": "blocked_malicious",
                "message": "This app/link is globally flagged as malicious.",
                "source_key": source_key,
                "source_type": source_type,
                "permission": permission,
                "allow_real_data": False,
                "shadow_injection": True,
                "warning": True,
                "manual_trust_available": False,
                "decision": "deny_real_data",
            }
        )

    trusted_row = conn.execute(
        """
        SELECT display_name, is_preverified, trusted_by_user
        FROM trusted_apps
        WHERE source_type = ? AND app_key = ?
        """,
        (source_type, source_key),
    ).fetchone()

    if trusted_row and is_sensitive_permission(permission):
        trust_mode = "pre_verified" if trusted_row["is_preverified"] else "manual_user_trusted"
        return jsonify(
            {
                "status": "trusted_allow",
                "message": "Trusted source detected. Sensitive permission is auto-allowed.",
                "source_key": source_key,
                "source_type": source_type,
                "permission": permission,
                "allow_real_data": True,
                "shadow_injection": False,
                "warning": False,
                "manual_trust_available": False,
                "decision": trust_mode,
                "display_name": trusted_row["display_name"],
            }
        )

    if trusted_row:
        return jsonify(
            {
                "status": "trusted_allow",
                "message": "Trusted source detected.",
                "source_key": source_key,
                "source_type": source_type,
                "permission": permission,
                "allow_real_data": True,
                "shadow_injection": False,
                "warning": False,
                "manual_trust_available": False,
                "decision": "trusted_non_sensitive",
                "display_name": trusted_row["display_name"],
            }
        )

    return jsonify(
        {
            "status": "unknown_shadow",
            "message": "Warning: This app/link is not pre-verified as secure.",
            "source_key": source_key,
            "source_type": source_type,
            "permission": permission,
            "allow_real_data": False if is_sensitive_permission(permission) else True,
            "shadow_injection": True,
            "warning": True,
            "manual_trust_available": True,
            "decision": "unknown_source_shadow_mode" if is_sensitive_permission(permission) else "unknown_non_sensitive_warn",
            "evaluated_by": email,
        }
    )


@api_bp.route("/permissions-vault/manual-trust", methods=["POST"])
def permissions_vault_manual_trust():
    email, err = _require_email()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    source = (data.get("source") or "").strip()
    source_type = normalize_source_type(data.get("source_type", "app"))
    source_key = normalize_source_key(source, source_type)
    if not source_key:
        return jsonify({"status": "error", "message": "Invalid app/link provided"}), 400

    display_name = source.strip() or source_key
    conn = get_db()
    conn.execute(
        """
        INSERT INTO trusted_apps (source_type, app_key, display_name, category, is_preverified, trusted_by_user, created_by, created_at)
        VALUES (?, ?, ?, 'User Verified', 0, 1, ?, ?)
        ON CONFLICT(source_type, app_key) DO UPDATE SET
            trusted_by_user = 1,
            is_preverified = CASE WHEN trusted_apps.is_preverified = 1 THEN 1 ELSE 0 END,
            display_name = excluded.display_name,
            category = 'User Verified',
            created_by = excluded.created_by
        """,
        (
            source_type,
            source_key,
            display_name,
            email,
            datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    return jsonify({"status": "trusted", "source_key": source_key, "source_type": source_type, "display_name": display_name})


@api_bp.route("/permissions-vault/feedback", methods=["POST"])
def permissions_vault_feedback():
    email, err = _require_email()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    source = (data.get("source") or "").strip()
    verdict = (data.get("verdict") or "").strip().lower()
    source_type = normalize_source_type(data.get("source_type", "app"))
    source_key = normalize_source_key(source, source_type)
    if not source_key:
        return jsonify({"status": "error", "message": "Invalid app/link provided"}), 400
    if verdict not in {"right", "wrong"}:
        return jsonify({"status": "error", "message": "verdict must be right or wrong"}), 400

    feedback_key = _feedback_source_key(source_type, source_key)
    manual_status = "MALICIOUS (User Trained)" if verdict == "wrong" else "CLEAN (User Verified)"
    conn = get_db()
    conn.execute("INSERT OR REPLACE INTO feedback (url, manual_status) VALUES (?, ?)", (feedback_key, manual_status))
    conn.commit()

    if verdict == "wrong":
        threading.Thread(
            target=neural_engine.train_from_db,
            args=(current_app.config["DATABASE_PATH"],),
            daemon=True,
        ).start()
        send_security_alert(
            current_app._get_current_object(),
            email=email,
            title="Permissions Vault Malicious Report",
            details=f"Source marked malicious and propagated to model learning.<br>Source: {feedback_key}",
        )
        return jsonify({"status": "learned_malicious", "source": feedback_key})

    return jsonify({"status": "recorded_clean", "source": feedback_key})
