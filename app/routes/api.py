import json
import threading
from datetime import datetime
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request, session

from app.db import get_db
from app.ml import neural_engine
from app.services.governance import find_governed_app_from_url, get_effective_trust_level
from app.services.intel import NeuralAnalyzer, deep_scan_file, get_url_intel, normalize_url
from app.services.notifications import push_notification
from app.services.notify import send_security_alert
from app.services.trusted_apps import (
    is_always_trusted_link,
    is_sensitive_permission,
    normalize_source_key,
    normalize_source_type,
    persist_whitelist_link,
)

api_bp = Blueprint("api", __name__, url_prefix="/api")


def _require_email():
    email = session.get("user_email")
    if not email:
        return None, (jsonify({"status": "unauthorized"}), 401)
    return email, None


def _refresh_user_metrics(conn, email: str):
    total_scans = conn.execute("SELECT COUNT(*) FROM history WHERE email = ?", (email,)).fetchone()[0]
    total_threats = conn.execute(
        'SELECT COUNT(*) FROM history WHERE email = ? AND (status LIKE "MALICIOUS%" OR status LIKE "SUSPICIOUS%" OR status LIKE "BLOCKED%")',
        (email,),
    ).fetchone()[0]
    conn.execute("UPDATE users SET scans = ?, threats = ? WHERE email = ?", (total_scans, total_threats, email))


def _feedback_source_key(source_type: str, source_key: str) -> str:
    return f"{source_type}::{source_key}"


def _load_shadow_bundle() -> dict:
    bundle_path = Path(current_app.root_path).parent / "app" / "data" / "shadow_bundle.json"
    try:
        payload = json.loads(bundle_path.read_text(encoding="utf-8"))
        return payload
    except Exception:
        contacts = [{"name": f"Shadow Contact {i:03d}", "phone": f"+91-900000{i:04d}", "email": f"shadow{i:03d}@privacy.local"} for i in range(1, 101)]
        return {
            "profile": {"name": "Shadow User", "email": "shadow@privacy.local"},
            "contacts": contacts,
            "gallery_paths": ["/storage/emulated/0/DCIM/.shadow/empty_album"],
            "files": ["IMG_SHADOW_0001.jpg"],
        }


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
    if not url:
        return jsonify({"status": "error", "message": "URL is required"}), 400

    conn = get_db()
    governed_app = find_governed_app_from_url(conn, url)
    if governed_app and get_effective_trust_level(conn, email, governed_app["app_key"]) == "BLOCK":
        status = "BLOCKED (Shadow Mode)"
        conn.execute(
            "INSERT OR REPLACE INTO history (email, url, status, timestamp) VALUES (?, ?, ?, ?)",
            (email, url, status, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        )
        push_notification(
            conn,
            email,
            "Privacy Shield Active",
            f"Fake data injected for blocked app: {governed_app['display_name']}",
            "danger",
        )
        _refresh_user_metrics(conn, email)
        conn.commit()
        send_security_alert(
            current_app._get_current_object(),
            email=email,
            title="Action Required: Shadow Mode Activated",
            details=f"A blocked app attempted sensitive access.<br>App: {governed_app['display_name']}<br>URL: {url}",
        )
        return jsonify(
            {
                "status": status,
                "is_threat": True,
                "shadow_mode": True,
                "app_name": governed_app["display_name"],
                "alert": f"Privacy Shield Active: Fake Data Injected for {governed_app['display_name']}",
                "shadow_bundle": _load_shadow_bundle(),
                "vendors": [],
                "stats": {},
            }
        )

    exact = conn.execute("SELECT manual_status FROM feedback WHERE url = ?", (url,)).fetchone()
    exact_status = exact["manual_status"] if exact else None
    if is_always_trusted_link(url):
        exact_status = "VERIFIED SECURE (Whitelisted)"

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
    return jsonify({"status": status, "is_threat": is_threat, "shadow_mode": False, "vendors": vendors, "stats": stats})


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
    conn.execute("DELETE FROM notifications WHERE email = ?", (email,))
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


@api_bp.route("/history-feedback", methods=["POST"])
def history_feedback():
    email, err = _require_email()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    url = normalize_url(data.get("url", ""))
    verdict = (data.get("verdict") or "").strip().lower()
    current_status = (data.get("current_status") or "").strip().upper()
    if verdict not in {"right", "wrong"}:
        return jsonify({"status": "error", "message": "verdict must be right or wrong"}), 400

    conn = get_db()
    if verdict == "wrong" and ("MALICIOUS" in current_status or "SUSPICIOUS" in current_status or "BLOCKED" in current_status):
        trusted_key = persist_whitelist_link(url)
        if not trusted_key:
            return jsonify({"status": "error", "message": "Unable to whitelist link"}), 500
        conn.execute(
            """
            INSERT INTO trusted_apps (source_type, app_key, display_name, category, is_preverified, trusted_by_user, created_by, created_at)
            VALUES ('LINK', ?, ?, 'User Corrected', 1, 1, ?, ?)
            ON CONFLICT(source_type, app_key) DO UPDATE SET trusted_by_user = 1, is_preverified = 1
            """,
            (trusted_key, trusted_key, email, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
        )
        conn.execute("INSERT OR REPLACE INTO feedback (url, manual_status) VALUES (?, ?)", (url, "VERIFIED SECURE (User Corrected)"))
        conn.execute("UPDATE history SET status = ? WHERE email = ? AND url = ?", ("VERIFIED SECURE", email, url))
        push_notification(conn, email, "Whitelist Updated", f"URL permanently trusted: {trusted_key}", "success")
        _refresh_user_metrics(conn, email)
        conn.commit()
        return jsonify({"status": "whitelisted", "trusted_key": trusted_key})

    if verdict == "wrong":
        conn.execute("INSERT OR REPLACE INTO feedback (url, manual_status) VALUES (?, ?)", (url, "MALICIOUS (User Trained)"))
        conn.execute("UPDATE history SET status = ? WHERE email = ? AND url = ?", ("MALICIOUS (User Trained)", email, url))
        push_notification(conn, email, "Threat Training Updated", f"Marked malicious: {url}", "danger")
        _refresh_user_metrics(conn, email)
        conn.commit()
        threading.Thread(
            target=neural_engine.train_from_db,
            args=(current_app.config["DATABASE_PATH"],),
            daemon=True,
        ).start()
        return jsonify({"status": "learned_malicious"})

    push_notification(conn, email, "Feedback Saved", f"Marked as correct: {url}", "info")
    conn.commit()
    return jsonify({"status": "recorded_right"})


@api_bp.route("/app-governance/apps", methods=["GET"])
def app_governance_apps():
    email, err = _require_email()
    if err:
        return err

    query = (request.args.get("q") or "").strip().lower()
    category = (request.args.get("category") or "All").strip()
    limit = min(max(int(request.args.get("limit", "400")), 1), 500)

    conn = get_db()
    params = [email]
    where_clauses = []
    if query:
        where_clauses.append("LOWER(g.display_name) LIKE ?")
        params.append(f"%{query}%")
    if category and category.lower() != "all":
        where_clauses.append("g.category = ?")
        params.append(category)

    where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
    rows = conn.execute(
        f"""
        SELECT
            g.app_key,
            g.display_name,
            g.category,
            g.homepage,
            COALESCE(p.trust_level, 'ALLOW') AS trust_level
        FROM governance_apps g
        LEFT JOIN user_app_policies p ON p.app_key = g.app_key AND p.email = ?
        {where_sql}
        ORDER BY g.display_name
        LIMIT ?
        """,
        (*params, limit),
    ).fetchall()
    categories = conn.execute("SELECT DISTINCT category FROM governance_apps ORDER BY category").fetchall()
    return jsonify(
        {
            "apps": [dict(row) for row in rows],
            "categories": ["All", *[row["category"] for row in categories]],
            "total_catalog": conn.execute("SELECT COUNT(*) FROM governance_apps").fetchone()[0],
        }
    )


@api_bp.route("/app-governance/toggle", methods=["POST"])
def app_governance_toggle():
    email, err = _require_email()
    if err:
        return err

    data = request.get_json(silent=True) or {}
    app_key = (data.get("app_key") or "").strip().lower()
    trust_level = (data.get("trust_level") or "ALLOW").strip().upper()
    if trust_level not in {"ALLOW", "BLOCK"} or not app_key:
        return jsonify({"status": "error", "message": "Invalid trust update"}), 400

    conn = get_db()
    app_row = conn.execute("SELECT display_name FROM governance_apps WHERE app_key = ?", (app_key,)).fetchone()
    if not app_row:
        return jsonify({"status": "error", "message": "App not found"}), 404

    conn.execute(
        """
        INSERT INTO user_app_policies (email, app_key, trust_level, updated_at)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(email, app_key) DO UPDATE SET trust_level = excluded.trust_level, updated_at = excluded.updated_at
        """,
        (email, app_key, trust_level, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
    )
    if trust_level == "BLOCK":
        push_notification(conn, email, "App Blocked", f"Shadow Mode will trigger for {app_row['display_name']}", "danger")
    else:
        push_notification(conn, email, "App Allowed", f"Real permissions restored for {app_row['display_name']}", "success")
    conn.commit()
    return jsonify({"status": "ok", "app_key": app_key, "trust_level": trust_level})


@api_bp.route("/notifications", methods=["GET"])
def notifications_list():
    email, err = _require_email()
    if err:
        return err

    conn = get_db()
    rows = conn.execute(
        """
        SELECT id, title, message, level, is_read, created_at
        FROM notifications
        WHERE email = ?
        ORDER BY id DESC
        LIMIT 50
        """,
        (email,),
    ).fetchall()
    unread = conn.execute("SELECT COUNT(*) FROM notifications WHERE email = ? AND is_read = 0", (email,)).fetchone()[0]
    return jsonify({"notifications": [dict(row) for row in rows], "unread_count": unread})


@api_bp.route("/notifications/read", methods=["POST"])
def notifications_mark_read():
    email, err = _require_email()
    if err:
        return err
    conn = get_db()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE email = ?", (email,))
    conn.commit()
    return jsonify({"status": "ok"})


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
                "message": "Warning: This app/link is not pre-verified as secure.",
                "source_key": source_key,
                "source_type": source_type,
                "permission": permission,
                "allow_real_data": False,
                "shadow_injection": True,
                "warning": True,
                "manual_trust_available": True,
                "decision": "deny_real_data",
                "alert": "Privacy Shield Active: Fake Data Injected",
            }
        )

    if source_type == "LINK":
        app_row = find_governed_app_from_url(conn, source)
    else:
        app_row = conn.execute(
            "SELECT app_key, display_name FROM governance_apps WHERE app_key = ? OR LOWER(display_name) = ? LIMIT 1",
            (source_key, source.lower()),
        ).fetchone()

    if app_row and get_effective_trust_level(conn, email, app_row["app_key"]) == "BLOCK":
        return jsonify(
            {
                "status": "blocked_shadow",
                "message": "Warning: This app/link is marked as unwanted.",
                "source_key": source_key,
                "source_type": source_type,
                "permission": permission,
                "allow_real_data": False,
                "shadow_injection": True,
                "warning": True,
                "manual_trust_available": True,
                "decision": "user_block_policy",
                "display_name": app_row["display_name"],
                "alert": f"Privacy Shield Active: Fake Data Injected for {app_row['display_name']}",
            }
        )

    trusted_row = conn.execute(
        """
        SELECT display_name
        FROM trusted_apps
        WHERE source_type = ? AND app_key = ?
        """,
        (source_type, source_key),
    ).fetchone()
    if trusted_row and is_sensitive_permission(permission):
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
                "decision": "trusted_allow",
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
            "decision": "unknown_source_shadow_mode",
            "shadow_bundle": _load_shadow_bundle(),
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

    conn = get_db()
    display_name = source or source_key
    conn.execute(
        """
        INSERT INTO trusted_apps (source_type, app_key, display_name, category, is_preverified, trusted_by_user, created_by, created_at)
        VALUES (?, ?, ?, 'User Verified', 0, 1, ?, ?)
        ON CONFLICT(source_type, app_key) DO UPDATE SET trusted_by_user = 1, display_name = excluded.display_name
        """,
        (source_type, source_key, display_name, email, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
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
    if verdict not in {"right", "wrong"} or not source_key:
        return jsonify({"status": "error", "message": "Invalid payload"}), 400

    conn = get_db()
    if verdict == "wrong" and source_type == "LINK":
        trusted_key = persist_whitelist_link(source)
        if trusted_key:
            conn.execute("INSERT OR REPLACE INTO feedback (url, manual_status) VALUES (?, ?)", (_feedback_source_key(source_type, source_key), "VERIFIED SECURE"))
            conn.commit()
            return jsonify({"status": "whitelisted", "source": trusted_key})

    manual_status = "MALICIOUS (User Trained)" if verdict == "wrong" else "CLEAN (User Verified)"
    conn.execute("INSERT OR REPLACE INTO feedback (url, manual_status) VALUES (?, ?)", (_feedback_source_key(source_type, source_key), manual_status))
    conn.commit()
    if verdict == "wrong":
        threading.Thread(target=neural_engine.train_from_db, args=(current_app.config["DATABASE_PATH"],), daemon=True).start()
    return jsonify({"status": "recorded"})
