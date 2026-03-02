import hashlib
import secrets
import time
from datetime import datetime

from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app import oauth
from app.db import get_db
from app.services.notifications import push_notification
from app.services.notify import send_login_notification, send_password_reset_code, send_security_alert

web_bp = Blueprint("web", __name__)


@web_bp.route("/healthz")
def healthz():
    return {"status": "ok"}, 200


def _best_effort_location(request_obj) -> str:
    city = request_obj.headers.get("X-AppEngine-City") or request_obj.headers.get("CF-IPCity") or ""
    region = request_obj.headers.get("X-AppEngine-Region") or request_obj.headers.get("CF-IPRegion") or ""
    country = request_obj.headers.get("X-AppEngine-Country") or request_obj.headers.get("CF-IPCountry") or ""
    parts = [part for part in [city, region, country] if part]
    return ", ".join(parts) if parts else "Unknown"


@web_bp.route("/")
def home():
    if session.get("logged_in"):
        return redirect(url_for("web.dashboard"))
    return render_template("login.html")


@web_bp.route("/dashboard")
def dashboard():
    email = session.get("user_email")
    if not email:
        return redirect(url_for("web.home"))

    show_tour = request.args.get("tour", "false") == "true"
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    history = conn.execute(
        "SELECT * FROM history WHERE email = ? ORDER BY timestamp DESC LIMIT 10",
        (email,),
    ).fetchall()
    patterns = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
    unread_notifications = conn.execute(
        "SELECT COUNT(*) FROM notifications WHERE email = ? AND is_read = 0",
        (email,),
    ).fetchone()[0]
    return render_template(
        "dashboard.html",
        user=user,
        history=history,
        show_tour=show_tour,
        ai_stats={"patterns_learned": patterns},
        unread_notifications=unread_notifications,
    )


@web_bp.route("/app-vault")
def app_vault_page():
    email = session.get("user_email")
    if not email:
        return redirect(url_for("web.home"))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    unread_notifications = conn.execute(
        "SELECT COUNT(*) FROM notifications WHERE email = ? AND is_read = 0",
        (email,),
    ).fetchone()[0]
    return render_template("app_vault.html", user=user, unread_notifications=unread_notifications)


@web_bp.route("/deep-scan")
def deep_scan_page():
    email = session.get("user_email")
    if not email:
        return redirect(url_for("web.home"))
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    return render_template("deep_scan.html", user=user)


@web_bp.route("/subscription")
def subscription():
    return render_template("subscription.html")


@web_bp.route("/login", methods=["POST"])
def login():
    email = (request.form.get("email") or "").strip().lower()
    password = request.form.get("password") or ""
    if not email or not password:
        flash("Email and password are required.")
        return redirect(url_for("web.home"))

    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if user is None:
        name = email.split("@")[0].replace(".", " ").title()
        conn.execute(
            "INSERT INTO users (email, name, profile_pic, scans, threats, password_hash) VALUES (?, ?, ?, 0, 0, ?)",
            (email, name, "", generate_password_hash(password)),
        )
        conn.commit()
    else:
        saved_hash = user["password_hash"]
        if saved_hash:
            if not check_password_hash(saved_hash, password):
                flash("Invalid credentials.")
                return redirect(url_for("web.home"))
        else:
            conn.execute("UPDATE users SET password_hash = ? WHERE email = ?", (generate_password_hash(password), email))
            conn.commit()

    session.update({"logged_in": True, "user_email": email, "login_at": datetime.utcnow().isoformat()})
    send_login_notification(
        current_app._get_current_object(),
        email=email,
        method="Email/Password",
        ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
        user_agent=request.user_agent.string,
        location=_best_effort_location(request),
    )
    push_notification(
        conn,
        email,
        "New Login",
        f"Email/Password login from {request.headers.get('X-Forwarded-For', request.remote_addr) or 'Unknown IP'}",
        "info",
    )
    conn.commit()
    return redirect(url_for("web.dashboard"))


@web_bp.route("/google-login")
def google_login():
    google = oauth.create_client("google")
    redirect_uri = current_app.config.get("OAUTH_REDIRECT_URI") or url_for("web.auth", _external=True)
    return google.authorize_redirect(redirect_uri)


@web_bp.route("/auth")
def auth():
    google = oauth.create_client("google")
    token = google.authorize_access_token()
    user_info = token.get("userinfo")
    if not user_info:
        return redirect(url_for("web.home"))

    email = user_info["email"]
    conn = get_db()
    existing = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not existing:
        conn.execute(
            "INSERT INTO users (email, name, profile_pic, scans, threats, password_hash) VALUES (?, ?, ?, 0, 0, NULL)",
            (email, user_info.get("name", email), user_info.get("picture", "")),
        )
        conn.commit()

    session.update({"logged_in": True, "user_email": email, "login_at": datetime.utcnow().isoformat()})
    send_login_notification(
        current_app._get_current_object(),
        email=email,
        method="Google OAuth",
        ip_address=request.headers.get("X-Forwarded-For", request.remote_addr),
        user_agent=request.user_agent.string,
        location=_best_effort_location(request),
    )
    push_notification(
        conn,
        email,
        "New Login",
        f"Google OAuth login from {request.headers.get('X-Forwarded-For', request.remote_addr) or 'Unknown IP'}",
        "info",
    )
    conn.commit()
    return redirect(url_for("web.dashboard", tour="true"))


@web_bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("web.home"))


@web_bp.route("/forgot-password/request", methods=["POST"])
def forgot_password_request():
    email = (request.form.get("email") or "").strip().lower()
    if not email:
        flash("Please enter a valid email.", "error")
        return redirect(url_for("web.home"))

    conn = get_db()
    user = conn.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
    # Generic response to prevent user enumeration
    if user:
        code = f"{secrets.randbelow(1000000):06d}"
        raw = f"{email}|{code}|{current_app.config['SECRET_KEY']}"
        code_hash = hashlib.sha256(raw.encode()).hexdigest()
        now = int(time.time())
        expiry_minutes = 10
        expires_at = now + expiry_minutes * 60

        conn.execute("UPDATE password_reset_codes SET used = 1 WHERE email = ? AND used = 0", (email,))
        conn.execute(
            "INSERT INTO password_reset_codes (email, code_hash, expires_at, used, created_at) VALUES (?, ?, ?, 0, ?)",
            (email, code_hash, expires_at, now),
        )
        conn.commit()

        send_password_reset_code(current_app._get_current_object(), email, code, expiry_minutes)

    flash("If account exists, a verification code has been sent to your email.", "info")
    return redirect(url_for("web.home"))


@web_bp.route("/forgot-password/verify", methods=["POST"])
def forgot_password_verify():
    email = (request.form.get("email") or "").strip().lower()
    code = (request.form.get("code") or "").strip()
    new_password = request.form.get("new_password") or ""

    if not email or not code or not new_password:
        flash("Email, code, and new password are required.", "error")
        return redirect(url_for("web.home"))
    if len(new_password) < 8:
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for("web.home"))

    conn = get_db()
    row = conn.execute(
        """
        SELECT id, code_hash, expires_at, used
        FROM password_reset_codes
        WHERE email = ?
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (email,),
    ).fetchone()
    if not row:
        flash("Invalid or expired code.", "error")
        return redirect(url_for("web.home"))

    now = int(time.time())
    raw = f"{email}|{code}|{current_app.config['SECRET_KEY']}"
    expected_hash = hashlib.sha256(raw.encode()).hexdigest()
    if row["used"] or now > row["expires_at"] or expected_hash != row["code_hash"]:
        flash("Invalid or expired code.", "error")
        return redirect(url_for("web.home"))

    user = conn.execute("SELECT email FROM users WHERE email = ?", (email,)).fetchone()
    if not user:
        flash("Invalid account.", "error")
        return redirect(url_for("web.home"))

    conn.execute("UPDATE users SET password_hash = ? WHERE email = ?", (generate_password_hash(new_password), email))
    conn.execute("UPDATE password_reset_codes SET used = 1 WHERE id = ?", (row["id"],))
    conn.commit()

    send_security_alert(
        current_app._get_current_object(),
        email=email,
        title="Password Changed",
        details="Your CypherScout account password was updated successfully.",
    )

    flash("Password updated. You can login now.", "success")
    return redirect(url_for("web.home"))
