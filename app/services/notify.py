import smtplib
import threading
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from flask import current_app


def _mail_ready() -> bool:
    cfg = current_app.config
    return bool(
        cfg.get("MAIL_ENABLED")
        and cfg.get("SMTP_HOST")
        and cfg.get("SMTP_USER")
        and cfg.get("SMTP_PASSWORD")
        and cfg.get("MAIL_FROM")
    )


def send_email(recipient: str, subject: str, html_body: str, text_body: str = "") -> bool:
    if not _mail_ready():
        return False

    cfg = current_app.config
    message = MIMEMultipart("alternative")
    message["Subject"] = subject
    message["From"] = cfg["MAIL_FROM"]
    message["To"] = recipient
    message.attach(MIMEText(text_body or "Please view this message in HTML format.", "plain", "utf-8"))
    message.attach(MIMEText(html_body, "html", "utf-8"))

    try:
        with smtplib.SMTP(cfg["SMTP_HOST"], cfg["SMTP_PORT"], timeout=12) as server:
            if cfg["SMTP_USE_TLS"]:
                server.starttls()
            server.login(cfg["SMTP_USER"], cfg["SMTP_PASSWORD"])
            server.sendmail(cfg["MAIL_FROM"], [recipient], message.as_string())
        return True
    except Exception:
        return False


def send_email_async(app, recipient: str, subject: str, html_body: str, text_body: str = "") -> None:
    def _worker():
        with app.app_context():
            send_email(recipient, subject, html_body, text_body)

    threading.Thread(target=_worker, daemon=True).start()


def send_password_reset_code(app, email: str, code: str, expiry_minutes: int) -> None:
    subject = "CypherScout Password Reset Code"
    html = f"""
    <div style="font-family:Arial,sans-serif;background:#081627;color:#eaf5ff;padding:24px;border-radius:12px">
      <h2 style="margin:0 0 12px;color:#7fddff">CypherScout Password Reset</h2>
      <p style="margin:0 0 12px">Use this verification code to reset your password:</p>
      <div style="font-size:30px;font-weight:700;letter-spacing:6px;background:#0f2742;padding:10px 16px;border-radius:10px;display:inline-block">{code}</div>
      <p style="margin:14px 0 0;color:#9ec0d9">This code expires in {expiry_minutes} minutes.</p>
    </div>
    """
    send_email_async(app, email, subject, html, f"Your CypherScout reset code is {code}. It expires in {expiry_minutes} minutes.")


def send_login_notification(app, email: str, method: str, ip_address: str, user_agent: str, location: str = "Unknown") -> None:
    subject = "CypherScout Login Notification"
    html = f"""
    <div style="font-family:Arial,sans-serif;background:#081627;color:#eaf5ff;padding:24px;border-radius:12px">
      <h2 style="margin:0 0 12px;color:#7fddff">New Login Detected</h2>
      <p style="margin:0 0 10px">Your account was accessed successfully.</p>
      <ul style="margin:0;padding-left:18px;line-height:1.7">
        <li>Method: {method}</li>
        <li>IP: {ip_address or "Unknown"}</li>
        <li>Device: {user_agent or "Unknown"}</li>
        <li>Location: {location or "Unknown"}</li>
      </ul>
    </div>
    """
    send_email_async(app, email, subject, html, f"New CypherScout login via {method}. IP: {ip_address}. Location: {location}.")


def send_security_alert(app, email: str, title: str, details: str) -> None:
    subject = f"CypherScout Alert: {title}"
    html = f"""
    <div style="font-family:Arial,sans-serif;background:#081627;color:#eaf5ff;padding:24px;border-radius:12px">
      <h2 style="margin:0 0 12px;color:#ff8696">{title}</h2>
      <p style="margin:0;line-height:1.6">{details}</p>
    </div>
    """
    send_email_async(app, email, subject, html, f"{title}: {details}")
