import os
from pathlib import Path


class Config:
    BASE_DIR = Path(__file__).resolve().parent.parent

    SECRET_KEY = os.getenv("SECRET_KEY", "change-this-in-production")
    DATABASE_PATH = os.getenv("DATABASE_PATH", str(BASE_DIR / "cypher.db"))

    SESSION_DAYS = int(os.getenv("SESSION_DAYS", "7"))
    ALLOW_INSECURE_OAUTH = os.getenv("ALLOW_INSECURE_OAUTH", "false").lower() == "true"

    VT_API_KEY = os.getenv("VT_API_KEY", "")
    GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
    GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET", "")
    OAUTH_REDIRECT_URI = os.getenv("OAUTH_REDIRECT_URI", "")

    MAX_CONTENT_LENGTH = int(os.getenv("MAX_UPLOAD_BYTES", str(20 * 1024 * 1024)))

    SMTP_HOST = os.getenv("SMTP_HOST", "")
    SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
    SMTP_USER = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
    SMTP_USE_TLS = os.getenv("SMTP_USE_TLS", "true").lower() == "true"
    MAIL_FROM = os.getenv("MAIL_FROM", SMTP_USER)
    MAIL_ENABLED = os.getenv("MAIL_ENABLED", "true").lower() == "true"
