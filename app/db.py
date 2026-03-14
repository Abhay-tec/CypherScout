import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
import shutil
import os

from flask import Flask, g

from app.services.governance_catalog import build_app_catalog

DEFAULT_TRUSTED_APPS = [
    ("APP", "whatsapp", "WhatsApp", "Messaging"),
    ("APP", "instagram", "Instagram", "Social"),
    ("APP", "gmail", "Gmail", "Email"),
    ("APP", "google-messages", "Google Messages", "Messaging"),
    ("APP", "google-photos", "Google Photos", "Gallery"),
    ("APP", "google-drive", "Google Drive", "Cloud Storage"),
    ("APP", "phonepe", "PhonePe", "Banking"),
    ("APP", "google-pay", "Google Pay", "Banking"),
    ("APP", "paytm", "Paytm", "Banking"),
    ("APP", "sbi-yono", "SBI YONO", "Banking"),
    ("APP", "hdfc-bank", "HDFC Bank", "Banking"),
    ("APP", "icici-imobile", "ICICI iMobile", "Banking"),
    ("LINK", "whatsapp.com", "WhatsApp", "Messaging"),
    ("LINK", "instagram.com", "Instagram", "Social"),
    ("LINK", "mail.google.com", "Gmail", "Email"),
    ("LINK", "accounts.google.com", "Google Accounts", "Identity"),
    ("LINK", "drive.google.com", "Google Drive", "Cloud Storage"),
]


def get_db() -> sqlite3.Connection:
    if "db_conn" not in g:
        raise RuntimeError("Database connection requested outside app context")
    return g.db_conn


def open_connection(db_path: str) -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return conn
    except sqlite3.OperationalError:
        # Fallback for read-only root in serverless: try a writable /tmp copy.
        tmp_path = "/tmp/cypher.db"
        if db_path != tmp_path:
            try:
                Path("/tmp").mkdir(parents=True, exist_ok=True)
                bundled = Path(db_path)
                if bundled.exists():
                    shutil.copyfile(bundled, tmp_path)
                conn = sqlite3.connect(tmp_path)
                conn.row_factory = sqlite3.Row
                return conn
            except Exception:
                pass
        raise


def init_database(app: Flask) -> None:
    db_path = Path(app.config["DATABASE_PATH"])
    # If packaged DB is read-only (e.g., /var/task on Vercel), work on a /tmp copy.
    if not (db_path.exists() and os.access(db_path, os.W_OK)) or str(db_path).startswith("/var/task"):
        tmp_path = Path("/tmp/cypher.db")
        try:
            tmp_path.parent.mkdir(parents=True, exist_ok=True)
            if db_path.exists() and not tmp_path.exists():
                shutil.copyfile(db_path, tmp_path)
            app.config["DATABASE_PATH"] = str(tmp_path)
            db_path = tmp_path
        except Exception:
            # If copy fails, continue with original path (may still be writable)
            pass

    with closing(open_connection(str(db_path))) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                name TEXT,
                profile_pic TEXT,
                scans INTEGER DEFAULT 0,
                threats INTEGER DEFAULT 0,
                password_hash TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                url TEXT,
                status TEXT,
                user_feedback TEXT,
                timestamp TEXT,
                UNIQUE(email, url)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                manual_status TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS password_reset_codes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                used INTEGER DEFAULT 0,
                created_at INTEGER NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS trusted_apps (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_type TEXT NOT NULL,
                app_key TEXT NOT NULL,
                display_name TEXT NOT NULL,
                category TEXT,
                is_preverified INTEGER DEFAULT 1,
                trusted_by_user INTEGER DEFAULT 0,
                created_by TEXT DEFAULT 'system',
                created_at TEXT,
                UNIQUE(source_type, app_key)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS governance_apps (
                app_key TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                category TEXT NOT NULL,
                homepage TEXT,
                host_key TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS user_app_policies (
                email TEXT NOT NULL,
                app_key TEXT NOT NULL,
                trust_level TEXT NOT NULL,
                updated_at TEXT,
                PRIMARY KEY (email, app_key)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                level TEXT DEFAULT 'info',
                is_read INTEGER DEFAULT 0,
                created_at TEXT
            )
            """
        )
        conn.execute("CREATE INDEX IF NOT EXISTS idx_governance_apps_name ON governance_apps(display_name)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_governance_apps_category ON governance_apps(category)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_governance_apps_host ON governance_apps(host_key)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_notifications_email ON notifications(email, is_read, created_at)")
        _ensure_column_exists(conn, "users", "password_hash", "TEXT")
        _ensure_column_exists(conn, "history", "user_feedback", "TEXT")
        _seed_trusted_apps(conn)
        _seed_governance_apps(conn)
        conn.commit()

    @app.before_request
    def _bind_db_connection() -> None:
        g.db_conn = open_connection(app.config["DATABASE_PATH"])

    @app.teardown_request
    def _close_db_connection(_exc) -> None:
        conn = g.pop("db_conn", None)
        if conn:
            conn.close()


def _ensure_column_exists(conn: sqlite3.Connection, table: str, column: str, col_type: str) -> None:
    columns = [row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()]
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_type}")


def _seed_trusted_apps(conn: sqlite3.Connection) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    conn.executemany(
        """
        INSERT OR IGNORE INTO trusted_apps
            (source_type, app_key, display_name, category, is_preverified, trusted_by_user, created_by, created_at)
        VALUES (?, ?, ?, ?, 1, 0, 'system', ?)
        """,
        [(source_type, app_key, display_name, category, now) for source_type, app_key, display_name, category in DEFAULT_TRUSTED_APPS],
    )


def _seed_governance_apps(conn: sqlite3.Connection) -> None:
    apps = build_app_catalog()
    conn.executemany(
        """
        INSERT OR IGNORE INTO governance_apps (app_key, display_name, category, homepage, host_key)
        VALUES (?, ?, ?, ?, ?)
        """,
        [(app["app_key"], app["display_name"], app["category"], app["homepage"], app["host_key"]) for app in apps],
    )
