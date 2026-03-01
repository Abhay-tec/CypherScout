import sqlite3
from contextlib import closing

from flask import Flask, g


def get_db() -> sqlite3.Connection:
    if "db_conn" not in g:
        raise RuntimeError("Database connection requested outside app context")
    return g.db_conn


def open_connection(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_database(app: Flask) -> None:
    with closing(open_connection(app.config["DATABASE_PATH"])) as conn:
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
        _ensure_column_exists(conn, "users", "password_hash", "TEXT")
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
