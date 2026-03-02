from datetime import datetime


def push_notification(conn, email: str, title: str, message: str, level: str = "info") -> None:
    conn.execute(
        """
        INSERT INTO notifications (email, title, message, level, is_read, created_at)
        VALUES (?, ?, ?, ?, 0, ?)
        """,
        (email, title, message, level, datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")),
    )
