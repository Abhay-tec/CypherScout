from urllib.parse import urlparse

from app.services.trusted_apps import normalize_link_key


def get_effective_trust_level(conn, email: str, app_key: str) -> str:
    row = conn.execute(
        "SELECT trust_level FROM user_app_policies WHERE email = ? AND app_key = ?",
        (email, app_key),
    ).fetchone()
    if not row:
        return "BLOCK"
    value = (row["trust_level"] or "").upper()
    return "BLOCK" if value == "BLOCK" else "ALLOW"


def find_governed_app_from_url(conn, url: str):
    host = normalize_link_key(url)
    if not host:
        return None

    exact = conn.execute(
        "SELECT app_key, display_name, category, host_key FROM governance_apps WHERE host_key = ? LIMIT 1",
        (host,),
    ).fetchone()
    if exact:
        return exact

    suffix = conn.execute(
        """
        SELECT app_key, display_name, category, host_key
        FROM governance_apps
        WHERE ? = host_key OR ? LIKE ('%.' || host_key)
        ORDER BY LENGTH(host_key) DESC
        LIMIT 1
        """,
        (host, host),
    ).fetchone()
    if suffix:
        return suffix

    parsed = urlparse(url if url.startswith(("http://", "https://")) else f"https://{url}")
    token = (parsed.netloc or host).split(".")[0].replace("-", " ").strip()
    fuzzy = conn.execute(
        """
        SELECT app_key, display_name, category, host_key
        FROM governance_apps
        WHERE LOWER(display_name) LIKE ?
        LIMIT 1
        """,
        (f"%{token.lower()}%",),
    ).fetchone()
    return fuzzy
