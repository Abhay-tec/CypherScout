from urllib.parse import urlparse

from app.services.trusted_apps import normalize_app_key, normalize_link_key, normalize_source_type


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


def is_source_allowed_for_real_data(conn, email: str, source: str, source_type: str = "LINK"):
    normalized_type = normalize_source_type(source_type)
    if normalized_type == "LINK":
        source_key = normalize_link_key(source)
        governed_row = find_governed_app_from_url(conn, source)
    else:
        source_key = normalize_app_key(source)
        governed_row = conn.execute(
            "SELECT app_key, display_name, category, host_key FROM governance_apps WHERE app_key = ? LIMIT 1",
            (source_key,),
        ).fetchone()

    if not source_key:
        return False, None, ""

    if governed_row:
        return get_effective_trust_level(conn, email, governed_row["app_key"]) == "ALLOW", governed_row, source_key

    trusted_row = conn.execute(
        """
        SELECT trusted_by_user
        FROM trusted_apps
        WHERE source_type = ? AND app_key = ?
        LIMIT 1
        """,
        (normalized_type, source_key),
    ).fetchone()
    is_user_trusted = bool(trusted_row and int(trusted_row["trusted_by_user"] or 0) == 1)
    return is_user_trusted, None, source_key
