import re
from urllib.parse import urlparse

SENSITIVE_PERMISSIONS = {"contacts", "gallery"}


def normalize_source_type(source_type: str) -> str:
    return "LINK" if (source_type or "").strip().lower() == "link" else "APP"


def normalize_app_key(source: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", "-", (source or "").strip().lower()).strip("-")
    return cleaned


def normalize_link_key(source: str) -> str:
    text = (source or "").strip().lower()
    if not text:
        return ""
    if not text.startswith(("http://", "https://")):
        text = f"https://{text}"
    host = (urlparse(text).netloc or "").lower()
    if host.startswith("www."):
        host = host[4:]
    return host


def normalize_source_key(source: str, source_type: str) -> str:
    if normalize_source_type(source_type) == "LINK":
        return normalize_link_key(source)
    return normalize_app_key(source)


def is_sensitive_permission(permission: str) -> bool:
    return (permission or "").strip().lower() in SENSITIVE_PERMISSIONS

