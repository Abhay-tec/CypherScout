import re
from pathlib import Path
from urllib.parse import urlparse

SENSITIVE_PERMISSIONS = {"contacts", "gallery"}
ALWAYS_TRUSTED_LINK_KEYS = {
    "google.com",
    "mail.google.com",
    "youtube.com",
    "github.com",
    "whatsapp.com",
    "instagram.com",
    "linkedin.com",
    "paypal.com",
    "amazon.com",
}


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


def is_always_trusted_link(source: str) -> bool:
    key = normalize_link_key(source)
    if not key:
        return False
    for trusted in ALWAYS_TRUSTED_LINK_KEYS:
        if key == trusted or key.endswith(f".{trusted}"):
            return True
    return False


def persist_whitelist_link(source: str) -> str:
    key = normalize_link_key(source)
    if not key:
        return ""
    if key in ALWAYS_TRUSTED_LINK_KEYS:
        return key

    module_path = Path(__file__)
    content = module_path.read_text(encoding="utf-8")
    marker = "ALWAYS_TRUSTED_LINK_KEYS = {"
    idx = content.find(marker)
    if idx == -1:
        return ""

    closing = content.find("}", idx)
    if closing == -1:
        return ""

    insertion = f'    "{key}",\n'
    content = content[:closing] + insertion + content[closing:]
    module_path.write_text(content, encoding="utf-8")
    ALWAYS_TRUSTED_LINK_KEYS.add(key)
    return key
