import base64
import hashlib
import math
import os
import socket
import ssl
from urllib.parse import urlparse

import requests

from app.ml import neural_engine

TRUSTED_DOMAINS = {
    "google.com",
    "facebook.com",
    "amazon.in",
    "github.com",
    "microsoft.com",
    "instagram.com",
    "apple.com",
    "paypal.com",
    "netflix.com",
}
SHADY_TLDS = {"sbs", "icu", "top", "xyz", "shop", "online", "tk", "ml", "ga", "cf", "gq", "monster", "live", "buzz", "lat"}


def normalize_url(url: str) -> str:
    if not url:
        return ""
    url = url.strip().lower()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}"


def calculate_entropy(text: str) -> float:
    if not text:
        return 0.0
    probs = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
    return -sum([p * math.log(p) / math.log(2.0) for p in probs])


def calculate_byte_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    entropy = 0.0
    total = len(data)
    for count in freq:
        if count:
            p = count / total
            entropy -= p * math.log2(p)
    return entropy


def deep_scan_file(file_storage) -> dict:
    filename = (file_storage.filename or "unknown.bin").strip()
    raw = file_storage.read() or b""
    size = len(raw)
    ext = os.path.splitext(filename.lower())[1]
    sha256 = hashlib.sha256(raw).hexdigest()
    preview = raw[:250000]

    risk = 0
    reasons = []

    suspicious_exts = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".hta", ".iso"}
    if ext in suspicious_exts:
        risk += 5
        reasons.append(f"High-risk extension detected: {ext}")

    if preview[:2] == b"MZ":
        risk += 4
        reasons.append("Portable executable (MZ header) detected")

    text_sample = preview.decode("latin-1", errors="ignore").lower()
    suspicious_tokens = [
        "powershell -enc",
        "frombase64string",
        "invoke-webrequest",
        "wscript.shell",
        "cmd.exe /c",
        "autoopen",
        "downloadstring",
    ]
    token_hits = [token for token in suspicious_tokens if token in text_sample]
    if token_hits:
        risk += min(6, len(token_hits) * 2)
        reasons.append(f"Suspicious script pattern(s): {', '.join(token_hits[:3])}")

    entropy = calculate_byte_entropy(preview)
    if size > 0 and entropy > 7.4:
        risk += 3
        reasons.append(f"High byte entropy ({entropy:.2f}) suggests packed/obfuscated payload")

    if size > 18 * 1024 * 1024:
        risk += 1
        reasons.append("Large file size requires additional manual validation")

    if risk >= 8:
        status = "MALICIOUS (Deep Scan)"
    elif risk >= 4:
        status = "SUSPICIOUS (Deep Scan)"
    else:
        status = "CLEAN (Deep Scan)"

    if not reasons:
        reasons.append("No high-confidence malicious indicators detected")

    return {
        "filename": filename,
        "size_bytes": size,
        "sha256": sha256,
        "entropy": round(entropy, 3),
        "risk_score": risk,
        "status": status,
        "reasons": reasons,
    }


def get_url_intel(raw_url: str) -> dict:
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    host = parsed.hostname or ""
    if not host:
        return {"status": "error", "message": "Invalid URL"}

    ip_address = None
    addresses = []
    reverse_dns = None
    geo = {}
    ssl_info = {}

    try:
        infos = socket.getaddrinfo(host, None)
        addresses = sorted(list({i[4][0] for i in infos}))
        ip_address = addresses[0] if addresses else socket.gethostbyname(host)
    except Exception:
        ip_address = None

    if ip_address:
        try:
            reverse_dns = socket.gethostbyaddr(ip_address)[0]
        except Exception:
            reverse_dns = None

        try:
            geo_res = requests.get(
                f"http://ip-api.com/json/{ip_address}?fields=status,country,regionName,city,zip,lat,lon,isp,org,as,timezone,query",
                timeout=5,
            )
            geo_json = geo_res.json()
            if geo_json.get("status") == "success":
                geo = {
                    "ip": geo_json.get("query"),
                    "country": geo_json.get("country"),
                    "region": geo_json.get("regionName"),
                    "city": geo_json.get("city"),
                    "zip": geo_json.get("zip"),
                    "lat": geo_json.get("lat"),
                    "lon": geo_json.get("lon"),
                    "timezone": geo_json.get("timezone"),
                    "isp": geo_json.get("isp"),
                    "org": geo_json.get("org"),
                    "asn": geo_json.get("as"),
                }
        except Exception:
            geo = {}

    try:
        with socket.create_connection((host, 443), timeout=4) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                ssl_info = {
                    "enabled": True,
                    "version": ssock.version(),
                    "issuer": dict(x[0] for x in cert.get("issuer", [])) if cert else {},
                    "subject": dict(x[0] for x in cert.get("subject", [])) if cert else {},
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                }
    except Exception:
        ssl_info = {"enabled": False}

    host_token = host.split(".")[0] if host else ""
    entropy = round(calculate_entropy(host_token), 3)

    return {
        "status": "ok",
        "url": normalized,
        "scheme": parsed.scheme,
        "host": host,
        "path": parsed.path or "/",
        "query": parsed.query or "",
        "fragment": parsed.fragment or "",
        "port": parsed.port or (443 if parsed.scheme == "https" else 80),
        "ip_primary": ip_address,
        "ip_all": addresses,
        "reverse_dns": reverse_dns,
        "host_entropy": entropy,
        "ssl": ssl_info,
        "geo": geo,
    }


def check_virustotal_detailed(url: str, api_key: str):
    if not api_key:
        return False, [], {}
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        headers = {"x-apikey": api_key}
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers, timeout=5)
        if response.status_code != 200:
            return False, [], {}

        data = response.json().get("data", {})
        attr = data.get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        results = attr.get("last_analysis_results", {})

        vendors = []
        for engine, info in results.items():
            vendors.append(
                {
                    "engine": engine,
                    "result": info.get("result", "clean"),
                    "category": info.get("category", "harmless"),
                }
            )
        is_threat = stats.get("malicious", 0) > 0 or stats.get("phishing", 0) > 0
        return is_threat, vendors, stats
    except Exception:
        return False, [], {}


class NeuralAnalyzer:
    def __init__(self, url: str, vt_api_key: str):
        self.url = normalize_url(url)
        parsed = urlparse(self.url)
        self.domain = parsed.netloc.lower().replace("www.", "")
        self.tld = self.domain.split(".")[-1] if "." in self.domain else ""
        self.vt_api_key = vt_api_key

    def check_ssl_tls(self) -> bool:
        if self.domain in TRUSTED_DOMAINS:
            return True
        try:
            with socket.create_connection((self.domain, 443), timeout=3) as sock:
                with ssl.create_default_context().wrap_socket(sock, server_hostname=self.domain):
                    return True
        except Exception:
            return False

    def heuristic_score(self) -> int:
        score = 0
        if self.tld in SHADY_TLDS:
            score += 7

        target_keywords = ["allegro", "google", "pay", "billing", "login", "verify", "bank", "secure", "gift", "update", "account", "idp"]
        for word in target_keywords:
            if word in self.url and self.domain not in TRUSTED_DOMAINS:
                score += 5

        if self.domain.count("-") >= 2:
            score += 5
        if not self.check_ssl_tls():
            score += 6
        main_part = self.domain.split(".")[0]
        if calculate_entropy(main_part) > 3.8:
            score += 5
        return score

    def analyze(self, exact_feedback_status: str | None):
        if not self.url or "127.0.0.1" in self.url:
            return False, "SYSTEM_INTERNAL", [], {}

        if exact_feedback_status:
            return "MALICIOUS" in exact_feedback_status, exact_feedback_status, [], {}

        vt_threat, vendors, stats = check_virustotal_detailed(self.url, self.vt_api_key)
        if vt_threat:
            return True, f"MALICIOUS ({stats.get('malicious', 0)} Engines Flagged)", vendors, stats

        h_score = self.heuristic_score()
        ml_score = neural_engine.predict_malicious_prob(self.url)
        if h_score >= 10 or ml_score > 0.65:
            return True, "MALICIOUS (Neural Flagged)", vendors, stats
        if h_score >= 5:
            return True, "SUSPICIOUS (Pattern Match)", vendors, stats
        return False, "CLEAN", vendors, stats
