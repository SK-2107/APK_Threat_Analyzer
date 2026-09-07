"""Static URL and domain indicator checks for APK file contents."""

import re
from typing import Any
from urllib.parse import urlparse

from security.models import Finding

URL_PATTERN = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.IGNORECASE)
RAW_IP_PATTERN = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
HOSTNAME_PATTERN = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.IGNORECASE)
PRINTABLE_RUN_PATTERN = re.compile(rb"[\x20-\x7e]{12,}")
ANDROID_SCHEMA_HOSTS = {"schemas.android.com", "www.w3.org"}


def find_url_indicators(apk: Any, suspicious_tlds: list[str]) -> list[Finding]:
    """Find HTTP, raw-IP, and configured unusual-TLD URL indicators."""
    try:
        urls = _extract_urls(apk)
    except (AttributeError, OSError, TypeError, ValueError):
        return []

    findings: list[Finding] = []
    for url in urls:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
        if hostname.lower() in ANDROID_SCHEMA_HOSTS or not _valid_hostname(hostname):
            continue
        if RAW_IP_PATTERN.fullmatch(hostname):
            findings.append(_url_finding(url, "Raw IP address", "MEDIUM", 8, "Direct IP-based network communication deserves additional review."))
        elif parsed.scheme.lower() == "http":
            findings.append(_url_finding(url, "HTTP endpoint", "MEDIUM", 8, "Uses unencrypted HTTP."))
        elif parsed.scheme.lower() == "https":
            findings.append(_url_finding(url, "HTTPS endpoint", "INFO", 0, "Uses encrypted HTTPS network communication."))
        elif any(hostname.lower().endswith(tld.lower()) for tld in suspicious_tlds):
            findings.append(_url_finding(url, "Unusual domain pattern", "LOW", 5, "Matches a configured unusual TLD."))
    return findings


def _extract_urls(apk: Any) -> set[str]:
    """Search printable string runs, not arbitrary binary bytes, for URLs."""
    urls: set[str] = set()
    for file_name in apk.get_files():
        file_bytes = apk.get_file(file_name)
        if not file_bytes or len(file_bytes) > 5_000_000:
            continue
        for text_run in PRINTABLE_RUN_PATTERN.findall(file_bytes):
            text = text_run.decode("ascii", errors="ignore")
            urls.update(match.rstrip(".,;:)") for match in URL_PATTERN.findall(text))
    return urls


def _valid_hostname(hostname: str) -> bool:
    """Reject malformed binary-text matches before they become findings."""
    if len(hostname) > 253:
        return False
    if RAW_IP_PATTERN.fullmatch(hostname):
        return all(0 <= int(part) <= 255 for part in hostname.split("."))
    return bool(HOSTNAME_PATTERN.fullmatch(hostname))


def _url_finding(
    url: str, category: str, severity: str, score: int, description: str
) -> Finding:
    """Build a URL finding with a consistent explanation."""
    return Finding(
        category, url, severity, score, description,
        "Review whether this endpoint is expected for the app's intended service.",
        "APK resources and DEX strings",
    )
