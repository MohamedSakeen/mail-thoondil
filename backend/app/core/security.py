"""
Security utilities: input validation, SSRF protection, sanitization.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from app.core.config import BLOCKED_HOSTNAMES, MAX_EMAIL_BYTES, MAX_URL_LENGTH


def validate_email_size(data: bytes) -> None:
    """Raise ValueError if email exceeds size limits."""
    if not data:
        raise ValueError("Email is empty")
    if len(data) > MAX_EMAIL_BYTES:
        raise ValueError(
            f"Email exceeds maximum size of {MAX_EMAIL_BYTES // (1024*1024)} MB"
        )


def is_safe_url(url: str) -> bool:
    """Check if a URL is safe to fetch (no SSRF)."""
    if len(url) > MAX_URL_LENGTH:
        return False
    try:
        parsed = urlparse(url)
    except Exception:
        return False

    if parsed.scheme not in ("http", "https"):
        return False

    hostname = (parsed.hostname or "").lower()
    if not hostname:
        return False

    if hostname in BLOCKED_HOSTNAMES:
        return False

    try:
        addr = ipaddress.ip_address(hostname)
        if addr.is_private or addr.is_loopback or addr.is_reserved or addr.is_link_local:
            return False
    except ValueError:
        pass  # Not an IP, that's fine

    return True


def sanitize_html_for_display(html: str) -> str:
    """Basic sanitization of HTML for display purposes.
    Strips script tags and event handlers. For production use a proper
    library like bleach.
    """
    html = re.sub(r"<script\b[^>]*>.*?</script>", "", html, flags=re.I | re.S)
    html = re.sub(r"<iframe\b[^>]*>.*?</iframe>", "", html, flags=re.I | re.S)
    html = re.sub(r"\bon\w+\s*=", " data-removed=", html, flags=re.I)
    return html


def sanitize_filename(filename: str) -> str:
    """Remove path components and dangerous characters from a filename."""
    # Strip directory components
    filename = filename.split("/")[-1].split("\\")[-1]
    # Remove null bytes
    filename = filename.replace("\x00", "")
    # Limit length
    if len(filename) > 255:
        name, ext = filename.rsplit(".", 1) if "." in filename else (filename, "")
        filename = name[:250] + ("." + ext if ext else "")
    return filename


def extract_domains_from_text(text: str) -> list[str]:
    """Extract domain names from arbitrary text."""
    return re.findall(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b",
        text,
    )


def normalize_domain(domain: str) -> str:
    """Normalize a domain: lowercase, strip trailing dots."""
    return domain.lower().rstrip(".")


def is_ip_address(value: str) -> bool:
    """Check if a string is an IP address."""
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
