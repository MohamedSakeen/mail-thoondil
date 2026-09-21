"""
URL analyzer: extracts structural, security, and phishing-relevant features.

Features extracted per URL:
- Structural: length, domain length, path length, subdomain count
- Security: HTTPS, IP address, port, punycode, encoding, @ symbol
- Phishing: shortener detection, suspicious keywords, visible/actual mismatch
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse
from typing import Any

from app.core.config import KNOWN_SHORTENERS

URL_RE = re.compile(r"https?://[^\s<>\"'')\]]+", re.I)

SUSPICIOUS_KEYWORDS = frozenset({
    "login", "signin", "verify", "account", "secure", "update",
    "confirm", "banking", "password", "credential", "auth",
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "facebook", "instagram", "support", "helpdesk", "billing",
})


def analyze(urls: list[str]) -> list[dict[str, Any]]:
    """Analyze a list of extracted URLs and return feature dictionaries."""
    results = []
    for i, raw_url in enumerate(urls):
        features = _analyze_single_url(raw_url)
        results.append({
            "id": f"url-{i+1}",
            "raw_url": raw_url,
            "normalized": features.pop("normalized"),
            "features": features,
        })
    return results


def _analyze_single_url(raw_url: str) -> dict[str, Any]:
    """Extract all features from a single URL."""
    p = urlparse(raw_url)
    host = (p.hostname or "").lower()
    scheme = p.scheme.lower()
    path = p.path
    query = p.query
    fragment = p.fragment

    # IP address check
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    # Domain label analysis
    labels = [x for x in host.split(".") if x]
    tld = labels[-1] if labels else ""

    # Subdomain count
    subdomain_count = max(0, len(labels) - 2)

    # Digit ratio in domain
    domain_digit_ratio = sum(c.isdigit() for c in host) / max(1, len(host))

    # Hyphen count
    hyphen_count = host.count("-")

    # Path analysis
    path_length = len(path)
    path_depth = len([p for p in path.split("/") if p])

    # Visible text mismatch detection (simplified)
    # Check if URL contains @ which can hide the real destination
    has_at = "@" in raw_url

    # Check for encoded characters (potential obfuscation)
    has_encoded = "%" in raw_url and re.search(r"%[0-9a-fA-F]{2}", raw_url)

    # Check for port (non-standard ports can be suspicious)
    has_port = p.port is not None
    suspicious_port = has_port and p.port not in (None, 80, 443)

    # Punycode detection
    has_punycode = any(label.startswith("xn--") for label in labels)

    # URL length as a feature
    url_length = len(raw_url)

    # Shortener detection
    is_shortener = host in KNOWN_SHORTENERS

    # Suspicious keyword detection in path/query
    text_to_check = f"{path} {query}".lower()
    suspicious_keyword_hits = [kw for kw in SUSPICIOUS_KEYWORDS if kw in text_to_check]

    return {
        "normalized": {
            "scheme": scheme,
            "domain": host,
            "path": path,
            "query": query,
            "fragment": fragment,
            "tld": tld,
            "port": p.port,
        },
        "length": url_length,
        "domain_length": len(host),
        "path_length": path_length,
        "path_depth": path_depth,
        "subdomain_count": subdomain_count,
        "dot_count": host.count("."),
        "hyphen_count": hyphen_count,
        "digit_ratio": round(domain_digit_ratio, 4),
        "is_https": scheme == "https",
        "is_ip_address": is_ip,
        "has_port": has_port,
        "suspicious_port": suspicious_port,
        "has_punycode": has_punycode,
        "has_at_symbol": has_at,
        "has_encoded_chars": has_encoded,
        "shortener_detected": is_shortener,
        "suspicious_keywords": suspicious_keyword_hits,
        "suspicious_keyword_count": len(suspicious_keyword_hits),
    }
