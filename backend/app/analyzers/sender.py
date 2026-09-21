"""
Sender analyzer: examines the sender identity for impersonation indicators.

Features extracted:
- Display name vs From address consistency
- Display name brand impersonation detection
- Sender domain characteristics
- Reply-To / Return-Path consistency
"""

from __future__ import annotations

import re
from typing import Any


# Known brand names that attackers commonly impersonate
KNOWN_BRANDS: dict[str, list[str]] = {
    "microsoft": ["microsoft", "ms", "office", "outlook", "teams", "azure", "onedrive"],
    "google": ["google", "gmail", "workspace", "drive", "android"],
    "apple": ["apple", "icloud", "itunes", "iphone", "mac", "siri"],
    "amazon": ["amazon", "aws", "prime", "alexa", "kindle"],
    "facebook": ["facebook", "meta", "instagram", "whatsapp"],
    "paypal": ["paypal", "venmo"],
    "netflix": ["netflix"],
    "banking": ["bank", "chase", "wells", "citi", "capital", "fargo", "boa"],
    "dhl": ["dhl", "fedex", "ups", "usps"],
    "dropbox": ["dropbox"],
    "adobe": ["adobe", "photoshop", "creative"],
    "twitter": ["twitter", "x"],
    "linkedin": ["linkedin"],
}

# Known legitimate domains for brands
_BRAND_LEGITIMATE_DOMAINS: dict[str, set[str]] = {
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com"},
    "google": {"google.com", "gmail.com", "googlemail.com"},
    "apple": {"apple.com", "icloud.com", "me.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "aws.amazon.com"},
    "facebook": {"facebook.com", "meta.com", "instagram.com"},
    "paypal": {"paypal.com", "paypal.co.uk"},
    "netflix": {"netflix.com"},
}


def analyze_sender(
    sender_info: dict[str, Any],
    reply_to_domain: str | None = None,
    return_path_domain: str | None = None,
) -> dict[str, Any]:
    """Analyze sender identity for impersonation indicators."""
    display_name = (sender_info.get("display_name") or "").strip()
    from_address = sender_info.get("from_address") or ""
    from_domain = sender_info.get("from_domain") or ""
    from_localpart = sender_info.get("from_localpart") or ""

    # Brand impersonation detection
    claimed_brands = _detect_brand_in_display_name(display_name)
    domain_brands = _detect_brand_in_domain(from_domain)

    # Display name claims a brand but domain doesn't match
    brand_domain_mismatch = bool(
        claimed_brands
        and not _domain_matches_any_brand(from_domain, claimed_brands)
    )

    # Display name contains a different brand than the domain suggests
    cross_brand_conflict = bool(
        claimed_brands
        and domain_brands
        and not set(claimed_brands).intersection(set(domain_brands))
    )

    # Display name looks like an email address (obfuscation)
    display_looks_like_email = "@" in display_name

    # Display name contains excessive spaces or special characters
    has_suspicious_display = bool(
        re.search(r"[^\w\s@.\-,<>]", display_name)
        or "  " in display_name
    )

    # Local part analysis
    local_is_numeric = from_localpart.isdigit()
    local_has_plus = "+" in from_localpart  # Plus addressing
    local_length = len(from_localpart)

    return {
        "claimed_brands": claimed_brands,
        "domain_brands": domain_brands,
        "brand_domain_mismatch": brand_domain_mismatch,
        "cross_brand_conflict": cross_brand_conflict,
        "display_looks_like_email": display_looks_like_email,
        "has_suspicious_display": has_suspicious_display,
        "display_name": display_name,
        "local_is_numeric": local_is_numeric,
        "local_has_plus": local_has_plus,
        "local_length": local_length,
    }


def _detect_brand_in_display_name(display_name: str) -> list[str]:
    """Detect brand references in the display name."""
    lower = display_name.lower()
    found = []
    for brand, keywords in KNOWN_BRANDS.items():
        for keyword in keywords:
            if keyword in lower:
                found.append(brand)
                break
    return found


def _detect_brand_in_domain(domain: str) -> list[str]:
    """Detect brand references in the domain (word-boundary aware)."""
    lower = domain.lower()
    # Split domain into labels for word-boundary matching
    labels = set(lower.replace("-", "").split("."))
    found = []
    for brand, keywords in KNOWN_BRANDS.items():
        for keyword in keywords:
            # Check if the keyword appears as a whole label or substring in a label
            if keyword in labels or any(keyword in label for label in labels):
                found.append(brand)
                break
    return found


_GENERIC_TLDS = {"com", "org", "net", "io", "co", "gov", "edu"}


def _domain_matches_any_brand(domain: str, brands: list[str]) -> bool:
    """Check if the domain is one of the legitimate domains for any of the given brands."""
    if not domain:
        return False
    domain_labels = set(domain.lower().replace("-", "").split(".")) - _GENERIC_TLDS

    for brand in brands:
        legit_domains = _BRAND_LEGITIMATE_DOMAINS.get(brand, set())
        for d in legit_domains:
            d_labels = set(d.replace("-", "").split(".")) - _GENERIC_TLDS
            if d_labels and domain_labels == d_labels:
                return True

    return False
