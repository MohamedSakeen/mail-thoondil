"""
Header analyzer: extracts sender, authentication, and header-level features.

Features extracted:
- Sender identity (from, reply-to, return-path, display name)
- Authentication results (SPF, DKIM, DMARC)
- Header anomalies (mismatches, hop count, message-ID domain)
"""

from __future__ import annotations

import re
from email.message import EmailMessage
from email.utils import parseaddr
from typing import Any


def _domain(address: str | None) -> str | None:
    """Extract domain from an email address."""
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[1].lower().strip()


def _localpart(address: str | None) -> str | None:
    """Extract local part from an email address."""
    if not address or "@" not in address:
        return None
    return address.rsplit("@", 1)[0].lower().strip()


def analyze(msg: EmailMessage) -> dict[str, Any]:
    """Analyze email headers and return structured features."""
    from_header = msg.get("From", "")
    from_name, from_addr = parseaddr(from_header)
    reply_to_raw = msg.get("Reply-To", "")
    _, reply_to_addr = parseaddr(reply_to_raw)
    return_path_raw = msg.get("Return-Path", "")
    _, return_path_addr = parseaddr(return_path_raw)

    from_domain = _domain(from_addr)
    reply_domain = _domain(reply_to_addr)
    return_domain = _domain(return_path_addr)
    from_local = _localpart(from_addr)

    # Message-ID domain
    message_id = msg.get("Message-ID", "")
    mid_match = re.search(r"@([^>]+)", message_id)
    mid_domain = mid_match.group(1).lower().strip() if mid_match else None

    # Authentication-Results
    auth_raw = (msg.get("Authentication-Results") or "").lower()

    def _auth_status(name: str) -> str:
        for value in ("pass", "fail", "softfail", "neutral", "none"):
            if f"{name}={value}" in auth_raw:
                return value
        return "unknown"

    spf_status = _auth_status("spf")
    dkim_status = _auth_status("dkim")
    dmarc_status = _auth_status("dmarc")

    # Received header count (proxy for routing complexity)
    received_headers = msg.get_all("Received", [])

    # Date
    date_str = msg.get("Date", "")

    # User-Agent / X-Mailer (sometimes indicative of automation)
    user_agent = msg.get("User-Agent") or msg.get("X-Mailer") or ""

    # X-Priority
    x_priority = msg.get("X-Priority", "")

    # Display name vs from domain mismatch detection
    display_name_mismatch = _check_display_name_mismatch(from_name, from_domain)

    return {
        "sender": {
            "display_name": from_name,
            "from_address": from_addr,
            "from_domain": from_domain,
            "from_localpart": from_local,
            "reply_to": reply_to_addr or None,
            "reply_to_domain": reply_domain,
            "return_path": return_path_addr or None,
            "return_path_domain": return_domain,
            "sender_domain_length": len(from_domain) if from_domain else 0,
            "sender_localpart_length": len(from_local) if from_local else 0,
            "sender_domain_digit_ratio": (
                sum(c.isdigit() for c in from_domain) / max(1, len(from_domain))
                if from_domain else 0.0
            ),
            "sender_domain_hyphen_count": (
                from_domain.count("-") if from_domain else 0
            ),
        },
        "authentication": {
            "spf": spf_status,
            "dkim": dkim_status,
            "dmarc": dmarc_status,
            "spf_fail": spf_status == "fail",
            "dkim_fail": dkim_status == "fail",
            "dmarc_fail": dmarc_status == "fail",
            "authentication_alignment": (
                spf_status == "pass"
                and dkim_status == "pass"
                and dmarc_status == "pass"
            ),
            "authentication_raw": auth_raw,
        },
        "headers": {
            "received_hop_count": len(received_headers),
            "header_count": len(msg.items()),
            "reply_to_mismatch": bool(
                reply_domain and from_domain and reply_domain != from_domain
            ),
            "return_path_mismatch": bool(
                return_domain and from_domain and return_domain != from_domain
            ),
            "message_id_domain": mid_domain,
            "message_id_domain_mismatch": bool(
                mid_domain and from_domain and mid_domain != from_domain
            ),
            "date_anomaly": False,
            "user_agent": user_agent,
            "x_priority": x_priority,
            "has_reply_to": bool(reply_to_addr),
            "display_name_from_mismatch": display_name_mismatch,
        },
    }


# Known brands that display names commonly impersonate
_BRAND_KEYWORDS = [
    "microsoft", "google", "apple", "amazon", "facebook", "meta",
    "paypal", "netflix", "bank", "chase", "wellsfargo", "citi",
    "dropbox", "adobe", "twitter", "linkedin", "instagram",
    "dhl", "fedex", "ups", "usps", "irs", "fbi",
]

# Map brand names to their known legitimate domains for domain matching
_BRAND_DOMAINS: dict[str, set[str]] = {
    "microsoft": {"microsoft.com", "outlook.com", "live.com", "office.com", "microsoft365.com"},
    "google": {"google.com", "gmail.com", "googlemail.com"},
    "apple": {"apple.com", "icloud.com", "me.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "aws.amazon.com"},
    "facebook": {"facebook.com", "meta.com", "instagram.com"},
    "paypal": {"paypal.com", "paypal.co.uk"},
    "netflix": {"netflix.com"},
    "dhl": {"dhl.com", "dhl.de"},
    "fedex": {"fedex.com"},
    "ups": {"ups.com"},
    "usps": {"usps.com"},
}


def _check_display_name_mismatch(display_name: str, from_domain: str | None) -> bool:
    """Check if the display name implies a brand/organization not matching the domain."""
    if not display_name or not from_domain:
        return False

    _GENERIC_TLDS = {"com", "org", "net", "io", "co", "gov", "edu"}
    lower_name = display_name.lower()
    domain_labels = set(from_domain.lower().replace("-", "").split(".")) - _GENERIC_TLDS

    for brand in _BRAND_KEYWORDS:
        if brand not in lower_name:
            continue

        # Check if the sender domain is one of the known legitimate domains for this brand
        known_domains = _BRAND_DOMAINS.get(brand, set())
        is_legitimate = False
        for d in known_domains:
            d_labels = set(d.replace("-", "").split(".")) - _GENERIC_TLDS
            if d_labels and domain_labels == d_labels:
                is_legitimate = True
                break

        if is_legitimate:
            continue

        # Brand in display name but not in a legitimate domain = mismatch
        return True

    return False
