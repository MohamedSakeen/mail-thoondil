"""
Domain analyzer: checks sender and URL domains for suspicious properties.

Features extracted:
- TLD analysis
- Subdomain depth
- Suspicious TLD flag
- Homoglyph / look-alike detection
- Domain length and character composition
"""

from __future__ import annotations

import re
from typing import Any

from app.core.config import SUSPICIOUS_TLDS

# Characters that look similar to ASCII letters (homoglyphs)
HOMOGLYPH_MAP: dict[str, str] = {
    "а": "a",  # Cyrillic а
    "е": "e",  # Cyrillic е
    "о": "o",  # Cyrillic о
    "р": "p",  # Cyrillic р
    "с": "c",  # Cyrillic с
    "у": "y",  # Cyrillic у
    "х": "x",  # Cyrillic х
    "ᴀ": "a", "ʙ": "b", "ᴄ": "c", "ᴅ": "d",
    "ⅰ": "i", "ⅱ": "ii", "ⅲ": "iii",
}


def analyze_domain(domain: str | None) -> dict[str, Any]:
    """Analyze a single domain for suspicious properties."""
    if not domain:
        return _empty_domain()

    domain = domain.lower().strip()
    labels = domain.split(".")

    tld = labels[-1] if labels else ""
    tld_full = f".{tld}" if tld else ""

    # Subdomain depth
    subdomain_depth = max(0, len(labels) - 2)

    # Check for suspicious TLD
    has_suspicious_tld = tld_full in SUSPICIOUS_TLDS

    # Homoglyph detection
    has_homoglyphs = _contains_homoglyphs(domain)

    # Domain composition
    digit_ratio = sum(c.isdigit() for c in domain) / max(1, len(domain))
    hyphen_count = domain.count("-")
    has_underscore = "_" in domain
    has_double_hyphen = "--" in domain

    # Length analysis
    domain_length = len(domain)
    tld_length = len(tld)
    label_lengths = [len(l) for l in labels]
    max_label_length = max(label_lengths) if label_lengths else 0
    avg_label_length = sum(label_lengths) / max(1, len(label_lengths))

    # Suspicious patterns
    # Random-looking domains (high entropy)
    has_random_pattern = _looks_random(domain)

    # Brand name detection (common targets)
    brand_indicators = _detect_brand_reference(domain)

    return {
        "domain": domain,
        "tld": tld,
        "tld_full": tld_full,
        "label_count": len(labels),
        "subdomain_depth": subdomain_depth,
        "has_suspicious_tld": has_suspicious_tld,
        "has_homoglyphs": has_homoglyphs,
        "digit_ratio": round(digit_ratio, 4),
        "hyphen_count": hyphen_count,
        "has_underscore": has_underscore,
        "has_double_hyphen": has_double_hyphen,
        "length": domain_length,
        "tld_length": tld_length,
        "max_label_length": max_label_length,
        "avg_label_length": round(avg_label_length, 2),
        "has_random_pattern": has_random_pattern,
        "brand_indicators": brand_indicators,
        "has_brand_reference": len(brand_indicators) > 0,
    }


def analyze_domains(domains: list[str | None]) -> dict[str, Any]:
    """Analyze multiple domains and return aggregate features."""
    results = [analyze_domain(d) for d in domains]
    return {
        "domains": results,
        "unique_tlds": list({r["tld"] for r in results if r["tld"]}),
        "suspicious_tld_count": sum(1 for r in results if r["has_suspicious_tld"]),
        "homoglyph_count": sum(1 for r in results if r["has_homoglyphs"]),
        "random_pattern_count": sum(1 for r in results if r["has_random_pattern"]),
        "brand_reference_count": sum(1 for r in results if r["has_brand_reference"]),
    }


def _contains_homoglyphs(domain: str) -> bool:
    """Check if domain contains Cyrillic or other homoglyph characters."""
    for char in domain:
        if ord(char) > 127:
            return True
    return False


def _looks_random(domain: str) -> bool:
    """Heuristic: does the domain look randomly generated?"""
    # Remove TLD for analysis
    labels = domain.split(".")
    main_label = labels[0] if labels else domain

    if len(main_label) < 4:
        return False

    # Check consonant-vowel patterns (random domains often lack natural patterns)
    vowels = set("aeiou")
    consonants = sum(1 for c in main_label if c.isalpha() and c not in vowels)
    v = sum(1 for c in main_label if c in vowels)
    d = sum(1 for c in main_label if c.isdigit())

    # Random domains often have many consecutive consonants or digits
    max_consecutive_consonants = _max_consecutive(main_label, vowels, is_vowel=False)
    max_consecutive_digits = _max_consecutive_digits(main_label)

    if max_consecutive_consonants > 4 or max_consecutive_digits > 3:
        return True
    if d > 0 and d / max(1, len(main_label)) > 0.4:
        return True

    return False


def _max_consecutive(text: str, target: set[str], is_vowel: bool) -> int:
    """Count maximum consecutive characters that are/aren't in target."""
    max_count = 0
    current = 0
    for c in text:
        if c.isalpha():
            in_target = c in target
            if in_target == is_vowel:
                current += 1
                max_count = max(max_count, current)
            else:
                current = 0
    return max_count


def _max_consecutive_digits(text: str) -> int:
    """Count maximum consecutive digit characters."""
    max_count = 0
    current = 0
    for c in text:
        if c.isdigit():
            current += 1
            max_count = max(max_count, current)
        else:
            current = 0
    return max_count


BRAND_KEYWORDS = {
    "microsoft", "google", "apple", "amazon", "facebook", "meta",
    "netflix", "paypal", "bank", "chase", "wellsfargo", "citi",
    "dropbox", "adobe", "twitter", "linkedin", "instagram",
    "office365", "outlook", "gmail", "icloud", "live",
}


def _detect_brand_reference(domain: str) -> list[str]:
    """Detect if domain references a well-known brand."""
    found = []
    for brand in BRAND_KEYWORDS:
        if brand in domain:
            found.append(brand)
    return found


def _empty_domain() -> dict[str, Any]:
    """Return zeroed-out domain features."""
    return {
        "domain": "",
        "tld": "",
        "tld_full": "",
        "label_count": 0,
        "subdomain_depth": 0,
        "has_suspicious_tld": False,
        "has_homoglyphs": False,
        "digit_ratio": 0.0,
        "hyphen_count": 0,
        "has_underscore": False,
        "has_double_hyphen": False,
        "length": 0,
        "tld_length": 0,
        "max_label_length": 0,
        "avg_label_length": 0.0,
        "has_random_pattern": False,
        "brand_indicators": [],
        "has_brand_reference": False,
    }
