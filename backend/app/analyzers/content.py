"""
Content / NLP analyzer: extracts linguistic and phishing-relevant features.

Features extracted:
- Basic statistics: word count, sentence count, character ratios
- Phishing indicators: urgency, credential requests, financial requests, threats
- Style indicators: authority impersonation, call-to-action density
"""

from __future__ import annotations

import re
import math
from typing import Any

from app.core.config import (
    ACCOUNT_ACTION_PATTERNS,
    AUTHORITY_PATTERNS,
    CALL_TO_ACTION_PATTERNS,
    CREDENTIAL_PATTERNS,
    FINANCIAL_PATTERNS,
    THREAT_PATTERNS,
    URGENCY_PATTERNS,
)


def _score_patterns(patterns: list[str], text: str) -> float:
    """Score text against a list of regex patterns. Returns 0.0–1.0."""
    if not text:
        return 0.0
    hits = sum(1 for p in patterns if re.search(p, text, re.I))
    # Normalize: if half the patterns match, score is ~1.0
    return min(1.0, hits / max(1, len(patterns) * 0.5))


def _language_hint(text: str) -> str:
    """Very basic language detection heuristic."""
    if not text:
        return "unknown"
    ascii_ratio = sum(ord(c) < 128 for c in text) / max(1, len(text))
    if ascii_ratio > 0.9:
        return "en"  # likely English
    return "other"


def _entropy(text: str) -> float:
    """Shannon entropy of the text (measures randomness / obfuscation)."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def analyze(text: str) -> dict[str, Any]:
    """Analyze email body text and return content features."""
    if not text:
        return _empty_features()

    words = re.findall(r"\b\w+\b", text, re.UNICODE)
    word_count = len(words)
    sentence_count = max(1, len(re.findall(r"[.!?]+", text)))

    # Character ratios
    alpha_chars = sum(c.isalpha() for c in text)
    upper_chars = sum(c.isupper() for c in text)

    return {
        "word_count": word_count,
        "sentence_count": sentence_count,
        "avg_word_length": (
            sum(len(w) for w in words) / max(1, word_count)
        ),
        "uppercase_ratio": upper_chars / max(1, alpha_chars),
        "digit_ratio": sum(c.isdigit() for c in text) / max(1, len(text)),
        "punctuation_ratio": (
            sum(not c.isalnum() and not c.isspace() for c in text)
            / max(1, len(text))
        ),
        "text_entropy": round(_entropy(text), 4),
        "language": _language_hint(text),

        # Phishing-indicator scores (0.0–1.0)
        "urgency_score": round(_score_patterns(URGENCY_PATTERNS, text), 4),
        "credential_request_score": round(_score_patterns(CREDENTIAL_PATTERNS, text), 4),
        "financial_request_score": round(_score_patterns(FINANCIAL_PATTERNS, text), 4),
        "account_action_score": round(_score_patterns(ACCOUNT_ACTION_PATTERNS, text), 4),
        "threat_score": round(_score_patterns(THREAT_PATTERNS, text), 4),
        "authority_impersonation_score": round(_score_patterns(AUTHORITY_PATTERNS, text), 4),
        "call_to_action_score": round(_score_patterns(CALL_TO_ACTION_PATTERNS, text), 4),

        # Combined phishing-indicator aggregate
        "phishing_indicator_sum": round(
            _score_patterns(URGENCY_PATTERNS, text)
            + _score_patterns(CREDENTIAL_PATTERNS, text)
            + _score_patterns(FINANCIAL_PATTERNS, text)
            + _score_patterns(THREAT_PATTERNS, text)
            + _score_patterns(AUTHORITY_PATTERNS, text),
            4,
        ),
    }


def _empty_features() -> dict[str, Any]:
    """Return zeroed-out features for empty content."""
    return {
        "word_count": 0,
        "sentence_count": 0,
        "avg_word_length": 0.0,
        "uppercase_ratio": 0.0,
        "digit_ratio": 0.0,
        "punctuation_ratio": 0.0,
        "text_entropy": 0.0,
        "language": "unknown",
        "urgency_score": 0.0,
        "credential_request_score": 0.0,
        "financial_request_score": 0.0,
        "account_action_score": 0.0,
        "threat_score": 0.0,
        "authority_impersonation_score": 0.0,
        "call_to_action_score": 0.0,
        "phishing_indicator_sum": 0.0,
    }
