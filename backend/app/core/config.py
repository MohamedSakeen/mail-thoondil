"""
Centralized configuration for the Phishing Mail Detector.
All magic numbers, thresholds, limits, and version strings live here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Versioning – stored with every analysis for reproducibility
# ---------------------------------------------------------------------------
SCHEMA_VERSION = "1.0"
PARSER_VERSION = "1.0.0"
RULE_VERSION = "1.0.0"
MODEL_VERSION = "baseline-v1"


# ---------------------------------------------------------------------------
# Security limits
# ---------------------------------------------------------------------------
MAX_EMAIL_BYTES = 10 * 1024 * 1024          # 10 MB
MAX_MIME_DEPTH = 30
MAX_URL_LENGTH = 2048
MAX_ATTACHMENT_COUNT = 50
MAX_SINGLE_ATTACHMENT_BYTES = 25 * 1024 * 1024  # 25 MB
MAX_HTML_SIZE = 5 * 1024 * 1024             # 5 MB
MAX_URLS_PER_EMAIL = 100

# SSRF / outbound-request protection
ALLOWED_SCHEMES = {"http", "https"}
BLOCKED_HOSTNAMES = {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
MAX_EXTERNAL_FETCH_TIMEOUT = 5  # seconds

# ---------------------------------------------------------------------------
# Risk-score thresholds  (0–100 scale)
# ---------------------------------------------------------------------------
RISK_THRESHOLDS = {
    "benign_upper": 24,
    "suspicious_lower": 25,
    "suspicious_upper": 49,
    "high_suspicious_lower": 50,
    "high_suspicious_upper": 74,
    "phishing_lower": 75,
}

# Category caps prevent one dimension from dominating the score.
CATEGORY_CAPS: dict[str, float] = {
    "authentication": 20,
    "sender": 20,
    "url": 30,
    "domain": 20,
    "content": 25,
    "html": 20,
    "attachment": 25,
    "relationship": 15,
    "ml": 25,
}


# ---------------------------------------------------------------------------
# Content-analysis keyword patterns
# ---------------------------------------------------------------------------
URGENCY_PATTERNS = [
    r"\burgent\b", r"\bimmediately\b", r"\bwithin\s+\d+\b",
    r"\bact\s+now\b", r"\basap\b", r"\btime\s+sensitive\b",
    r"\bexpires?\b", r"\blast\s+chance\b",
]

CREDENTIAL_PATTERNS = [
    r"\bpassword\b", r"\bverify\s+(your\s+)?account\b",
    r"\bsign\s+in\b", r"\blogin\b", r"\bcredentials?\b",
    r"\bconfirm\s+your\s+identity\b", r"\bupdate\s+your\s+information\b",
    r"\baccount\s+verification\b", r"\benter\s+your\b",
]

FINANCIAL_PATTERNS = [
    r"\bpayment\b", r"\binvoice\b", r"\bwire\s+transfer\b",
    r"\bbank\b", r"\bbitcoin\b", r"\bcrypto\b", r"\bpay\s+now\b",
    r"\brefund\b", r"\baccount\s+number\b",
]

THREAT_PATTERNS = [
    r"\bsuspend\w*\b", r"\bterminate\w*\b", r"\blocked\b",
    r"\blegal\s+action\b", r"\bpenalty\b", r"\bdeactivate\w*\b",
    r"\bwill\s+be\s+clos", r"\brestrict\w*\b",
]

AUTHORITY_PATTERNS = [
    r"\bsecurity\s+team\b", r"\badministrator\b",
    r"\bsupport\s+team\b", r"\bIT\s+department\b",
    r"\bhelpdesk\b", r"\bsystem\s+admin\b", r"\bnoreply\b",
    r"\bcompliance\b",
]

ACCOUNT_ACTION_PATTERNS = [
    r"\baccount\b", r"\bsuspend\w*\b", r"\bverify\b",
    r"\bunlock\b", r"\bsecurity\b", r"\brestore\b",
    r"\breactivate\b", r"\bconfirm\b",
]

CALL_TO_ACTION_PATTERNS = [
    r"\bclick\s+(here|below|the)\b", r"\bverify\b",
    r"\bopen\s+the\b", r"\bdownload\b", r"\bconfirm\b",
    r"\bfollow\s+(this|the)\b", r"\bupdate\s+now\b",
]


# ---------------------------------------------------------------------------
# Shortener / known-suspicious domains (small seed list)
# ---------------------------------------------------------------------------
KNOWN_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "cutt.ly", "rebrand.ly", "shorturl.at",
    "bl.ink", "lnkd.in", "rb.gy", "tiny.cc",
})

SUSPICIOUS_TLDS = frozenset({
    ".xyz", ".top", ".club", ".work", ".buzz", ".tk", ".ml",
    ".ga", ".cf", ".gq", ".loan", ".racing", ".date", ".win",
    ".bid", ".stream", ".download", ".accountant", ".faith",
})

# ---------------------------------------------------------------------------
# Database
# ---------------------------------------------------------------------------
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://phishing:phishing@localhost:5432/phishing_detector",
)

DATABASE_URL_SYNC = os.getenv(
    "DATABASE_URL_SYNC",
    "postgresql://phishing:phishing@localhost:5432/phishing_detector",
)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
API_PREFIX = "/api/v1"
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000").split(",")


# ---------------------------------------------------------------------------
# ML
# ---------------------------------------------------------------------------
ML_MODEL_DIR = os.getenv("ML_MODEL_DIR", "models")
ML_MAX_FEATURES = 10_000
ML_NGRAM_RANGE = (1, 2)


# ---------------------------------------------------------------------------
# Policy actions
# ---------------------------------------------------------------------------
class PolicyAction:
    ALLOW = "allow"
    REVIEW = "review"
    ALERT = "alert"
    QUARANTINE = "quarantine"
    BLOCK = "block"


POLICY_MAP = {
    "benign": PolicyAction.ALLOW,
    "suspicious": PolicyAction.REVIEW,
    "high_suspicious": PolicyAction.ALERT,
    "phishing": PolicyAction.QUARANTINE,
}
