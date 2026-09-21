"""
Relationship analyzer: correlates signals across different analyzers
to produce stronger combined indicators.

This is where the "attack narrative" begins to form. Individual signals
from different analyzers are cross-referenced to detect coordinated
deception patterns.

Example:
    Claimed Brand = Microsoft
    Sender Domain = micros0ft.example  (homoglyph)
    Reply-To = attacker.example  (mismatch)
    URL = credential-login.example  (suspicious)
    Content = "verify your password"  (credential request)

This correlation produces a stronger combined signal than any
individual analyzer alone.
"""

from __future__ import annotations

from typing import Any


def analyze_relationships(
    header_data: dict[str, Any],
    url_features: list[dict[str, Any]],
    content_features: dict[str, Any],
    attachment_features: list[dict[str, Any]],
    sender_features: dict[str, Any] | None = None,
    domain_features: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Cross-correlate features from different analyzers."""
    relationships: dict[str, float] = {}
    details: dict[str, Any] = {}

    sender = header_data.get("sender", {})
    auth = header_data.get("authentication", {})
    headers = header_data.get("headers", {})

    # 1. From ↔ Reply-To consistency
    from_replyto_consistency = _check_from_replyto_consistency(
        sender.get("from_domain"), sender.get("reply_to_domain")
    )
    relationships["from_replyto_consistency"] = from_replyto_consistency

    # 2. Sender ↔ URL domain consistency
    sender_url_consistency = _check_sender_url_consistency(
        sender.get("from_domain"), url_features
    )
    relationships["sender_url_consistency"] = sender_url_consistency

    # 3. Brand ↔ Domain consistency
    brand_domain_consistency = _check_brand_domain_consistency(
        sender_features or {}
    )
    relationships["brand_domain_consistency"] = brand_domain_consistency

    # 4. Brand ↔ URL consistency
    brand_url_consistency = _check_brand_url_consistency(
        sender_features or {}, url_features
    )
    relationships["brand_url_consistency"] = brand_url_consistency

    # 5. Authentication ↔ Identity consistency
    auth_identity_consistency = _check_auth_identity_consistency(
        auth, headers
    )
    relationships["authentication_identity_consistency"] = auth_identity_consistency

    # 6. Visible ↔ Actual URL domain consistency
    visible_actual_consistency = _check_visible_actual_consistency(
        url_features
    )
    relationships["visible_actual_domain_consistency"] = visible_actual_consistency

    # 7. Content ↔ Attachment consistency
    content_attachment_consistency = _check_content_attachment_consistency(
        content_features, attachment_features
    )
    relationships["content_attachment_consistency"] = content_attachment_consistency

    # 8. Overall deception score (weighted combination)
    deception_score = _compute_deception_score(relationships)

    return {
        "relationships": relationships,
        "deception_score": round(deception_score, 4),
        "details": details,
    }


def _check_from_replyto_consistency(
    from_domain: str | None, reply_to_domain: str | None
) -> float:
    """Check if From and Reply-To domains are consistent.
    Returns 1.0 for consistent, 0.0 for mismatch.
    """
    if not from_domain or not reply_to_domain:
        return 1.0  # Can't determine, assume consistent
    return 1.0 if from_domain == reply_to_domain else 0.0


def _check_sender_url_consistency(
    from_domain: str | None, url_features: list[dict[str, Any]]
) -> float:
    """Check if sender domain appears in any of the URLs."""
    if not from_domain or not url_features:
        return 1.0

    matching = sum(
        1 for u in url_features
        if from_domain in u.get("normalized", {}).get("domain", "")
    )
    if matching > 0:
        return 1.0
    # No URL matches the sender domain
    return 0.0


def _check_brand_domain_consistency(sender_features: dict[str, Any]) -> float:
    """Check if claimed brand matches the domain brand."""
    if not sender_features:
        return 1.0
    if sender_features.get("brand_domain_mismatch"):
        return 0.0
    if sender_features.get("cross_brand_conflict"):
        return 0.1
    return 1.0


def _check_brand_url_consistency(
    sender_features: dict[str, Any],
    url_features: list[dict[str, Any]],
) -> float:
    """Check if claimed brand is consistent with URL domains."""
    if not sender_features or not url_features:
        return 1.0

    claimed = sender_features.get("claimed_brands", [])
    if not claimed:
        return 1.0  # No brand claimed, can't be inconsistent

    # Check if any URL domain is from the claimed brand's known domains
    from app.analyzers.sender import _BRAND_LEGITIMATE_DOMAINS
    legit_domains: set[str] = set()
    for b in claimed:
        legit_domains.update(_BRAND_LEGITIMATE_DOMAINS.get(b, set()))

    for u in url_features:
        url_domain = u.get("normalized", {}).get("domain", "")
        if any(legit in url_domain for legit in legit_domains):
            return 1.0

    # None of the URLs are from legitimate brand domains
    return 0.2


def _check_auth_identity_consistency(
    auth: dict[str, Any], headers: dict[str, Any]
) -> float:
    """Check if authentication results are consistent with identity claims."""
    score = 1.0

    # Authentication failures
    if auth.get("spf_fail"):
        score -= 0.3
    if auth.get("dkim_fail"):
        score -= 0.3
    if auth.get("dmarc_fail"):
        score -= 0.4

    # Mismatched identity fields
    if headers.get("reply_to_mismatch"):
        score -= 0.2
    if headers.get("return_path_mismatch"):
        score -= 0.2
    if headers.get("message_id_domain_mismatch"):
        score -= 0.1

    return max(0.0, score)


def _check_visible_actual_consistency(url_features: list[dict[str, Any]]) -> float:
    """Check if visible text matches actual URL destinations."""
    if not url_features:
        return 1.0

    # Count URLs with suspicious properties
    suspicious_count = sum(
        1 for u in url_features
        if u.get("features", {}).get("is_ip_address")
        or u.get("features", {}).get("has_at_symbol")
        or u.get("features", {}).get("has_encoded_chars")
    )

    if not suspicious_count:
        return 1.0

    return max(0.0, 1.0 - (suspicious_count * 0.3))


def _check_content_attachment_consistency(
    content_features: dict[str, Any],
    attachment_features: list[dict[str, Any]],
) -> float:
    """Check if content and attachments are consistent."""
    score = 1.0

    # Content mentions "attached" but no attachments present
    has_attachment_reference = content_features.get("call_to_action_score", 0) > 0.5
    has_attachments = len(attachment_features) > 0

    # Dangerous attachments with credential-request content
    dangerous_attachments = sum(
        1 for a in attachment_features
        if a.get("features", {}).get("dangerous_type", False)
    )
    if dangerous_attachments and content_features.get("credential_request_score", 0) > 0.5:
        score -= 0.3

    return max(0.0, score)


def _compute_deception_score(relationships: dict[str, float]) -> float:
    """Compute overall deception score from relationship consistency scores.
    Lower score = more deceptive (more inconsistencies).
    """
    if not relationships:
        return 0.5

    # Weight the relationships
    weights = {
        "from_replyto_consistency": 0.15,
        "sender_url_consistency": 0.15,
        "brand_domain_consistency": 0.15,
        "brand_url_consistency": 0.15,
        "authentication_identity_consistency": 0.20,
        "visible_actual_domain_consistency": 0.10,
        "content_attachment_consistency": 0.10,
    }

    total_weight = 0.0
    weighted_sum = 0.0
    for key, weight in weights.items():
        if key in relationships:
            weighted_sum += relationships[key] * weight
            total_weight += weight

    if total_weight == 0:
        return 0.5

    # Invert: higher deception score = more suspicious
    consistency = weighted_sum / total_weight
    return 1.0 - consistency
