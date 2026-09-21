"""
Explanation Engine.

Generates human-readable explanations and attack narratives from
the signals, risk score, and relationship analysis.

The output is not just:
    PHISHING — 89/100

But rather:
    HIGH RISK — 89/100

    Primary indicators:
    - Sender domain resembles a trusted organization.
    - DMARC authentication failed.
    - Reply-To domain differs from sender.
    - Message requests credentials.

    Attack narrative:
    An email impersonating Microsoft was sent from a non-Microsoft domain
    with failed authentication. The Reply-To address redirects to a
    different domain, and the message urges the recipient to verify
    their password via a suspicious URL.
"""

from __future__ import annotations

from typing import Any

from app.core.config import RISK_THRESHOLDS, PolicyAction, POLICY_MAP
from app.schemas.analysis import Signal


def generate_explanation(
    signals: list[Signal],
    risk_score: float,
    classification: str,
    sender_info: dict[str, Any],
    header_data: dict[str, Any],
    url_features: list[dict[str, Any]],
    content: dict[str, Any],
    relationships: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate a complete explanation with attack narrative."""

    # Group signals by category
    signals_by_category: dict[str, list[Signal]] = {}
    for sig in signals:
        signals_by_category.setdefault(sig.category, []).append(sig)

    # Sort categories by total risk contribution
    category_importance = sorted(
        signals_by_category.keys(),
        key=lambda cat: sum(s.risk_contribution for s in signals_by_category[cat]),
        reverse=True,
    )

    # Primary indicators (top 5 by risk contribution)
    primary_signals = sorted(signals, key=lambda s: s.risk_contribution, reverse=True)[:5]

    # Attack narrative
    narrative = _build_narrative(
        signals, classification, sender_info, header_data,
        url_features, content, relationships,
    )

    # Risk level label
    risk_label = _risk_label(classification)

    # Recommended action
    recommended_action = _recommended_action(classification, risk_score)

    return {
        "risk_label": risk_label,
        "risk_score": risk_score,
        "classification": classification,
        "primary_indicators": [
            {
                "category": s.category,
                "explanation": s.explanation,
                "severity": s.severity,
                "risk_contribution": s.risk_contribution,
            }
            for s in primary_signals
        ],
        "signals_by_category": {
            cat: [
                {"explanation": s.explanation, "risk": s.risk_contribution}
                for s in cat_signals
            ]
            for cat, cat_signals in [
                (c, signals_by_category[c]) for c in category_importance
            ]
        },
        "narrative": narrative,
        "recommended_action": recommended_action,
        "total_signals": len(signals),
        "categories_triggered": len(signals_by_category),
    }


def _risk_label(classification: str) -> str:
    """Map classification to a human-readable risk label."""
    labels = {
        "benign": "LOW RISK",
        "suspicious": "MODERATE RISK",
        "high_suspicious": "HIGH RISK",
        "phishing": "CRITICAL — LIKELY PHISHING",
    }
    return labels.get(classification, "UNKNOWN")


def _recommended_action(classification: str, risk_score: float) -> str:
    """Map classification to a recommended analyst action."""
    action = POLICY_MAP.get(classification, PolicyAction.REVIEW)

    descriptions = {
        PolicyAction.ALLOW: "This email appears legitimate. No action required.",
        PolicyAction.REVIEW: "This email has some suspicious indicators. Manual review recommended.",
        PolicyAction.ALERT: "This email is highly suspicious. Alert the security team.",
        PolicyAction.QUARANTINE: "This email is very likely phishing. Quarantine immediately and investigate.",
        PolicyAction.BLOCK: "Block this sender and investigate for broader campaign.",
    }
    return descriptions.get(action, "Review recommended.")


def _build_narrative(
    signals: list[Signal],
    classification: str,
    sender_info: dict[str, Any],
    header_data: dict[str, Any],
    url_features: list[dict[str, Any]],
    content: dict[str, Any],
    relationships: dict[str, Any] | None,
) -> str:
    """Build a human-readable attack narrative."""
    parts: list[str] = []
    sender = header_data.get("sender", {})
    auth = header_data.get("authentication", {})
    headers = header_data.get("headers", {})

    # Opening
    sender_domain = sender.get("from_domain", "unknown")
    display_name = sender.get("display_name", "")
    subject = header_data.get("metadata", {}).get("subject", "No subject")

    if classification in ("phishing", "high_suspicious"):
        if display_name:
            parts.append(
                f'An email claiming to be from "{display_name}" was sent '
                f"from {sender_domain}."
            )
        else:
            parts.append(f"An email from {sender_domain} was analyzed.")

        # Authentication story
        auth_issues = []
        if auth.get("spf_fail"):
            auth_issues.append("SPF")
        if auth.get("dkim_fail"):
            auth_issues.append("DKIM")
        if auth.get("dmarc_fail"):
            auth_issues.append("DMARC")
        if auth_issues:
            parts.append(
                f"Authentication checks failed: {', '.join(auth_issues)}. "
                "This suggests the sender is not authorized to send from this domain."
            )

        # Reply-To story
        if headers.get("reply_to_mismatch"):
            reply_domain = sender.get("reply_to_domain", "unknown")
            parts.append(
                f"The Reply-To address redirects to {reply_domain}, "
                f"which differs from the sender domain."
            )

        # URL story
        suspicious_urls = [
            u for u in url_features
            if u.get("features", {}).get("is_ip_address")
            or u.get("features", {}).get("shortener_detected")
            or u.get("features", {}).get("has_at_symbol")
            or u.get("features", {}).get("suspicious_keyword_count", 0) > 0
        ]
        if suspicious_urls:
            parts.append(
                f"The email contains {len(suspicious_urls)} suspicious URL(s)."
            )

        # Content story
        if content.get("credential_request_score", 0) > 0.5:
            parts.append("The message urges the recipient to provide credentials or verify their account.")
        if content.get("urgency_score", 0) > 0.5:
            parts.append("The message uses urgency tactics to pressure immediate action.")
        if content.get("threat_score", 0) > 0.5:
            parts.append("The message contains threatening language about account suspension or consequences.")

    elif classification == "suspicious":
        parts.append(
            f"Email from {sender_domain} has some suspicious indicators "
            f"but is not definitively phishing."
        )
        top_signals = sorted(signals, key=lambda s: s.risk_contribution, reverse=True)[:3]
        for sig in top_signals:
            parts.append(f"- {sig.explanation}")

    else:  # benign
        parts.append(
            f"Email from {sender_domain} appears legitimate with no significant "
            f"phishing indicators detected."
        )

    return " ".join(parts)
