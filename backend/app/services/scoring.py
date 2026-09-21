"""
Risk Scoring Engine.

Converts fused signals into a 0–100 risk score and a classification.

Scoring methodology:
1. Sum all risk contributions from fused signals
2. Apply ML probability as an additional component
3. Apply relationship / deception bonus
4. Clamp to [0, 100]
5. Map to classification using configurable thresholds
6. Estimate confidence based on signal agreement
"""

from __future__ import annotations

from typing import Any

from app.core.config import RISK_THRESHOLDS
from app.schemas.analysis import Signal


def compute_risk_score(
    signals: list[Signal],
    ml_probability: float = 0.0,
    deception_score: float = 0.0,
    relationship_bonus: float = 0.0,
) -> dict[str, Any]:
    """Compute the final risk score, confidence, and classification."""

    # Base score: sum of all signal risk contributions
    base_score = sum(s.risk_contribution for s in signals)

    # ML component: scale 0-1 probability to 0-25 range
    ml_component = ml_probability * 25.0

    # Relationship / deception component
    relationship_component = deception_score * 10.0 + relationship_bonus

    # Total score
    raw_score = base_score + ml_component + relationship_component
    score = round(min(100.0, max(0.0, raw_score)), 2)

    # Classification
    classification = _classify(score)

    # Confidence estimation
    confidence = _estimate_confidence(signals, ml_probability, score)

    return {
        "score": score,
        "confidence": round(confidence, 4),
        "classification": classification,
        "breakdown": {
            "rule_contribution": round(base_score, 2),
            "ml_contribution": round(ml_component, 2),
            "relationship_contribution": round(relationship_component, 2),
        },
    }


def _classify(score: float) -> str:
    """Map a risk score to a classification."""
    if score >= RISK_THRESHOLDS["phishing_lower"]:
        return "phishing"
    elif score >= RISK_THRESHOLDS["high_suspicious_lower"]:
        return "high_suspicious"
    elif score >= RISK_THRESHOLDS["suspicious_lower"]:
        return "suspicious"
    else:
        return "benign"


def _estimate_confidence(
    signals: list[Signal],
    ml_probability: float,
    score: float,
) -> float:
    """Estimate confidence in the classification.

    Confidence is higher when:
    - Multiple signals agree (consistent category distribution)
    - Signals have high severity
    - ML probability aligns with rule-based score
    - Score is far from decision boundaries
    """
    if not signals:
        return 0.1

    # Signal count factor: more signals = more confidence
    signal_count_factor = min(1.0, len(signals) / 8.0)

    # Severity factor: average severity across signals
    avg_severity = sum(s.severity for s in signals) / max(1, len(signals))
    severity_factor = avg_severity

    # Category diversity: signals from multiple categories = more confidence
    categories = set(s.category for s in signals)
    category_factor = min(1.0, len(categories) / 4.0)

    # Boundary distance: scores near thresholds are less confident
    boundaries = [
        RISK_THRESHOLDS["suspicious_lower"],
        RISK_THRESHOLDS["high_suspicious_lower"],
        RISK_THRESHOLDS["phishing_lower"],
    ]
    min_boundary_dist = min(abs(score - b) for b in boundaries) / 25.0
    boundary_factor = min(1.0, min_boundary_dist)

    # ML alignment: if ML and rules agree, confidence is higher
    ml_alignment = 1.0 - abs(ml_probability - (score / 100.0))

    # Weighted combination
    confidence = (
        signal_count_factor * 0.20
        + severity_factor * 0.25
        + category_factor * 0.15
        + boundary_factor * 0.20
        + ml_alignment * 0.20
    )

    return min(1.0, max(0.0, confidence))
