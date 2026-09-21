"""
Main analysis pipeline.

Orchestrates the complete email analysis workflow:
  1. Parse email
  2. Run all analyzers (header, URL, content, HTML, attachment, sender, domain)
  3. Run relationship analysis
  4. Evaluate rules → signals
  5. Run ML prediction
  6. Fuse signals
  7. Compute risk score
  8. Generate explanation
  9. Return complete analysis result

Design principle: Every step is independent and testable in isolation.
"""

from __future__ import annotations

import uuid
from typing import Any

from app.core.config import PARSER_VERSION, RULE_VERSION, SCHEMA_VERSION
from app.services.parser import parse_email, ParsedEmail, ParseError
from app.analyzers.header import analyze as analyze_headers
from app.analyzers.url import analyze as analyze_urls
from app.analyzers.content import analyze as analyze_content
from app.analyzers.html import analyze as analyze_html
from app.analyzers.attachment import analyze as analyze_attachments
from app.analyzers.sender import analyze_sender
from app.analyzers.domain import analyze_domains
from app.analyzers.relationship import analyze_relationships
from app.services.rules import evaluate as evaluate_rules
from app.ml.model import get_predictor
from app.ml.features import extract_features
from app.services.fusion import fuse_signals
from app.services.scoring import compute_risk_score
from app.services.explanation import generate_explanation


def analyze_email_bytes(data: bytes) -> dict[str, Any]:
    """Analyze raw email bytes and return a complete result."""
    # Step 1: Parse
    parsed = parse_email(data)

    return analyze_parsed_email(parsed)


def analyze_parsed_email(parsed: ParsedEmail) -> dict[str, Any]:
    """Analyze an already-parsed email."""
    msg = parsed.message

    # Step 2: Run analyzers
    header_data = analyze_headers(msg)
    plain_body = parsed.plain_body
    html_body = parsed.html_body
    combined_text = plain_body + "\n" + html_body

    # Strip HTML for content analysis
    import re
    content_text = plain_body or re.sub(r"<[^>]+>", " ", html_body)

    content = analyze_content(content_text)
    url_features = analyze_urls(parsed.urls)
    html_features = analyze_html(html_body)
    attachment_features = analyze_attachments(msg)

    # Sender features
    sender_features = analyze_sender(
        header_data.get("sender", {}),
        header_data.get("sender", {}).get("reply_to_domain"),
        header_data.get("sender", {}).get("return_path_domain"),
    )

    # Domain features
    domains_to_check = [
        header_data.get("sender", {}).get("from_domain"),
        header_data.get("sender", {}).get("reply_to_domain"),
    ]
    # Add URL domains
    for u in url_features:
        d = u.get("normalized", {}).get("domain")
        if d:
            domains_to_check.append(d)
    domain_features = analyze_domains(domains_to_check)

    # Step 3: Relationship analysis
    relationships = analyze_relationships(
        header_data, url_features, content,
        attachment_features, sender_features, domain_features.get("domains"),
    )

    # Step 4: Rule evaluation
    rule_signals = evaluate_rules(
        header_data, url_features, content,
        attachment_features, sender_features,
        domain_features, html_features, relationships,
    )

    # Step 5: ML prediction
    predictor = get_predictor()
    ml_result = predictor.predict(
        combined_text, header_data, url_features, content,
        html_features, attachment_features,
        sender_features, domain_features,
    )

    # Create ML signal only on strong predictions (>0.7) to avoid false positives
    ml_signal = None
    if ml_result.get("is_ml_prediction") and ml_result.get("probability", 0) > 0.7:
        from app.schemas.analysis import Signal
        ml_prob = ml_result["probability"]
        ml_signal = Signal(
            signal_id="ML-S001",
            category="ml",
            severity=round(ml_prob, 4),
            risk_contribution=round(ml_prob * 20.0, 2),
            source="ml",
            explanation=f"ML model estimates {ml_prob:.0%} phishing probability.",
            evidence={"probability": ml_prob, "model_version": ml_result.get("model_version")},
        )

    # Step 6: Fuse signals
    all_signals = fuse_signals(rule_signals, ml_signal)

    # Step 7: Compute risk score
    deception_score = relationships.get("deception_score", 0.0)

    # Relationship bonus: only if specific correlated indicators are present
    relationship_bonus = 0.0
    if (
        header_data.get("headers", {}).get("reply_to_mismatch")
        and content.get("credential_request_score", 0) >= 0.75
    ):
        relationship_bonus = 5.0

    risk = compute_risk_score(
        all_signals,
        ml_probability=ml_result.get("probability", 0.0),
        deception_score=deception_score,
        relationship_bonus=relationship_bonus,
    )

    # Step 8: Generate explanation
    explanation = generate_explanation(
        all_signals, risk["score"], risk["classification"],
        header_data.get("sender", {}), header_data,
        url_features, content, relationships,
    )

    # Build the verdict
    verdict = {
        "classification": risk["classification"],
        "reasons": [s.explanation for s in all_signals],
        "recommended_action": explanation["recommended_action"],
    }

    # Step 9: Assemble final result
    return {
        "schema_version": SCHEMA_VERSION,
        "analysis_id": str(uuid.uuid4()),
        "metadata": {
            "message_id": msg.get("Message-ID"),
            "subject": msg.get("Subject"),
            "date": msg.get("Date"),
            "from": msg.get("From"),
            "to": msg.get("To"),
            "parser_version": PARSER_VERSION,
            "rule_version": RULE_VERSION,
            "model_version": ml_result.get("model_version", "unknown"),
        },
        "sender": header_data["sender"],
        "authentication": header_data["authentication"],
        "headers": header_data["headers"],
        "urls": url_features,
        "content": content,
        "html": html_features,
        "attachments": attachment_features,
        "sender_features": sender_features,
        "domain_features": domain_features,
        "relationships": relationships,
        "signals": [s.model_dump() for s in all_signals],
        "risk": risk,
        "verdict": verdict,
        "explanation": explanation,
        "ml_prediction": ml_result,
    }
