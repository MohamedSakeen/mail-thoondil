"""
Feature extraction for ML-based phishing detection.

Converts the structured feature dictionaries produced by analyzers
into a flat numerical feature vector suitable for scikit-learn models.
"""

from __future__ import annotations

from typing import Any


# Canonical feature names in order.  This list IS the model contract;
# changing it requires retraining.
FEATURE_NAMES: list[str] = [
    # Header / sender
    "reply_to_mismatch",
    "return_path_mismatch",
    "message_id_domain_mismatch",
    "display_name_from_mismatch",
    "sender_domain_digit_ratio",
    "sender_domain_hyphen_count",
    "received_hop_count",
    # Authentication
    "spf_fail",
    "dkim_fail",
    "dmarc_fail",
    # URL aggregate
    "url_count",
    "url_has_ip",
    "url_has_punycode",
    "url_has_shortener",
    "url_has_at_symbol",
    "url_avg_length",
    "url_max_subdomain_count",
    "url_suspicious_keyword_count",
    # Content / NLP
    "word_count",
    "uppercase_ratio",
    "urgency_score",
    "credential_request_score",
    "financial_request_score",
    "threat_score",
    "authority_impersonation_score",
    "call_to_action_score",
    "phishing_indicator_sum",
    # HTML
    "html_form_count",
    "html_iframe_count",
    "html_script_count",
    "html_hidden_count",
    "html_external_resource_count",
    "html_mismatch_count",
    # Attachments
    "attachment_count",
    "has_executable",
    "has_macro_document",
    "has_html_attachment",
    "has_archive",
    "has_double_extension",
    # Sender features
    "brand_domain_mismatch",
    "cross_brand_conflict",
    # Domain
    "has_suspicious_tld",
    "has_homoglyphs",
    "domain_random_pattern",
]


def extract_features(
    header_data: dict[str, Any],
    url_features: list[dict[str, Any]],
    content: dict[str, Any],
    html_features: dict[str, Any],
    attachment_features: list[dict[str, Any]],
    sender_features: dict[str, Any] | None = None,
    domain_features: list[dict[str, Any]] | None = None,
) -> list[float]:
    """Extract a flat feature vector from analyzer outputs."""
    sender = header_data.get("sender", {})
    auth = header_data.get("authentication", {})
    headers = header_data.get("headers", {})
    sender_f = sender_features or {}
    domain_f = domain_features or {}

    # URL aggregates
    url_has_ip = any(u.get("features", {}).get("is_ip_address") for u in url_features)
    url_has_puny = any(u.get("features", {}).get("has_punycode") for u in url_features)
    url_has_short = any(u.get("features", {}).get("shortener_detected") for u in url_features)
    url_has_at = any(u.get("features", {}).get("has_at_symbol") for u in url_features)
    url_lengths = [u.get("features", {}).get("length", 0) for u in url_features]
    url_subs = [u.get("features", {}).get("subdomain_count", 0) for u in url_features]
    url_kw_count = sum(
        u.get("features", {}).get("suspicious_keyword_count", 0) for u in url_features
    )

    # Attachment aggregates
    att_exec = any(a.get("features", {}).get("executable") for a in attachment_features)
    att_macro = any(a.get("features", {}).get("macro_document") for a in attachment_features)
    att_html = any(a.get("features", {}).get("html_attachment") for a in attachment_features)
    att_archive = any(a.get("features", {}).get("archive") for a in attachment_features)
    att_double = any(a.get("features", {}).get("double_extension") for a in attachment_features)

    # Domain aggregates
    domains = domain_f.get("domains", [])
    has_susp_tld = domain_f.get("suspicious_tld_count", 0) > 0
    has_homoglyphs = domain_f.get("homoglyph_count", 0) > 0
    has_random = domain_f.get("random_pattern_count", 0) > 0

    values = [
        # Header / sender
        float(headers.get("reply_to_mismatch", False)),
        float(headers.get("return_path_mismatch", False)),
        float(headers.get("message_id_domain_mismatch", False)),
        float(sender_f.get("brand_domain_mismatch", False) or headers.get("display_name_from_mismatch", False)),
        sender.get("sender_domain_digit_ratio", 0.0),
        sender.get("sender_domain_hyphen_count", 0),
        headers.get("received_hop_count", 0),
        # Authentication
        float(auth.get("spf_fail", False)),
        float(auth.get("dkim_fail", False)),
        float(auth.get("dmarc_fail", False)),
        # URL
        float(len(url_features)),
        float(url_has_ip),
        float(url_has_puny),
        float(url_has_short),
        float(url_has_at),
        (sum(url_lengths) / max(1, len(url_lengths))) if url_lengths else 0.0,
        max(url_subs) if url_subs else 0,
        float(url_kw_count),
        # Content / NLP
        content.get("word_count", 0),
        content.get("uppercase_ratio", 0.0),
        content.get("urgency_score", 0.0),
        content.get("credential_request_score", 0.0),
        content.get("financial_request_score", 0.0),
        content.get("threat_score", 0.0),
        content.get("authority_impersonation_score", 0.0),
        content.get("call_to_action_score", 0.0),
        content.get("phishing_indicator_sum", 0.0),
        # HTML
        html_features.get("form_count", 0),
        html_features.get("iframe_count", 0),
        html_features.get("script_count", 0),
        html_features.get("hidden_element_count", 0),
        html_features.get("external_resource_count", 0),
        html_features.get("visible_actual_mismatch_count", 0),
        # Attachments
        float(len(attachment_features)),
        float(att_exec),
        float(att_macro),
        float(att_html),
        float(att_archive),
        float(att_double),
        # Sender
        float(sender_f.get("brand_domain_mismatch", False)),
        float(sender_f.get("cross_brand_conflict", False)),
        # Domain
        float(has_susp_tld),
        float(has_homoglyphs),
        float(has_random),
    ]

    return values
