"""
YAML-based configurable rule engine.

Rules convert extracted features into security signals. Each rule:
1. Has a unique ID (e.g., AUTH-S001)
2. Checks one or more features
3. Produces a Signal with a severity and risk contribution
4. Provides a human-readable explanation

Rules are defined in YAML files under rules/ and loaded at startup.
Falling back to built-in rules if YAML files are not found.
"""

from __future__ import annotations

import os
import re
from typing import Any

import yaml

from app.core.config import RULE_VERSION
from app.schemas.analysis import Signal

# Path to YAML rule definitions
RULES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "rules")


def evaluate(
    header_data: dict[str, Any],
    url_features: list[dict[str, Any]],
    content: dict[str, Any],
    attachment_features: list[dict[str, Any]],
    sender_features: dict[str, Any] | None = None,
    domain_features: dict[str, Any] | None = None,
    html_features: dict[str, Any] | None = None,
    relationships: dict[str, Any] | None = None,
) -> list[Signal]:
    """Evaluate all rules against the extracted features."""
    # Try to load YAML rules first, fall back to built-in
    yaml_rules = _load_yaml_rules()
    if yaml_rules:
        return _evaluate_yaml_rules(
            yaml_rules, header_data, url_features, content,
            attachment_features, sender_features, domain_features,
            html_features, relationships,
        )
    return _builtin_rules(
        header_data, url_features, content, attachment_features,
        sender_features, domain_features, html_features, relationships,
    )


# ---------------------------------------------------------------------------
# Built-in rules (fallback when YAML files aren't available)
# ---------------------------------------------------------------------------

def _builtin_rules(
    header_data: dict[str, Any],
    url_features: list[dict[str, Any]],
    content: dict[str, Any],
    attachment_features: list[dict[str, Any]],
    sender_features: dict[str, Any] | None = None,
    domain_features: dict[str, Any] | None = None,
    html_features: dict[str, Any] | None = None,
    relationships: dict[str, Any] | None = None,
) -> list[Signal]:
    """Built-in rules evaluated against extracted features."""
    signals: list[Signal] = []
    auth = header_data.get("authentication", {})
    headers = header_data.get("headers", {})
    sender = header_data.get("sender", {})

    # === Authentication Rules ===
    if auth.get("dmarc_fail"):
        signals.append(Signal(
            signal_id="AUTH-S001",
            category="authentication",
            severity=0.7,
            risk_contribution=10.0,
            source="rule",
            explanation="DMARC authentication failed.",
            evidence={"dmarc": auth.get("dmarc")},
        ))

    if auth.get("spf_fail"):
        signals.append(Signal(
            signal_id="AUTH-S002",
            category="authentication",
            severity=0.6,
            risk_contribution=8.0,
            source="rule",
            explanation="SPF authentication failed.",
            evidence={"spf": auth.get("spf")},
        ))

    if auth.get("dkim_fail"):
        signals.append(Signal(
            signal_id="AUTH-S003",
            category="authentication",
            severity=0.6,
            risk_contribution=8.0,
            source="rule",
            explanation="DKIM authentication failed.",
            evidence={"dkim": auth.get("dkim")},
        ))

    # All three fail = very strong signal
    if auth.get("spf_fail") and auth.get("dkim_fail") and auth.get("dmarc_fail"):
        signals.append(Signal(
            signal_id="AUTH-S004",
            category="authentication",
            severity=0.95,
            risk_contribution=5.0,  # Additional on top of individual
            source="rule",
            explanation="All authentication checks (SPF, DKIM, DMARC) failed.",
            evidence={"spf": auth.get("spf"), "dkim": auth.get("dkim"), "dmarc": auth.get("dmarc")},
        ))

    # === Sender Rules ===
    if headers.get("reply_to_mismatch"):
        signals.append(Signal(
            signal_id="SND-S001",
            category="sender",
            severity=0.8,
            risk_contribution=12.0,
            source="rule",
            explanation="Reply-To domain differs from the sender domain.",
            evidence={
                "from_domain": sender.get("from_domain"),
                "reply_to_domain": sender.get("reply_to_domain"),
            },
        ))

    if headers.get("return_path_mismatch"):
        signals.append(Signal(
            signal_id="SND-S002",
            category="sender",
            severity=0.7,
            risk_contribution=8.0,
            source="rule",
            explanation="Return-Path domain differs from the sender domain.",
            evidence={
                "from_domain": sender.get("from_domain"),
                "return_path_domain": sender.get("return_path_domain"),
            },
        ))

    if headers.get("message_id_domain_mismatch"):
        signals.append(Signal(
            signal_id="SND-S003",
            category="sender",
            severity=0.5,
            risk_contribution=5.0,
            source="rule",
            explanation="Message-ID domain differs from the sender domain.",
            evidence={
                "from_domain": sender.get("from_domain"),
                "message_id_domain": headers.get("message_id_domain"),
            },
        ))

    if sender.get("sender_domain_digit_ratio", 0) > 0.3:
        signals.append(Signal(
            signal_id="SND-S004",
            category="sender",
            severity=0.5,
            risk_contribution=4.0,
            source="rule",
            explanation="Sender domain contains a high ratio of digits.",
            evidence={"digit_ratio": sender.get("sender_domain_digit_ratio")},
        ))

    if headers.get("display_name_from_mismatch"):
        signals.append(Signal(
            signal_id="SND-S005",
            category="sender",
            severity=0.6,
            risk_contribution=6.0,
            source="rule",
            explanation="Display name does not match the sender domain.",
            evidence={
                "display_name": sender.get("display_name"),
                "from_domain": sender.get("from_domain"),
            },
        ))

    # Sender brand analysis
    if sender_features:
        if sender_features.get("brand_domain_mismatch"):
            signals.append(Signal(
                signal_id="SND-S006",
                category="sender",
                severity=0.85,
                risk_contribution=12.0,
                source="rule",
                explanation="Display name claims a brand but the sender domain is not associated with it.",
                evidence={
                    "claimed_brands": sender_features.get("claimed_brands"),
                    "from_domain": sender.get("from_domain"),
                },
            ))
        if sender_features.get("cross_brand_conflict"):
            signals.append(Signal(
                signal_id="SND-S007",
                category="sender",
                severity=0.8,
                risk_contribution=10.0,
                source="rule",
                explanation="Display name references a different brand than the sender domain.",
                evidence={
                    "claimed_brands": sender_features.get("claimed_brands"),
                    "domain_brands": sender_features.get("domain_brands"),
                },
            ))

    # === URL Rules ===
    for url in url_features:
        f = url.get("features", {})
        url_id = url.get("id", "url-?")

        if f.get("is_ip_address"):
            signals.append(Signal(
                signal_id="URL-S001",
                category="url",
                severity=0.9,
                risk_contribution=15.0,
                source="rule",
                explanation=f"URL {url_id} uses an IP address instead of a domain.",
                evidence={"url": url.get("raw_url")},
            ))

        if f.get("has_punycode"):
            signals.append(Signal(
                signal_id="URL-S002",
                category="url",
                severity=0.8,
                risk_contribution=10.0,
                source="rule",
                explanation=f"URL {url_id} contains a punycode domain label.",
                evidence={"url": url.get("raw_url")},
            ))

        if f.get("shortener_detected"):
            signals.append(Signal(
                signal_id="URL-S003",
                category="url",
                severity=0.6,
                risk_contribution=6.0,
                source="rule",
                explanation=f"URL {url_id} uses a URL shortening service.",
                evidence={"url": url.get("raw_url")},
            ))

        if f.get("has_at_symbol"):
            signals.append(Signal(
                signal_id="URL-S004",
                category="url",
                severity=0.85,
                risk_contribution=12.0,
                source="rule",
                explanation=f"URL {url_id} contains an @ symbol, which can mask the real destination.",
                evidence={"url": url.get("raw_url")},
            ))

        if f.get("suspicious_port"):
            signals.append(Signal(
                signal_id="URL-S005",
                category="url",
                severity=0.5,
                risk_contribution=5.0,
                source="rule",
                explanation=f"URL {url_id} uses a non-standard port.",
                evidence={"url": url.get("raw_url")},
            ))

        if not f.get("is_https"):
            signals.append(Signal(
                signal_id="URL-S006",
                category="url",
                severity=0.3,
                risk_contribution=2.0,
                source="rule",
                explanation=f"URL {url_id} does not use HTTPS.",
                evidence={"url": url.get("raw_url")},
            ))

        if f.get("suspicious_keyword_count", 0) >= 2:
            signals.append(Signal(
                signal_id="URL-S007",
                category="url",
                severity=0.6,
                risk_contribution=5.0,
                source="rule",
                explanation=f"URL {url_id} contains multiple suspicious keywords.",
                evidence={
                    "url": url.get("raw_url"),
                    "keywords": f.get("suspicious_keywords"),
                },
            ))

        if f.get("length", 0) > 200:
            signals.append(Signal(
                signal_id="URL-S008",
                category="url",
                severity=0.4,
                risk_contribution=3.0,
                source="rule",
                explanation=f"URL {url_id} is unusually long ({f['length']} chars).",
                evidence={"url": url.get("raw_url"), "length": f.get("length")},
            ))

        if f.get("subdomain_count", 0) >= 4:
            signals.append(Signal(
                signal_id="URL-S009",
                category="url",
                severity=0.5,
                risk_contribution=4.0,
                source="rule",
                explanation=f"URL {url_id} has excessive subdomains ({f['subdomain_count']}).",
                evidence={"url": url.get("raw_url"), "subdomain_count": f.get("subdomain_count")},
            ))

    # === Content / NLP Rules ===
    if content.get("credential_request_score", 0) >= 0.75:
        signals.append(Signal(
            signal_id="NLP-S001",
            category="content",
            severity=0.85,
            risk_contribution=12.0,
            source="rule",
            explanation="The message contains strong credential/account-verification language.",
            evidence={"credential_request_score": content.get("credential_request_score")},
        ))

    if content.get("urgency_score", 0) >= 0.75:
        signals.append(Signal(
            signal_id="NLP-S002",
            category="content",
            severity=0.75,
            risk_contribution=8.0,
            source="rule",
            explanation="The message uses strong urgency indicators.",
            evidence={"urgency_score": content.get("urgency_score")},
        ))

    if content.get("threat_score", 0) >= 0.6:
        signals.append(Signal(
            signal_id="NLP-S003",
            category="content",
            severity=0.7,
            risk_contribution=7.0,
            source="rule",
            explanation="The message contains threatening language.",
            evidence={"threat_score": content.get("threat_score")},
        ))

    if content.get("authority_impersonation_score", 0) >= 0.6:
        signals.append(Signal(
            signal_id="NLP-S004",
            category="content",
            severity=0.65,
            risk_contribution=6.0,
            source="rule",
            explanation="The message impersonates authority figures or departments.",
            evidence={"authority_impersonation_score": content.get("authority_impersonation_score")},
        ))

    if content.get("financial_request_score", 0) >= 0.75:
        signals.append(Signal(
            signal_id="NLP-S005",
            category="content",
            severity=0.8,
            risk_contribution=10.0,
            source="rule",
            explanation="The message contains financial request language.",
            evidence={"financial_request_score": content.get("financial_request_score")},
        ))

    if content.get("call_to_action_score", 0) >= 0.75:
        signals.append(Signal(
            signal_id="NLP-S006",
            category="content",
            severity=0.6,
            risk_contribution=5.0,
            source="rule",
            explanation="The message has a strong call-to-action pattern.",
            evidence={"call_to_action_score": content.get("call_to_action_score")},
        ))

    if content.get("uppercase_ratio", 0) > 0.5:
        signals.append(Signal(
            signal_id="NLP-S007",
            category="content",
            severity=0.4,
            risk_contribution=3.0,
            source="rule",
            explanation="The message is predominantly uppercase (shouting).",
            evidence={"uppercase_ratio": content.get("uppercase_ratio")},
        ))

    # Combined NLP signal: multiple high indicators
    high_indicator_count = sum(1 for k in [
        "urgency_score", "credential_request_score", "threat_score",
        "authority_impersonation_score", "financial_request_score",
    ] if content.get(k, 0) >= 0.6)

    if high_indicator_count >= 3:
        signals.append(Signal(
            signal_id="NLP-S008",
            category="content",
            severity=0.9,
            risk_contribution=8.0,
            source="rule",
            explanation=f"Multiple phishing indicators detected ({high_indicator_count} categories).",
            evidence={"high_indicator_count": high_indicator_count},
        ))

    # === Attachment Rules ===
    for att in attachment_features:
        f = att.get("features", {})
        att_id = att.get("id", "att-?")

        if f.get("executable") or f.get("double_extension"):
            signals.append(Signal(
                signal_id="ATT-S001",
                category="attachment",
                severity=0.95,
                risk_contribution=15.0,
                source="rule",
                explanation=f"Attachment {att_id} has an executable or deceptive extension.",
                evidence={"filename": att.get("filename"), "features": f},
            ))

        if f.get("macro_document"):
            signals.append(Signal(
                signal_id="ATT-S002",
                category="attachment",
                severity=0.85,
                risk_contribution=12.0,
                source="rule",
                explanation=f"Attachment {att_id} is a macro-capable document.",
                evidence={"filename": att.get("filename")},
            ))

        if f.get("html_attachment"):
            signals.append(Signal(
                signal_id="ATT-S003",
                category="attachment",
                severity=0.8,
                risk_contribution=10.0,
                source="rule",
                explanation=f"Attachment {att_id} is an HTML file (can contain phishing content).",
                evidence={"filename": att.get("filename")},
            ))

        if f.get("archive") and content.get("credential_request_score", 0) > 0.5:
            signals.append(Signal(
                signal_id="ATT-S004",
                category="attachment",
                severity=0.7,
                risk_contribution=8.0,
                source="rule",
                explanation=f"Attachment {att_id} is an archive in a message requesting credentials.",
                evidence={"filename": att.get("filename")},
            ))

    # === HTML Rules ===
    if html_features:
        if html_features.get("form_count", 0) > 0:
            signals.append(Signal(
                signal_id="HTML-S001",
                category="html",
                severity=0.7,
                risk_contribution=8.0,
                source="rule",
                explanation="The HTML contains forms (potential credential harvesting).",
                evidence={"form_count": html_features.get("form_count")},
            ))

        if html_features.get("iframe_count", 0) > 0:
            signals.append(Signal(
                signal_id="HTML-S002",
                category="html",
                severity=0.6,
                risk_contribution=6.0,
                source="rule",
                explanation="The HTML contains iframes (potential content injection).",
                evidence={"iframe_count": html_features.get("iframe_count")},
            ))

        if html_features.get("hidden_element_count", 0) > 3:
            signals.append(Signal(
                signal_id="HTML-S003",
                category="html",
                severity=0.6,
                risk_contribution=5.0,
                source="rule",
                explanation="The HTML contains many hidden elements.",
                evidence={"hidden_element_count": html_features.get("hidden_element_count")},
            ))

        if html_features.get("visible_actual_mismatch_count", 0) > 0:
            signals.append(Signal(
                signal_id="HTML-S004",
                category="html",
                severity=0.85,
                risk_contribution=12.0,
                source="rule",
                explanation="Link text does not match the actual URL destination.",
                evidence={"mismatch_count": html_features.get("visible_actual_mismatch_count")},
            ))

        if html_features.get("meta_refresh_count", 0) > 0:
            signals.append(Signal(
                signal_id="HTML-S005",
                category="html",
                severity=0.5,
                risk_contribution=5.0,
                source="rule",
                explanation="HTML contains meta refresh (auto-redirect).",
                evidence={"meta_refresh_count": html_features.get("meta_refresh_count")},
            ))

    # === Relationship Rules ===
    if relationships:
        rels = relationships.get("relationships", {})
        deception_score = relationships.get("deception_score", 0)

        if deception_score >= 0.5:
            signals.append(Signal(
                signal_id="REL-S001",
                category="relationship",
                severity=min(1.0, deception_score),
                risk_contribution=round(deception_score * 10, 1),
                source="rule",
                explanation="Multiple inconsistencies detected across email components.",
                evidence={"deception_score": deception_score, "relationships": rels},
            ))

    return signals


# ---------------------------------------------------------------------------
# YAML rule loading and evaluation
# ---------------------------------------------------------------------------

def _load_yaml_rules() -> list[dict[str, Any]]:
    """Load rules from YAML files in the rules/ directory."""
    rules: list[dict[str, Any]] = []
    if not os.path.isdir(RULES_DIR):
        return rules

    for filename in sorted(os.listdir(RULES_DIR)):
        if not filename.endswith((".yml", ".yaml")):
            continue
        filepath = os.path.join(RULES_DIR, filename)
        try:
            with open(filepath) as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict) and "rules" in data:
                rules.extend(data["rules"])
            elif isinstance(data, list):
                rules.extend(data)
        except Exception:
            continue
    return rules


def _evaluate_yaml_rules(
    rules: list[dict[str, Any]],
    header_data: dict[str, Any],
    url_features: list[dict[str, Any]],
    content: dict[str, Any],
    attachment_features: list[dict[str, Any]],
    sender_features: dict[str, Any] | None,
    domain_features: dict[str, Any] | None,
    html_features: dict[str, Any] | None,
    relationships: dict[str, Any] | None,
) -> list[Signal]:
    """Evaluate YAML-defined rules against features."""
    signals: list[Signal] = []

    # Build a flat feature context for rule evaluation
    ctx = {
        "header": header_data,
        "sender": header_data.get("sender", {}),
        "authentication": header_data.get("authentication", {}),
        "headers": header_data.get("headers", {}),
        "urls": url_features,
        "content": content,
        "attachments": attachment_features,
        "html": html_features or {},
        "sender_features": sender_features or {},
        "domain": domain_features or {},
        "relationships": relationships or {},
    }

    for rule in rules:
        try:
            signal = _evaluate_single_yaml_rule(rule, ctx)
            if signal:
                signals.append(signal)
        except Exception:
            continue
    return signals


def _evaluate_single_yaml_rule(rule: dict[str, Any], ctx: dict[str, Any]) -> Signal | None:
    """Evaluate a single YAML rule against the feature context."""
    rule_id = rule.get("id", "YAML-???")
    condition = rule.get("condition", "")
    if not condition:
        return None

    # Simple condition evaluation using safe eval
    # Supported: field comparisons, "any", "all", "exists"
    try:
        result = _eval_condition(condition, ctx)
    except Exception:
        return None

    if not result:
        return None

    return Signal(
        signal_id=rule_id,
        category=rule.get("category", "rule"),
        severity=float(rule.get("severity", 0.5)),
        risk_contribution=float(rule.get("risk_contribution", 5.0)),
        source="rule",
        explanation=rule.get("explanation", f"Rule {rule_id} triggered."),
        evidence={"condition": condition},
    )


def _eval_condition(condition: str, ctx: dict[str, Any]) -> bool:
    """Safely evaluate a rule condition string.

    Supported syntax:
      - "authentication.dmarc_fail"           (truthy check)
      - "headers.reply_to_mismatch"           (truthy check)
      - "content.credential_request_score >= 0.75"
      - "urls[*].features.is_ip_address"      (any-match)
    """
    condition = condition.strip()

    # Handle "any URLs have is_ip_address"
    any_match = re.match(r"(\w+)\[\*\]\.(\S+)\s*==\s*(.+)", condition)
    if any_match:
        collection_key, field_path, expected = any_match.groups()
        collection = ctx.get(collection_key, [])
        if not isinstance(collection, list):
            return False
        expected_val = _parse_value(expected)
        for item in collection:
            val = _resolve_field(item, field_path)
            if val == expected_val:
                return True
        return False

    # Handle "any URLs have is_ip_address" (truthy)
    any_truthy = re.match(r"(\w+)\[\*\]\.(\S+)", condition)
    if any_truthy and ">=" not in condition:
        collection_key, field_path = any_truthy.groups()
        collection = ctx.get(collection_key, [])
        if not isinstance(collection, list):
            return False
        return any(_resolve_field(item, field_path) for item in collection)

    # Handle comparison operators
    comp_match = re.match(r"(\S+)\s*(>=|<=|==|!=|>|<)\s*(.+)", condition)
    if comp_match:
        field_path, op, expected_str = comp_match.groups()
        val = _resolve_field(ctx, field_path)
        expected_val = _parse_value(expected_str)
        if op == ">=":
            return float(val or 0) >= float(expected_val)
        elif op == "<=":
            return float(val or 0) <= float(expected_val)
        elif op == "==":
            return val == expected_val
        elif op == "!=":
            return val != expected_val
        elif op == ">":
            return float(val or 0) > float(expected_val)
        elif op == "<":
            return float(val or 0) < float(expected_val)

    # Simple truthy check
    val = _resolve_field(ctx, condition)
    return bool(val)


def _resolve_field(obj: Any, path: str) -> Any:
    """Resolve a dotted field path like 'authentication.dmarc_fail'."""
    parts = path.split(".")
    current = obj
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


def _parse_value(s: str) -> Any:
    """Parse a value string into its Python type."""
    s = s.strip().strip("'\"")
    if s.lower() == "true":
        return True
    if s.lower() == "false":
        return False
    try:
        return float(s)
    except ValueError:
        return s
