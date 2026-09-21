"""
HTML analyzer: statically analyzes HTML content for phishing indicators.

Features extracted:
- Presence and size
- Form, iframe, script, and hidden-element counts
- External resource references
- Link text vs href mismatch detection
- Obfuscation indicators
"""

from __future__ import annotations

import re
from typing import Any

from app.core.config import MAX_HTML_SIZE


def analyze(html: str) -> dict[str, Any]:
    """Analyze HTML content and return security-relevant features."""
    if not html:
        return _empty_features()

    html = html[:MAX_HTML_SIZE]  # Enforce size limit

    # Basic structure
    tag_count = len(re.findall(r"<\s*[a-zA-Z][^>]*>", html))
    form_count = len(re.findall(r"<\s*form\b", html, re.I))
    iframe_count = len(re.findall(r"<\s*iframe\b", html, re.I))
    script_count = len(re.findall(r"<\s*script\b", html, re.I))

    # Hidden elements (CSS-based hiding)
    hidden_css_count = len(
        re.findall(r"display\s*:\s*none|visibility\s*:\s*hidden", html, re.I)
    )
    hidden_attr_count = len(re.findall(r"\bhidden\b", html, re.I))
    hidden_element_count = hidden_css_count + hidden_attr_count

    # External resource loading
    external_src_count = len(
        re.findall(r"(?:src|href)\s*=\s*[\"']https?://", html, re.I)
    )

    # Link mismatch detection: <a href="...">visible text</a>
    visible_actual_mismatch_count = _count_link_mismatches(html)

    # Form action analysis
    forms_with_action = re.findall(
        r"<\s*form\b[^>]*action\s*=\s*[\"']([^\"']*)[\"']",
        html,
        re.I,
    )
    external_form_actions = sum(
        1 for action in forms_with_action if action.startswith("http")
    )

    # Base64 encoded content in src attributes (data URIs)
    data_uri_count = len(
        re.findall(r"src\s*=\s*[\"']data:", html, re.I)
    )

    # JavaScript event handlers (potential obfuscation)
    event_handler_count = len(
        re.findall(r"\bon\w+\s*=\s*[\"']", html, re.I)
    )

    # Meta refresh (auto-redirect)
    meta_refresh_count = len(
        re.findall(r'<meta[^>]*http-equiv\s*=\s*["\']refresh["\']', html, re.I)
    )

    # Base tag (can redirect all relative URLs)
    has_base_tag = bool(re.search(r"<\s*base\b", html, re.I))

    # Encoded characters in HTML (potential obfuscation)
    html_entity_count = len(re.findall(r"&#\d+;|&#x[0-9a-fA-F]+;", html))

    return {
        "present": True,
        "html_size": len(html),
        "tag_count": tag_count,
        "form_count": form_count,
        "iframe_count": iframe_count,
        "script_count": script_count,
        "hidden_element_count": hidden_element_count,
        "external_resource_count": external_src_count,
        "visible_actual_mismatch_count": visible_actual_mismatch_count,
        "external_form_action_count": external_form_actions,
        "data_uri_count": data_uri_count,
        "event_handler_count": event_handler_count,
        "meta_refresh_count": meta_refresh_count,
        "has_base_tag": has_base_tag,
        "html_entity_count": html_entity_count,
        # Summary flags
        "has_forms": form_count > 0,
        "has_iframes": iframe_count > 0,
        "has_scripts": script_count > 0,
        "has_hidden_elements": hidden_element_count > 0,
    }


def _count_link_mismatches(html: str) -> int:
    """Count <a> tags where the visible text domain differs from href domain."""
    # Pattern: <a href="...">visible text</a>
    pattern = re.compile(
        r'<a\b[^>]*href\s*=\s*["\']([^"\']*)["\'][^>]*>(.*?)</a>',
        re.I | re.S,
    )
    mismatches = 0
    for href_match in pattern.finditer(html):
        href = href_match.group(1)
        visible_text = re.sub(r"<[^>]+>", "", href_match.group(2)).strip()

        if not href.startswith("http") or not visible_text:
            continue

        try:
            from urllib.parse import urlparse
            href_domain = urlparse(href).hostname or ""
            # Check if visible text looks like a domain
            visible_domain_match = re.search(
                r"(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", visible_text
            )
            if visible_domain_match:
                visible_domain = visible_domain_match.group(1)
                if (
                    href_domain
                    and visible_domain
                    and href_domain.lower() != visible_domain.lower()
                ):
                    mismatches += 1
        except Exception:
            pass

    return mismatches


def _empty_features() -> dict[str, Any]:
    """Return zeroed-out features for empty HTML."""
    return {
        "present": False,
        "html_size": 0,
        "tag_count": 0,
        "form_count": 0,
        "iframe_count": 0,
        "script_count": 0,
        "hidden_element_count": 0,
        "external_resource_count": 0,
        "visible_actual_mismatch_count": 0,
        "external_form_action_count": 0,
        "data_uri_count": 0,
        "event_handler_count": 0,
        "meta_refresh_count": 0,
        "has_base_tag": False,
        "html_entity_count": 0,
        "has_forms": False,
        "has_iframes": False,
        "has_scripts": False,
        "has_hidden_elements": False,
    }
