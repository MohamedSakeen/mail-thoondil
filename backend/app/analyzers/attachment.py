"""
Attachment analyzer: performs static analysis of email attachments.

Design principle: Attachments are NEVER executed. Only metadata and
file structure are examined.

Features extracted per attachment:
- Filename analysis: double extension, suspicious names, encoding
- Extension analysis: executable, macro-document, archive, HTML
- Size analysis
- Hash (SHA-256) for threat intelligence lookup
- Content-type analysis
"""

from __future__ import annotations

import hashlib
import re
from email.message import EmailMessage
from typing import Any

from app.core.config import MAX_SINGLE_ATTACHMENT_BYTES
from app.core.security import sanitize_filename

# Dangerous extensions that indicate executables or scripts
EXECUTABLE_EXTENSIONS = frozenset({
    "exe", "scr", "bat", "cmd", "com", "pif", "msi", "msp",
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "psm1",
    "reg", "rgs", "inf", "hta", "cpl", "lnk",
})

# Macro-capable document extensions
MACRO_EXTENSIONS = frozenset({
    "docm", "xlsm", "pptm", "dotm", "xltm", "sltm",
})

# Archive extensions
ARCHIVE_EXTENSIONS = frozenset({
    "zip", "rar", "7z", "tar", "gz", "bz2", "xz", "cab",
})

# HTML-related extensions (can embed phishing content)
HTML_EXTENSIONS = frozenset({"html", "htm", "xhtml", "svg"})

# Encoded / obfuscated filenames
DOUBLE_EXTENSION_RE = re.compile(r"\.\w+\.\w+$")


def analyze(msg: EmailMessage) -> list[dict[str, Any]]:
    """Analyze all attachments in the email message."""
    results: list[dict[str, Any]] = []
    index = 0

    for part in msg.walk():
        filename = part.get_filename()
        if not filename:
            continue

        index += 1
        sanitized = sanitize_filename(filename)
        payload = part.get_payload(decode=True) or b""
        content_type = part.get_content_type() or ""
        size_bytes = len(payload)

        # SHA-256 hash for threat intel lookup
        sha256 = hashlib.sha256(payload).hexdigest() if payload else ""

        features = _extract_features(sanitized, content_type, payload, size_bytes)

        results.append({
            "id": f"att-{index}",
            "filename": filename,
            "sanitized_filename": sanitized,
            "mime_type": content_type,
            "size_bytes": size_bytes,
            "hashes": {"sha256": sha256},
            "features": features,
        })

    return results


def _extract_features(
    filename: str,
    content_type: str,
    payload: bytes,
    size_bytes: int,
) -> dict[str, Any]:
    """Extract security features from a single attachment."""
    lower = filename.lower()
    parts = lower.split(".")
    extension = parts[-1] if len(parts) > 1 else ""

    # Double extension (e.g., document.pdf.exe)
    has_double_extension = bool(DOUBLE_EXTENSION_RE.search(lower))

    # Number of dots in filename
    dot_count = lower.count(".")

    # Executable check
    is_executable = extension in EXECUTABLE_EXTENSIONS

    # Macro document check
    is_macro_document = extension in MACRO_EXTENSIONS

    # Archive check
    is_archive = extension in ARCHIVE_EXTENSIONS

    # HTML attachment check
    is_html = extension in HTML_EXTENSIONS

    # Size check
    is_oversized = size_bytes > MAX_SINGLE_ATTACHMENT_BYTES

    # Filename-based heuristics
    # Spaces or special chars in extension (obfuscation)
    has_obfuscated_ext = bool(re.search(r"\.\s+\w+$", lower))

    # CLSID / double extension patterns
    has_clsid = "{0000" in filename or "{CLSID" in filename

    # Password-protected archive indicator (common names)
    password_archive_indicators = ["password", "protected", "encrypted"]
    may_be_password_protected = any(
        indicator in lower for indicator in password_archive_indicators
    )

    # Empty payload
    is_empty = size_bytes == 0

    return {
        "extension": f".{extension}" if extension else "",
        "dot_count": dot_count,
        "double_extension": has_double_extension,
        "executable": is_executable,
        "macro_document": is_macro_document,
        "archive": is_archive,
        "html_attachment": is_html,
        "nested_archive": False,  # Would require payload inspection
        "oversized": is_oversized,
        "obfuscated_extension": has_obfuscated_ext,
        "has_clsid": has_clsid,
        "may_be_password_protected": may_be_password_protected,
        "is_empty": is_empty,
        # Aggregate risk flags
        "dangerous_type": is_executable or is_macro_document or is_html,
        "suspicious_type": is_archive or has_double_extension or has_obfuscated_ext,
    }
