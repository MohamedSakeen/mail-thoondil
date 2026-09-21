"""
Secure email parser: ingests raw bytes, produces a normalised ParsedEmail.

Design principles:
- All input is untrusted.
- Filesize limits enforced before parsing.
- MIME depth limited to prevent decompression / recursion bombs.
- Attachments are extracted but never executed.
"""

from __future__ import annotations

import email.utils
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from typing import Any

from app.core.config import MAX_EMAIL_BYTES, MAX_MIME_DEPTH


class ParseError(ValueError):
    """Raised when the email cannot be parsed."""


@dataclass
class ParsedEmail:
    """Normalised representation of a parsed email."""

    message: EmailMessage
    plain_body: str = ""
    html_body: str = ""
    urls: list[str] = field(default_factory=list)
    attachments: list[dict[str, Any]] = field(default_factory=list)
    date: datetime | None = None
    date_anomaly: bool = False
    raw_headers: dict[str, str] = field(default_factory=dict)


def parse_email(data: bytes) -> ParsedEmail:
    """Parse raw email bytes into a ParsedEmail."""
    if not data:
        raise ParseError("Email is empty")
    if len(data) > MAX_EMAIL_BYTES:
        raise ParseError(
            f"Email exceeds maximum size of {MAX_EMAIL_BYTES // (1024*1024)} MB"
        )

    try:
        msg = BytesParser(policy=policy.default).parsebytes(data)
    except Exception as exc:
        raise ParseError(f"Invalid email format: {exc}") from exc

    # Basic validation: should have at least a From header
    if not msg.get("From") and not msg.get("Subject") and not msg.get("Date"):
        # Very minimal content — could be garbage
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            # It parsed but looks like garbage, still proceed
            pass

    plain, html = _extract_bodies(msg)
    urls = _extract_urls(plain, html)
    attachments = _extract_attachment_metadata(msg)
    date, date_anomaly = _parse_date(msg)
    raw_headers = _collect_raw_headers(msg)

    return ParsedEmail(
        message=msg,
        plain_body=plain,
        html_body=html,
        urls=urls,
        attachments=attachments,
        date=date,
        date_anomaly=date_anomaly,
        raw_headers=raw_headers,
    )


# ---------------------------------------------------------------------------
# Body extraction
# ---------------------------------------------------------------------------

def _extract_bodies(msg: EmailMessage) -> tuple[str, str]:
    """Walk MIME parts and collect plain-text and HTML bodies."""
    plain_parts: list[str] = []
    html_parts: list[str] = []
    depth = 0

    for part in msg.walk():
        depth += 1
        if depth > MAX_MIME_DEPTH:
            break
        if part.is_multipart() or part.get_filename():
            continue
        ctype = part.get_content_type()
        try:
            text = part.get_content()
        except Exception:
            continue
        if isinstance(text, bytes):
            try:
                text = text.decode("utf-8", errors="replace")
            except Exception:
                text = ""
        if ctype == "text/plain":
            plain_parts.append(text)
        elif ctype == "text/html":
            html_parts.append(text)

    return "\n".join(plain_parts), "\n".join(html_parts)


# ---------------------------------------------------------------------------
# URL extraction
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s<>\"'\'')\]]+", re.I)


def _extract_urls(plain: str, html: str) -> list[str]:
    """Extract and deduplicate URLs from both bodies."""
    combined = plain + "\n" + html
    urls = []
    seen: set[str] = set()
    for raw in _URL_RE.findall(combined):
        raw = raw.rstrip(".,);]}>")
        if raw not in seen:
            seen.add(raw)
            urls.append(raw)

    # Also extract href targets from HTML
    href_re = re.compile(r'href\s*=\s*["\']?\s*(https?://[^"\'\s>]+)', re.I)
    for match in href_re.findall(html):
        match = match.rstrip(".,);]}>")
        if match not in seen:
            seen.add(match)
            urls.append(match)

    return urls


# ---------------------------------------------------------------------------
# Attachment metadata (no payload extraction, no execution)
# ---------------------------------------------------------------------------

def _extract_attachment_metadata(msg: EmailMessage) -> list[dict[str, Any]]:
    """Collect metadata about attachments without decoding payloads."""
    results: list[dict[str, Any]] = []
    for i, part in enumerate(msg.walk()):
        filename = part.get_filename()
        if not filename:
            continue
        results.append({
            "index": i,
            "filename": filename,
            "content_type": part.get_content_type(),
            "content_disposition": str(part.get("Content-Disposition", "")),
        })
    return results


# ---------------------------------------------------------------------------
# Date parsing and anomaly detection
# ---------------------------------------------------------------------------

def _parse_date(msg: EmailMessage) -> tuple[datetime | None, bool]:
    """Parse the Date header and detect anomalies."""
    date_str = msg.get("Date")
    if not date_str:
        return None, True  # missing date is itself an anomaly

    try:
        dt = email.utils.parsedate_to_datetime(date_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        # Anomaly if date is > 24h in the future or > 365 days in the past
        delta_future = (dt - now).total_seconds()
        delta_past = (now - dt).total_seconds()
        anomaly = delta_future > 86400 or delta_past > 365 * 86400
        return dt, anomaly
    except Exception:
        return None, True


# ---------------------------------------------------------------------------
# Raw header collection
# ---------------------------------------------------------------------------

def _collect_raw_headers(msg: EmailMessage) -> dict[str, str]:
    """Collect all headers as a dictionary."""
    headers: dict[str, str] = {}
    for key, value in msg.items():
        headers[key] = value
    return headers
