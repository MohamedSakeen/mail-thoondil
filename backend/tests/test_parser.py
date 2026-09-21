"""Tests for the email parser module."""

import pytest
from app.services.parser import parse_email, ParseError


VALID_EMAIL = b"""\
From: Microsoft Security <security@micros0ft.example>
Reply-To: attacker@evil.example
To: user@example.com
Subject: Urgent account verification
Date: Mon, 15 Sep 2025 10:30:00 +0000
Message-ID: <abc123@micros0ft.example>
Authentication-Results: example; spf=fail; dkim=pass; dmarc=fail
Content-Type: text/plain; charset=utf-8

Your account will be suspended. Verify your password immediately:
https://1.2.3.4/login
"""


class TestParseEmail:
    def test_valid_email_parses(self):
        result = parse_email(VALID_EMAIL)
        assert result.message is not None
        assert result.plain_body.strip() != ""

    def test_empty_email_raises(self):
        with pytest.raises(ParseError, match="empty"):
            parse_email(b"")

    def test_oversized_email_raises(self):
        large = b"From: a@b.com\n" + b"X" * (11 * 1024 * 1024)
        with pytest.raises(ParseError, match="size"):
            parse_email(large)

    def test_garbage_input_handled(self):
        # Python's email parser is lenient; garbage bytes parse but produce minimal content
        result = parse_email(b"not an email at all \x00\x01\x02")
        assert result.message is not None
        # Should have no meaningful headers
        assert not result.raw_headers.get("From")

    def test_from_header_extracted(self):
        result = parse_email(VALID_EMAIL)
        from_header = result.message.get("From", "")
        assert "micros0ft.example" in from_header

    def test_subject_extracted(self):
        result = parse_email(VALID_EMAIL)
        assert result.message.get("Subject") == "Urgent account verification"

    def test_reply_to_extracted(self):
        result = parse_email(VALID_EMAIL)
        assert result.message.get("Reply-To") == "attacker@evil.example"

    def test_urls_extracted_from_body(self):
        result = parse_email(VALID_EMAIL)
        assert len(result.urls) > 0
        assert any("1.2.3.4" in u for u in result.urls)

    def test_date_parsed(self):
        result = parse_email(VALID_EMAIL)
        assert result.date is not None

    def test_html_body_extracted(self):
        html_email = b"""\
From: test@example.com
Content-Type: text/html; charset=utf-8

<html><body><a href="https://evil.com">Click here</a></body></html>
"""
        result = parse_email(html_email)
        assert result.html_body != ""
        assert "evil.com" in result.html_body

    def test_multipart_email(self):
        multipart = b"""\
From: test@example.com
MIME-Version: 1.0
Content-Type: multipart/alternative; boundary="boundary123"

--boundary123
Content-Type: text/plain

Plain text body
--boundary123
Content-Type: text/html

<html><body>HTML body</body></html>
--boundary123--
"""
        result = parse_email(multipart)
        assert "Plain text body" in result.plain_body
        assert "HTML body" in result.html_body

    def test_attachment_metadata_extracted(self):
        email_with_att = b"""\
From: test@example.com
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary456"

--boundary456
Content-Type: text/plain

Body text
--boundary456
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="malware.exe"

FAKE_PAYLOAD
--boundary456--
"""
        result = parse_email(email_with_att)
        assert len(result.attachments) > 0
        assert any(a["filename"] == "malware.exe" for a in result.attachments)

    def test_date_anomaly_detected_for_future_date(self):
        future_email = b"""\
From: test@example.com
Date: 01 Jan 2099 00:00:00 +0000
Content-Type: text/plain; charset=utf-8

Hello
"""
        result = parse_email(future_email)
        assert result.date_anomaly is True

    def test_raw_headers_collected(self):
        result = parse_email(VALID_EMAIL)
        assert "From" in result.raw_headers
        assert "Subject" in result.raw_headers
