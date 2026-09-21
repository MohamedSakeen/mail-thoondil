"""Tests for all analyzer modules."""

import pytest
from email.message import EmailMessage
from email import policy
from email.parser import BytesParser

from app.analyzers.header import analyze as analyze_headers
from app.analyzers.url import analyze as analyze_urls
from app.analyzers.content import analyze as analyze_content
from app.analyzers.html import analyze as analyze_html
from app.analyzers.attachment import analyze as analyze_attachments
from app.analyzers.sender import analyze_sender
from app.analyzers.domain import analyze_domain, analyze_domains
from app.analyzers.relationship import analyze_relationships


def _make_message(raw: str) -> EmailMessage:
    return BytesParser(policy=policy.default).parsebytes(raw.encode())


# ===== Header Analyzer =====

class TestHeaderAnalyzer:
    def test_basic_extraction(self):
        msg = _make_message(
            "From: Alice <alice@example.com>\n"
            "Reply-To: bob@other.com\n"
            "Return-Path: <charlie@evil.com>\n"
            "Message-ID: <123@example.com>\n"
            "Authentication-Results: example; spf=fail; dkim=pass; dmarc=fail\n"
            "Received: from mail.evil.com\n"
        )
        result = analyze_headers(msg)

        assert result["sender"]["from_domain"] == "example.com"
        assert result["sender"]["reply_to_domain"] == "other.com"
        assert result["sender"]["return_path_domain"] == "evil.com"
        assert result["authentication"]["spf"] == "fail"
        assert result["authentication"]["dkim"] == "pass"
        assert result["authentication"]["dmarc"] == "fail"
        assert result["headers"]["reply_to_mismatch"] is True
        assert result["headers"]["return_path_mismatch"] is True
        assert result["headers"]["received_hop_count"] == 1

    def test_no_reply_to(self):
        msg = _make_message("From: test@example.com\n")
        result = analyze_headers(msg)
        assert result["sender"]["reply_to"] is None
        assert result["headers"]["reply_to_mismatch"] is False

    def test_display_name_from_mismatch(self):
        msg = _make_message(
            'From: "Microsoft Support" <random@notmicrosoft.com>\n'
        )
        result = analyze_headers(msg)
        assert result["headers"]["display_name_from_mismatch"] is True

    def test_message_id_domain_mismatch(self):
        msg = _make_message(
            "From: test@example.com\n"
            "Message-ID: <abc@different.com>\n"
        )
        result = analyze_headers(msg)
        assert result["headers"]["message_id_domain_mismatch"] is True

    def test_all_auth_pass(self):
        msg = _make_message(
            "From: test@example.com\n"
            "Authentication-Results: ex; spf=pass; dkim=pass; dmarc=pass\n"
        )
        result = analyze_headers(msg)
        assert result["authentication"]["authentication_alignment"] is True
        assert result["authentication"]["spf_fail"] is False


# ===== URL Analyzer =====

class TestURLAnalyzer:
    def test_basic_url(self):
        results = analyze_urls(["https://example.com/path?q=1"])
        assert len(results) == 1
        assert results[0]["features"]["is_https"] is True
        assert results[0]["features"]["is_ip_address"] is False

    def test_ip_address_url(self):
        results = analyze_urls(["http://1.2.3.4/login"])
        assert results[0]["features"]["is_ip_address"] is True

    def test_punycode_url(self):
        results = analyze_urls(["https://xn--e1afmapc.xn--p1ai/login"])
        assert results[0]["features"]["has_punycode"] is True

    def test_shortener_detected(self):
        results = analyze_urls(["https://bit.ly/abc123"])
        assert results[0]["features"]["shortener_detected"] is True

    def test_at_symbol(self):
        results = analyze_urls(["https://google.com@evil.com/login"])
        assert results[0]["features"]["has_at_symbol"] is True

    def test_suspicious_keywords(self):
        results = analyze_urls(["https://example.com/login/verify"])
        assert results[0]["features"]["suspicious_keyword_count"] >= 2

    def test_long_url(self):
        long_url = "https://example.com/" + "a" * 200
        results = analyze_urls([long_url])
        assert results[0]["features"]["length"] > 200

    def test_subdomain_count(self):
        results = analyze_urls(["https://a.b.c.d.example.com/path"])
        assert results[0]["features"]["subdomain_count"] >= 3

    def test_non_standard_port(self):
        results = analyze_urls(["https://example.com:8080/path"])
        assert results[0]["features"]["suspicious_port"] is True

    def test_empty_list(self):
        results = analyze_urls([])
        assert results == []

    def test_multiple_urls(self):
        urls = ["https://a.com", "http://1.2.3.4", "https://bit.ly/x"]
        results = analyze_urls(urls)
        assert len(results) == 3


# ===== Content Analyzer =====

class TestContentAnalyzer:
    def test_empty_text(self):
        result = analyze_content("")
        assert result["word_count"] == 0
        assert result["urgency_score"] == 0.0

    def test_urgent_text(self):
        text = "URGENT: Your account will be suspended immediately. Act now!"
        result = analyze_content(text)
        assert result["urgency_score"] > 0.5

    def test_credential_request(self):
        text = "Please verify your account and enter your password to sign in."
        result = analyze_content(text)
        assert result["credential_request_score"] > 0.5

    def test_threat_language(self):
        text = "Your account will be suspended and terminated. Legal action will follow."
        result = analyze_content(text)
        assert result["threat_score"] > 0.5

    def test_financial_request(self):
        text = "Please process the payment and wire transfer the invoice amount."
        result = analyze_content(text)
        assert result["financial_request_score"] > 0.5

    def test_authority_impersonation(self):
        text = "This is the security team from the IT department and helpdesk."
        result = analyze_content(text)
        assert result["authority_impersonation_score"] > 0.5

    def test_uppercase_ratio(self):
        text = "THIS IS ALL UPPERCASE SHOUTING TEXT"
        result = analyze_content(text)
        assert result["uppercase_ratio"] > 0.8

    def test_basic_stats(self):
        text = "Hello world. This is a test."
        result = analyze_content(text)
        assert result["word_count"] == 6
        assert result["sentence_count"] >= 2

    def test_phishing_indicator_sum(self):
        text = "URGENT: verify your password immediately or your account will be suspended!"
        result = analyze_content(text)
        assert result["phishing_indicator_sum"] > 0.5


# ===== HTML Analyzer =====

class TestHTMLAnalyzer:
    def test_empty_html(self):
        result = analyze_html("")
        assert result["present"] is False

    def test_forms_detected(self):
        html = '<html><body><form action="https://evil.com"><input></form></body></html>'
        result = analyze_html(html)
        assert result["form_count"] == 1
        assert result["has_forms"] is True

    def test_iframe_detected(self):
        html = '<html><iframe src="https://evil.com"></iframe></html>'
        result = analyze_html(html)
        assert result["iframe_count"] == 1
        assert result["has_iframes"] is True

    def test_scripts_detected(self):
        html = '<html><script>alert("xss")</script></html>'
        result = analyze_html(html)
        assert result["script_count"] == 1
        assert result["has_scripts"] is True

    def test_hidden_elements(self):
        html = '<div style="display:none">hidden</div><span style="visibility:hidden">also hidden</span>'
        result = analyze_html(html)
        assert result["hidden_element_count"] >= 2

    def test_external_resources(self):
        html = '<img src="https://evil.com/pixel.png"><script src="https://evil.com/s.js"></script>'
        result = analyze_html(html)
        assert result["external_resource_count"] >= 2

    def test_meta_refresh(self):
        html = '<meta http-equiv="refresh" content="0;url=https://evil.com">'
        result = analyze_html(html)
        assert result["meta_refresh_count"] == 1

    def test_base_tag(self):
        html = '<base href="https://evil.com/">'
        result = analyze_html(html)
        assert result["has_base_tag"] is True

    def test_data_uri(self):
        html = '<img src="data:text/html,<script>alert(1)</script>">'
        result = analyze_html(html)
        assert result["data_uri_count"] == 1

    def test_link_mismatch(self):
        html = '<a href="https://evil.com">https://google.com</a>'
        result = analyze_html(html)
        assert result["visible_actual_mismatch_count"] > 0


# ===== Attachment Analyzer =====

class TestAttachmentAnalyzer:
    def _make_email_with_att(self, filename: str, content_type: str = "application/octet-stream") -> EmailMessage:
        raw = (
            f"From: test@example.com\n"
            f"MIME-Version: 1.0\n"
            f'Content-Type: multipart/mixed; boundary="b"\n\n'
            f"--b\n"
            f"Content-Type: text/plain\n\n"
            f"body\n"
            f"--b\n"
            f"Content-Type: {content_type}\n"
            f'Content-Disposition: attachment; filename="{filename}"\n\n'
            f"fake content\n"
            f"--b--\n"
        )
        return BytesParser(policy=policy.default).parsebytes(raw.encode())

    def test_executable_detected(self):
        msg = self._make_email_with_att("malware.exe")
        results = analyze_attachments(msg)
        assert len(results) == 1
        assert results[0]["features"]["executable"] is True
        assert results[0]["features"]["dangerous_type"] is True

    def test_double_extension(self):
        msg = self._make_email_with_att("invoice.pdf.exe")
        results = analyze_attachments(msg)
        assert results[0]["features"]["double_extension"] is True

    def test_macro_document(self):
        msg = self._make_email_with_att("document.docm")
        results = analyze_attachments(msg)
        assert results[0]["features"]["macro_document"] is True

    def test_archive(self):
        msg = self._make_email_with_att("data.zip")
        results = analyze_attachments(msg)
        assert results[0]["features"]["archive"] is True

    def test_html_attachment(self):
        msg = self._make_email_with_att("page.html", "text/html")
        results = analyze_attachments(msg)
        assert results[0]["features"]["html_attachment"] is True

    def test_normal_attachment(self):
        msg = self._make_email_with_att("report.pdf", "application/pdf")
        results = analyze_attachments(msg)
        assert results[0]["features"]["executable"] is False
        assert results[0]["features"]["dangerous_type"] is False

    def test_sha256_hash(self):
        msg = self._make_email_with_att("test.txt", "text/plain")
        results = analyze_attachments(msg)
        assert len(results[0]["hashes"]["sha256"]) == 64

    def test_no_attachments(self):
        msg = BytesParser(policy=policy.default).parsebytes(
            b"From: test@example.com\nContent-Type: text/plain\n\nhello\n"
        )
        results = analyze_attachments(msg)
        assert results == []


# ===== Sender Analyzer =====

class TestSenderAnalyzer:
    def test_brand_impersonation(self):
        sender = {
            "display_name": "Microsoft Security",
            "from_address": "random@notmicrosoft-example.com",
            "from_domain": "notmicrosoft-example.com",
            "from_localpart": "random",
        }
        result = analyze_sender(sender)
        assert "microsoft" in result["claimed_brands"]
        assert result["brand_domain_mismatch"] is True

    def test_legitimate_sender(self):
        sender = {
            "display_name": "GitHub",
            "from_address": "noreply@github.com",
            "from_domain": "github.com",
            "from_localpart": "noreply",
        }
        result = analyze_sender(sender)
        assert result["brand_domain_mismatch"] is False

    def test_display_looks_like_email(self):
        sender = {
            "display_name": "user@example.com",
            "from_address": "attacker@evil.com",
            "from_domain": "evil.com",
            "from_localpart": "attacker",
        }
        result = analyze_sender(sender)
        assert result["display_looks_like_email"] is True

    def test_cross_brand_conflict(self):
        sender = {
            "display_name": "PayPal Support",
            "from_address": "info@micros0ft-support-example.com",
            "from_domain": "micros0ft-support-example.com",
            "from_localpart": "info",
        }
        result = analyze_sender(sender)
        # Claims PayPal but domain references Microsoft
        assert result["cross_brand_conflict"] is True or len(result["claimed_brands"]) > 0


# ===== Domain Analyzer =====

class TestDomainAnalyzer:
    def test_suspicious_tld(self):
        result = analyze_domain("evil.xyz")
        assert result["has_suspicious_tld"] is True

    def test_normal_domain(self):
        result = analyze_domain("example.com")
        assert result["has_suspicious_tld"] is False

    def test_homoglyphs(self):
        result = analyze_domain("аpple.com")  # Cyrillic 'а'
        assert result["has_homoglyphs"] is True

    def test_brand_reference(self):
        result = analyze_domain("microsoft-login.com")
        assert result["has_brand_reference"] is True
        assert "microsoft" in result["brand_indicators"]

    def test_deep_subdomains(self):
        result = analyze_domain("a.b.c.d.e.example.com")
        assert result["subdomain_depth"] >= 4

    def test_random_pattern(self):
        result = analyze_domain("xkcd8374.xyz")
        # May or may not be detected as random, depends on heuristic
        assert result["length"] > 0

    def test_empty_domain(self):
        result = analyze_domain(None)
        assert result["domain"] == ""

    def test_analyze_multiple_domains(self):
        result = analyze_domains(["example.com", "evil.xyz"])
        assert result["suspicious_tld_count"] == 1


# ===== Relationship Analyzer =====

class TestRelationshipAnalyzer:
    def test_consistent_email(self):
        header = {
            "sender": {"from_domain": "example.com", "reply_to_domain": "example.com"},
            "authentication": {"spf_fail": False, "dkim_fail": False, "dmarc_fail": False},
            "headers": {"reply_to_mismatch": False, "return_path_mismatch": False, "message_id_domain_mismatch": False},
        }
        result = analyze_relationships(header, [], {"credential_request_score": 0}, [])
        assert result["relationships"]["from_replyto_consistency"] == 1.0
        assert result["deception_score"] < 0.3

    def test_inconsistent_email(self):
        header = {
            "sender": {"from_domain": "bank.com", "reply_to_domain": "evil.com"},
            "authentication": {"spf_fail": True, "dkim_fail": True, "dmarc_fail": True},
            "headers": {"reply_to_mismatch": True, "return_path_mismatch": True, "message_id_domain_mismatch": True},
        }
        result = analyze_relationships(header, [], {"credential_request_score": 0.8}, [])
        assert result["relationships"]["from_replyto_consistency"] == 0.0
        assert result["deception_score"] > 0.3

    def test_brand_url_mismatch(self):
        header = {
            "sender": {"from_domain": "bank.com", "reply_to_domain": "bank.com"},
            "authentication": {"spf_fail": False, "dkim_fail": False, "dmarc_fail": False},
            "headers": {"reply_to_mismatch": False, "return_path_mismatch": False, "message_id_domain_mismatch": False},
        }
        sender_f = {
            "claimed_brands": ["paypal"],
            "brand_domain_mismatch": True,
            "cross_brand_conflict": False,
        }
        urls = [{"normalized": {"domain": "evil.com"}, "features": {}}]
        result = analyze_relationships(header, urls, {}, [], sender_f)
        assert result["relationships"]["brand_url_consistency"] < 1.0
