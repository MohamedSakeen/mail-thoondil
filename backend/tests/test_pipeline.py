"""Integration tests for the complete analysis pipeline."""

import pytest
from app.services.pipeline import analyze_email_bytes


PHISHING_EMAIL = b"""\
From: Microsoft Security <security@micros0ft.example>
Reply-To: attacker@evil.example
To: user@example.com
Subject: Urgent: Your account has been compromised
Authentication-Results: example; spf=fail; dkim=pass; dmarc=fail
Content-Type: text/plain; charset=utf-8

URGENT: Your Microsoft account will be suspended immediately!
Verify your password within 24 hours or your account will be terminated.
Click here to verify: https://1.2.3.4/microsoft-login
"""

BENIGN_EMAIL = b"""\
From: noreply@github.com
To: user@example.com
Subject: [GitHub] A new sign-in to your account
Date: Mon, 15 Sep 2025 10:30:00 +0000
Message-ID: <abc123@github.com>
Authentication-Results: github.com; spf=pass; dkim=pass; dmarc=pass
Content-Type: text/plain; charset=utf-8

A new sign-in to your GitHub account was detected.
If this was you, no action is required.
"""

SUSPICIOUS_EMAIL = b"""\
From: IT Department <admin@company-mail.net>
Reply-To: support@company-mail.net
To: user@company.com
Subject: Please update your security settings
Authentication-Results: company.com; spf=softfail; dkim=pass; dmarc=none
Content-Type: text/plain; charset=utf-8

Hello,
Please review the attached document regarding your security settings.
Best regards,
IT Department
"""


class TestPipelineIntegration:
    def test_phishing_email_detected(self):
        result = analyze_email_bytes(PHISHING_EMAIL)
        assert result["schema_version"] == "1.0"
        assert result["analysis_id"] != ""
        assert result["risk"]["classification"] in ("suspicious", "high_suspicious", "phishing")
        assert result["risk"]["score"] >= 25
        assert len(result["signals"]) > 0

    def test_phishing_email_has_expected_signals(self):
        result = analyze_email_bytes(PHISHING_EMAIL)
        signal_ids = [s["signal_id"] for s in result["signals"]]
        # Should have auth, sender, URL, and content signals
        assert any("AUTH" in sid for sid in signal_ids)
        assert any("SND" in sid for sid in signal_ids)
        assert any("URL" in sid for sid in signal_ids)

    def test_phishing_email_explanation(self):
        result = analyze_email_bytes(PHISHING_EMAIL)
        assert result["explanation"] is not None
        assert result["explanation"]["narrative"] != ""
        assert result["explanation"]["recommended_action"] != ""

    def test_phishing_email_ml_prediction(self):
        result = analyze_email_bytes(PHISHING_EMAIL)
        assert result["ml_prediction"] is not None
        assert 0.0 <= result["ml_prediction"]["probability"] <= 1.0

    def test_benign_email_low_score(self):
        result = analyze_email_bytes(BENIGN_EMAIL)
        assert result["risk"]["classification"] == "benign"
        assert result["risk"]["score"] < 25

    def test_benign_email_few_signals(self):
        result = analyze_email_bytes(BENIGN_EMAIL)
        assert len(result["signals"]) <= 2  # At most non-specific signals

    def test_suspicious_email(self):
        result = analyze_email_bytes(SUSPICIOUS_EMAIL)
        assert result["risk"]["score"] >= 0
        assert result["risk"]["classification"] in ("benign", "suspicious", "high_suspicious")

    def test_empty_email_rejected(self):
        with pytest.raises(ValueError, match="empty"):
            analyze_email_bytes(b"")

    def test_metadata_populated(self):
        result = analyze_email_bytes(PHISHING_EMAIL)
        assert result["metadata"]["subject"] == "Urgent: Your account has been compromised"
        assert result["metadata"]["from"] is not None

    def test_sender_features_present(self):
        result = analyze_email_bytes(PHISHING_EMAIL)
        assert result["sender_features"] is not None
        assert "claimed_brands" in result["sender_features"]

    def test_domain_features_present(self):
        result = analyze_email_bytes(PHISHING_EMAIL)
        assert result["domain_features"] is not None

    def test_relationships_present(self):
        result = analyze_email_bytes(PHISHING_EMAIL)
        assert "relationships" in result
        assert "deception_score" in result["relationships"]

    def test_verdict_has_reasons(self):
        result = analyze_email_bytes(PHISHING_EMAIL)
        assert len(result["verdict"]["reasons"]) > 0

    def test_authentication_extracted(self):
        result = analyze_email_bytes(PHISHING_EMAIL)
        assert result["authentication"]["spf"] == "fail"
        assert result["authentication"]["dmarc"] == "fail"

    def test_urls_extracted(self):
        result = analyze_email_bytes(PHISHING_EMAIL)
        assert len(result["urls"]) > 0
        assert any(u["features"]["is_ip_address"] for u in result["urls"])

    def test_result_is_json_serializable(self):
        import json
        result = analyze_email_bytes(PHISHING_EMAIL)
        # Should not raise
        json.dumps(result)
