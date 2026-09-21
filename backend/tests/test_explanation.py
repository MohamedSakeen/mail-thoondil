"""Tests for the explanation engine."""

from app.services.explanation import generate_explanation
from app.schemas.analysis import Signal


class TestExplanationEngine:
    def test_benign_explanation(self):
        result = generate_explanation(
            signals=[],
            risk_score=5.0,
            classification="benign",
            sender_info={"from_domain": "example.com"},
            header_data={"sender": {"from_domain": "example.com"}, "authentication": {}, "headers": {}},
            url_features=[],
            content={"word_count": 50},
        )
        assert result["risk_label"] == "LOW RISK"
        assert result["classification"] == "benign"
        assert result["recommended_action"] != ""
        assert result["narrative"] != ""

    def test_phishing_explanation(self):
        signals = [
            Signal(signal_id="AUTH-S001", category="authentication", severity=0.7,
                   risk_contribution=10, source="rule", explanation="DMARC failed"),
            Signal(signal_id="SND-S001", category="sender", severity=0.8,
                   risk_contribution=12, source="rule", explanation="Reply-To mismatch"),
            Signal(signal_id="NLP-S001", category="content", severity=0.85,
                   risk_contribution=12, source="rule", explanation="Credential request"),
        ]
        result = generate_explanation(
            signals=signals,
            risk_score=85.0,
            classification="phishing",
            sender_info={"from_domain": "evil.com"},
            header_data={
                "sender": {"from_domain": "evil.com", "display_name": "Microsoft", "reply_to_domain": "attacker.com"},
                "authentication": {"spf": "fail", "dkim": "pass", "dmarc": "fail", "spf_fail": True, "dkim_fail": False, "dmarc_fail": True},
                "headers": {"reply_to_mismatch": True},
            },
            url_features=[{"id": "url-1", "raw_url": "http://1.2.3.4", "normalized": {"domain": "1.2.3.4"}, "features": {"is_ip_address": True}}],
            content={"credential_request_score": 0.9, "urgency_score": 0.7, "threat_score": 0.5},
        )
        assert result["risk_label"] == "CRITICAL — LIKELY PHISHING"
        assert result["classification"] == "phishing"
        assert len(result["primary_indicators"]) == 3
        assert "evil.com" in result["narrative"]

    def test_signals_by_category(self):
        signals = [
            Signal(signal_id="AUTH-S001", category="authentication", severity=0.7,
                   risk_contribution=10, source="rule", explanation="DMARC failed"),
            Signal(signal_id="URL-S001", category="url", severity=0.9,
                   risk_contribution=15, source="rule", explanation="IP address URL"),
        ]
        result = generate_explanation(
            signals=signals,
            risk_score=60.0,
            classification="suspicious",
            sender_info={},
            header_data={"sender": {}, "authentication": {}, "headers": {}},
            url_features=[],
            content={},
        )
        assert "authentication" in result["signals_by_category"]
        assert "url" in result["signals_by_category"]

    def test_narrative_includes_auth_issues(self):
        signals = [
            Signal(signal_id="AUTH-S001", category="authentication", severity=0.7,
                   risk_contribution=10, source="rule", explanation="DMARC failed"),
        ]
        result = generate_explanation(
            signals=signals,
            risk_score=50.0,
            classification="high_suspicious",
            sender_info={},
            header_data={
                "sender": {"from_domain": "bank.com"},
                "authentication": {"spf_fail": True, "dkim_fail": False, "dmarc_fail": True},
                "headers": {},
            },
            url_features=[],
            content={},
        )
        assert "SPF" in result["narrative"] or "DMARC" in result["narrative"]

    def test_narrative_includes_reply_to_mismatch(self):
        signals = [
            Signal(signal_id="SND-S001", category="sender", severity=0.8,
                   risk_contribution=12, source="rule", explanation="Reply-To mismatch"),
        ]
        result = generate_explanation(
            signals=signals,
            risk_score=55.0,
            classification="high_suspicious",
            sender_info={},
            header_data={
                "sender": {"from_domain": "bank.com", "reply_to_domain": "evil.com"},
                "authentication": {"spf_fail": False, "dkim_fail": False, "dmarc_fail": False},
                "headers": {"reply_to_mismatch": True},
            },
            url_features=[],
            content={},
        )
        assert "Reply-To" in result["narrative"]

    def test_total_signals_counted(self):
        signals = [
            Signal(signal_id=f"S{i}", category="test", severity=0.5,
                   risk_contribution=5, source="rule", explanation=f"signal {i}")
            for i in range(5)
        ]
        result = generate_explanation(
            signals=signals, risk_score=30, classification="suspicious",
            sender_info={}, header_data={"sender": {}, "authentication": {}, "headers": {}},
            url_features=[], content={},
        )
        assert result["total_signals"] == 5
        assert result["categories_triggered"] == 1
