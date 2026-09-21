"""Tests for the rule engine."""

from app.services.rules import evaluate
from app.schemas.analysis import Signal


def _minimal_header():
    return {
        "sender": {
            "display_name": "Test",
            "from_address": "test@example.com",
            "from_domain": "example.com",
            "from_localpart": "test",
            "reply_to": None,
            "reply_to_domain": None,
            "return_path": None,
            "return_path_domain": None,
            "sender_domain_digit_ratio": 0.0,
            "sender_domain_hyphen_count": 0,
        },
        "authentication": {
            "spf": "pass",
            "dkim": "pass",
            "dmarc": "pass",
            "spf_fail": False,
            "dkim_fail": False,
            "dmarc_fail": False,
        },
        "headers": {
            "received_hop_count": 2,
            "header_count": 10,
            "reply_to_mismatch": False,
            "return_path_mismatch": False,
            "message_id_domain": "example.com",
            "message_id_domain_mismatch": False,
            "display_name_from_mismatch": False,
        },
    }


class TestRuleEngine:
    def test_no_signals_for_clean_email(self):
        signals = evaluate(_minimal_header(), [], {"word_count": 10}, [])
        assert len(signals) == 0

    def test_dmarc_fail_signal(self):
        header = _minimal_header()
        header["authentication"]["dmarc_fail"] = True
        signals = evaluate(header, [], {"word_count": 10}, [])
        assert any(s.signal_id == "AUTH-S001" for s in signals)

    def test_spf_fail_signal(self):
        header = _minimal_header()
        header["authentication"]["spf_fail"] = True
        signals = evaluate(header, [], {"word_count": 10}, [])
        assert any(s.signal_id == "AUTH-S002" for s in signals)

    def test_reply_to_mismatch_signal(self):
        header = _minimal_header()
        header["headers"]["reply_to_mismatch"] = True
        signals = evaluate(header, [], {"word_count": 10}, [])
        assert any(s.signal_id == "SND-S001" for s in signals)

    def test_ip_url_signal(self):
        urls = [
            {
                "id": "url-1",
                "raw_url": "http://1.2.3.4/login",
                "normalized": {"domain": "1.2.3.4"},
                "features": {
                    "is_ip_address": True,
                    "has_punycode": False,
                    "shortener_detected": False,
                    "has_at_symbol": False,
                    "suspicious_port": False,
                    "is_https": False,
                    "suspicious_keyword_count": 0,
                    "length": 25,
                    "subdomain_count": 0,
                },
            }
        ]
        signals = evaluate(_minimal_header(), urls, {"word_count": 10}, [])
        assert any(s.signal_id == "URL-S001" for s in signals)

    def test_credential_request_signal(self):
        content = {"credential_request_score": 0.85, "word_count": 10}
        signals = evaluate(_minimal_header(), [], content, [])
        assert any(s.signal_id == "NLP-S001" for s in signals)

    def test_urgency_signal(self):
        content = {"urgency_score": 0.8, "word_count": 10}
        signals = evaluate(_minimal_header(), [], content, [])
        assert any(s.signal_id == "NLP-S002" for s in signals)

    def test_executable_attachment_signal(self):
        attachments = [
            {
                "id": "att-1",
                "filename": "malware.exe",
                "features": {"executable": True, "double_extension": False, "macro_document": False, "html_attachment": False, "archive": False},
            }
        ]
        signals = evaluate(_minimal_header(), [], {"word_count": 10}, attachments)
        assert any(s.signal_id == "ATT-S001" for s in signals)

    def test_form_html_signal(self):
        html = {"form_count": 2}
        signals = evaluate(_minimal_header(), [], {"word_count": 10}, [], html_features=html)
        assert any(s.signal_id == "HTML-S001" for s in signals)

    def test_relationship_signal(self):
        rels = {"deception_score": 0.7, "relationships": {"from_replyto_consistency": 0.0}}
        signals = evaluate(_minimal_header(), [], {"word_count": 10}, [], relationships=rels)
        assert any(s.signal_id == "REL-S001" for s in signals)

    def test_multiple_signals_combined(self):
        header = _minimal_header()
        header["authentication"]["dmarc_fail"] = True
        header["headers"]["reply_to_mismatch"] = True
        content = {"credential_request_score": 0.9, "word_count": 10}
        urls = [
            {
                "id": "url-1",
                "raw_url": "http://1.2.3.4",
                "normalized": {"domain": "1.2.3.4"},
                "features": {
                    "is_ip_address": True, "has_punycode": False,
                    "shortener_detected": False, "has_at_symbol": False,
                    "suspicious_port": False, "is_https": False,
                    "suspicious_keyword_count": 0, "length": 20,
                    "subdomain_count": 0,
                },
            }
        ]
        signals = evaluate(header, urls, content, [])
        assert len(signals) >= 4  # DMARC + reply-to + IP URL + credential

    def test_all_signals_are_valid(self):
        header = _minimal_header()
        header["authentication"]["dmarc_fail"] = True
        signals = evaluate(header, [], {"credential_request_score": 0.8, "word_count": 10}, [])
        for sig in signals:
            assert isinstance(sig, Signal)
            assert 0 <= sig.severity <= 1
            assert sig.risk_contribution >= 0
            assert sig.signal_id != ""
            assert sig.explanation != ""
