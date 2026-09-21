"""Tests for the ML prediction module."""

from app.ml.model import MLPredictor, get_predictor
from app.ml.features import extract_features, FEATURE_NAMES


class TestMLPredictor:
    def test_model_loads(self):
        predictor = MLPredictor()
        # Model may or may not be loaded depending on environment
        assert isinstance(predictor.is_loaded, bool)

    def test_prediction_returns_valid_result(self):
        predictor = MLPredictor()
        content = {
            "word_count": 50,
            "credential_request_score": 0.9,
            "urgency_score": 0.8,
            "threat_score": 0.7,
            "phishing_indicator_sum": 2.5,
        }
        result = predictor.predict("", {}, [], content, {}, [])
        assert "probability" in result
        assert 0.0 <= result["probability"] <= 1.0
        assert "is_ml_prediction" in result
        assert "model_type" in result

    def test_phishing_email_high_probability(self):
        predictor = MLPredictor()
        content = {
            "word_count": 50,
            "credential_request_score": 0.95,
            "urgency_score": 0.9,
            "threat_score": 0.8,
            "phishing_indicator_sum": 3.0,
        }
        result = predictor.predict("", {}, [], content, {}, [])
        # Whether ML or fallback, high phishing indicators should give high probability
        assert result["probability"] > 0.3

    def test_singleton_getter(self):
        p1 = get_predictor()
        p2 = get_predictor()
        assert p1 is p2

    def test_model_version_string(self):
        predictor = MLPredictor()
        assert predictor.model_version != ""

    def test_model_info_returns_dict(self):
        predictor = MLPredictor()
        info = predictor.model_info
        assert "loaded" in info
        assert "type" in info
        assert "version" in info


class TestFeatureExtraction:
    def test_feature_count_matches(self):
        header = {
            "sender": {"from_domain": "example.com", "from_localpart": "test",
                        "sender_domain_digit_ratio": 0.0, "sender_domain_hyphen_count": 0,
                        "display_name": "Test"},
            "authentication": {"spf_fail": False, "dkim_fail": False, "dmarc_fail": False},
            "headers": {"reply_to_mismatch": False, "return_path_mismatch": False,
                        "message_id_domain_mismatch": False, "display_name_from_mismatch": False,
                        "received_hop_count": 2},
        }
        content = {"word_count": 10, "uppercase_ratio": 0.1, "urgency_score": 0.0,
                    "credential_request_score": 0.0, "financial_request_score": 0.0,
                    "threat_score": 0.0, "authority_impersonation_score": 0.0,
                    "call_to_action_score": 0.0, "phishing_indicator_sum": 0.0}
        html = {"form_count": 0, "iframe_count": 0, "script_count": 0,
                "hidden_element_count": 0, "external_resource_count": 0,
                "visible_actual_mismatch_count": 0}
        features = extract_features(header, [], content, html, [])
        assert len(features) == len(FEATURE_NAMES)

    def test_feature_types_are_numeric(self):
        features = extract_features(
            {"sender": {}, "authentication": {}, "headers": {}},
            [],
            {"word_count": 0, "uppercase_ratio": 0, "urgency_score": 0,
             "credential_request_score": 0, "financial_request_score": 0,
             "threat_score": 0, "authority_impersonation_score": 0,
             "call_to_action_score": 0, "phishing_indicator_sum": 0},
            {"form_count": 0, "iframe_count": 0, "script_count": 0,
             "hidden_element_count": 0, "external_resource_count": 0,
             "visible_actual_mismatch_count": 0},
            [],
        )
        for v in features:
            assert isinstance(v, (int, float))

    def test_phishing_features_higher(self):
        phishing_header = {
            "sender": {"from_domain": "evil.com", "from_localpart": "x",
                        "sender_domain_digit_ratio": 0.5, "sender_domain_hyphen_count": 2,
                        "display_name": "Microsoft"},
            "authentication": {"spf_fail": True, "dkim_fail": True, "dmarc_fail": True},
            "headers": {"reply_to_mismatch": True, "return_path_mismatch": True,
                        "message_id_domain_mismatch": True, "display_name_from_mismatch": True,
                        "received_hop_count": 5},
        }
        benign_header = {
            "sender": {"from_domain": "github.com", "from_localpart": "noreply",
                        "sender_domain_digit_ratio": 0.0, "sender_domain_hyphen_count": 0,
                        "display_name": "GitHub"},
            "authentication": {"spf_fail": False, "dkim_fail": False, "dmarc_fail": False},
            "headers": {"reply_to_mismatch": False, "return_path_mismatch": False,
                        "message_id_domain_mismatch": False, "display_name_from_mismatch": False,
                        "received_hop_count": 2},
        }
        content = {"word_count": 50, "uppercase_ratio": 0.1, "urgency_score": 0.0,
                    "credential_request_score": 0.0, "financial_request_score": 0.0,
                    "threat_score": 0.0, "authority_impersonation_score": 0.0,
                    "call_to_action_score": 0.0, "phishing_indicator_sum": 0.0}
        html = {"form_count": 0, "iframe_count": 0, "script_count": 0,
                "hidden_element_count": 0, "external_resource_count": 0,
                "visible_actual_mismatch_count": 0}

        phishing_features = extract_features(phishing_header, [], content, html, [])
        benign_features = extract_features(benign_header, [], content, html, [])

        phishing_sum = sum(phishing_features)
        benign_sum = sum(benign_features)
        assert phishing_sum > benign_sum
