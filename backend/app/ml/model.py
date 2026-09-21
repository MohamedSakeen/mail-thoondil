"""
ML-based phishing detection model.

Supports:
- XGBoost with TF-IDF + engineered features (trained model)
- Logistic Regression fallback
- Heuristic fallback when no model is available

Usage:
    predictor = get_predictor()
    result = predictor.predict(text, header_data, url_features, ...)
"""

from __future__ import annotations

import json
import os
import pickle
from typing import Any

import numpy as np

from app.core.config import ML_MODEL_DIR, MODEL_VERSION

# Model file paths — models live at project root /models/
_MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "..", ML_MODEL_DIR)
_TFIDF_PATH = os.path.join(_MODEL_DIR, "tfidf_vectorizer.pkl")
_XGB_PATH = os.path.join(_MODEL_DIR, "xgboost_model.pkl")
_LR_PATH = os.path.join(_MODEL_DIR, "logistic_regression.pkl")
_METADATA_PATH = os.path.join(_MODEL_DIR, "model_metadata.json")


class MLPredictor:
    """Encapsulates the ML prediction pipeline."""

    def __init__(self) -> None:
        self._vectorizer = None
        self._model = None
        self._loaded = False
        self._model_type = None
        self._metadata = {}
        self._load_model()

    def _load_model(self) -> None:
        """Attempt to load a persisted model from disk."""
        try:
            # Try XGBoost first, then Logistic Regression
            for model_path, model_type in [
                (_XGB_PATH, "xgboost"),
                (_LR_PATH, "logistic_regression"),
            ]:
                if os.path.exists(_TFIDF_PATH) and os.path.exists(model_path):
                    with open(_TFIDF_PATH, "rb") as f:
                        self._vectorizer = pickle.load(f)
                    with open(model_path, "rb") as f:
                        self._model = pickle.load(f)
                    self._loaded = True
                    self._model_type = model_type
                    break

            # Load metadata
            if os.path.exists(_METADATA_PATH):
                with open(_METADATA_PATH) as f:
                    self._metadata = json.load(f)
        except Exception:
            self._loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    @property
    def model_version(self) -> str:
        if self._loaded and self._metadata:
            return self._metadata.get("version", MODEL_VERSION)
        return MODEL_VERSION

    @property
    def model_info(self) -> dict[str, Any]:
        """Return model metadata for the stats endpoint."""
        return {
            "loaded": self._loaded,
            "type": self._model_type,
            "version": self.model_version,
            "metadata": self._metadata,
        }

    def predict(
        self,
        text: str,
        header_data: dict[str, Any],
        url_features: list[dict[str, Any]],
        content: dict[str, Any],
        html_features: dict[str, Any],
        attachment_features: list[dict[str, Any]],
        sender_features: dict[str, Any] | None = None,
        domain_features: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Predict phishing probability."""
        if not self._loaded:
            return self._fallback_prediction(content)

        try:
            return self._ml_prediction(
                text, header_data, url_features, content,
                html_features, attachment_features,
                sender_features, domain_features,
            )
        except Exception as exc:
            print(f"ML prediction failed, using fallback: {exc}")
            return self._fallback_prediction(content)

    def _ml_prediction(
        self,
        text: str,
        header_data: dict[str, Any],
        url_features: list[dict[str, Any]],
        content: dict[str, Any],
        html_features: dict[str, Any],
        attachment_features: list[dict[str, Any]],
        sender_features: dict[str, Any] | None,
        domain_features: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Run the full ML pipeline."""
        from scipy.sparse import hstack, csr_matrix

        # Text features via TF-IDF
        text_tfidf = self._vectorizer.transform([text])

        # Engineered features (same as training.py extract_features_from_row)
        eng_features = self._extract_engineered_features(
            text, header_data, url_features, content,
            html_features, attachment_features,
            sender_features, domain_features,
        )
        eng_array = np.array(eng_features).reshape(1, -1)

        # Combine: sparse TF-IDF + dense engineered features
        combined = hstack([text_tfidf, csr_matrix(eng_array)])

        # Predict probability
        proba = self._model.predict_proba(combined)[0]
        # Class 1 = phishing
        phishing_prob = float(proba[1]) if len(proba) > 1 else float(proba[0])

        return {
            "probability": round(phishing_prob, 4),
            "model_version": self.model_version,
            "model_type": self._model_type,
            "is_ml_prediction": True,
        }

    def _extract_engineered_features(
        self,
        text: str,
        header_data: dict[str, Any],
        url_features: list[dict[str, Any]],
        content: dict[str, Any],
        html_features: dict[str, Any],
        attachment_features: list[dict[str, Any]],
        sender_features: dict[str, Any] | None,
        domain_features: dict[str, Any] | None,
    ) -> list[float]:
        """Extract the same 27 engineered features used during training."""
        import re

        sender = header_data.get("sender", {})
        headers = header_data.get("headers", {})

        # Basic text stats
        words = re.findall(r"\b\w+\b", text, re.UNICODE)
        word_count = len(words)
        alpha_chars = sum(c.isalpha() for c in text)
        upper_chars = sum(c.isupper() for c in text)

        # URL features
        url_count = len(url_features)
        url_has_ip = any(u.get("features", {}).get("is_ip_address") for u in url_features)
        url_has_punycode = any(u.get("features", {}).get("has_punycode") for u in url_features)
        url_has_shortener = any(u.get("features", {}).get("shortener_detected") for u in url_features)
        url_has_at = any(u.get("features", {}).get("has_at_symbol") for u in url_features)
        url_has_https = any(u.get("features", {}).get("is_https") for u in url_features)
        url_lengths = [u.get("features", {}).get("length", 0) for u in url_features]
        url_avg_length = float(np.mean(url_lengths)) if url_lengths else 0.0
        url_suspicious_kw = sum(
            u.get("features", {}).get("suspicious_keyword_count", 0) for u in url_features
        )

        # Sender features
        from_domain = sender.get("from_domain", "")
        domain_length = len(from_domain)
        domain_digit_ratio = sender.get("sender_domain_digit_ratio", 0.0)
        domain_hyphen_count = sender.get("sender_domain_hyphen_count", 0)
        local_is_numeric = 1.0 if sender.get("from_localpart", "").isdigit() else 0.0

        # NLP scores (from content analyzer)
        urgency = content.get("urgency_score", 0.0)
        credential = content.get("credential_request_score", 0.0)
        financial = content.get("financial_request_score", 0.0)
        threat = content.get("threat_score", 0.0)
        authority = content.get("authority_impersonation_score", 0.0)
        cta = content.get("call_to_action_score", 0.0)
        phishing_sum = content.get("phishing_indicator_sum", 0.0)

        return [
            float(word_count),
            upper_chars / max(1, alpha_chars),
            sum(c.isdigit() for c in text) / max(1, len(text)),
            float(np.mean([len(w) for w in words])) if words else 0.0,
            float(max(1, len(re.findall(r"[.!?]+", text)))),
            float(url_count),
            float(url_has_ip),
            float(url_has_punycode),
            float(url_has_shortener),
            float(url_has_at),
            float(url_has_https),
            url_avg_length,
            float(url_suspicious_kw),
            float(domain_length),
            float(domain_digit_ratio),
            float(domain_hyphen_count),
            float(local_is_numeric),
            float(urgency),
            float(credential),
            float(financial),
            float(threat),
            float(authority),
            float(cta),
            float(phishing_sum),
        ]

    def _fallback_prediction(self, content: dict[str, Any]) -> dict[str, Any]:
        """Heuristic fallback when no trained model is available."""
        indicator_sum = content.get("phishing_indicator_sum", 0.0)
        urgency = content.get("urgency_score", 0.0)
        credential = content.get("credential_request_score", 0.0)
        threat = content.get("threat_score", 0.0)

        probability = (
            credential * 0.35
            + urgency * 0.20
            + threat * 0.20
            + min(1.0, indicator_sum / 3.0) * 0.25
        )

        return {
            "probability": round(min(1.0, max(0.0, probability)), 4),
            "model_version": f"{MODEL_VERSION}-fallback",
            "model_type": "heuristic",
            "is_ml_prediction": False,
        }


# Singleton
_predictor: MLPredictor | None = None


def get_predictor() -> MLPredictor:
    """Get or create the singleton MLPredictor."""
    global _predictor
    if _predictor is None:
        _predictor = MLPredictor()
    return _predictor
