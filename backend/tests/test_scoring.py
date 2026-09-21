"""Tests for risk scoring and signal fusion."""

from app.schemas.analysis import Signal
from app.services.scoring import compute_risk_score
from app.services.fusion import fuse_signals


class TestRiskScoring:
    def test_benign_score(self):
        score = compute_risk_score([])
        assert score["score"] == 0.0
        assert score["classification"] == "benign"

    def test_phishing_score(self):
        signals = [
            Signal(signal_id="T1", category="auth", severity=0.9,
                   risk_contribution=20, source="rule", explanation="test"),
            Signal(signal_id="T2", category="url", severity=0.9,
                   risk_contribution=20, source="rule", explanation="test"),
            Signal(signal_id="T3", category="content", severity=0.9,
                   risk_contribution=20, source="rule", explanation="test"),
            Signal(signal_id="T4", category="sender", severity=0.9,
                   risk_contribution=20, source="rule", explanation="test"),
        ]
        score = compute_risk_score(signals)
        assert score["classification"] == "phishing"
        assert score["score"] >= 75

    def test_suspicious_score(self):
        signals = [
            Signal(signal_id="T1", category="auth", severity=0.7,
                   risk_contribution=15, source="rule", explanation="test"),
        ]
        score = compute_risk_score(signals)
        assert score["classification"] in ("suspicious", "benign")

    def test_ml_contribution(self):
        signals = [
            Signal(signal_id="T1", category="auth", severity=0.7,
                   risk_contribution=15, source="rule", explanation="test"),
        ]
        score_with_ml = compute_risk_score(signals, ml_probability=0.9)
        score_without = compute_risk_score(signals, ml_probability=0.0)
        assert score_with_ml["score"] > score_without["score"]

    def test_score_clamped_to_100(self):
        signals = [
            Signal(signal_id=f"T{i}", category="url", severity=1.0,
                   risk_contribution=30, source="rule", explanation="test")
            for i in range(10)
        ]
        score = compute_risk_score(signals)
        assert score["score"] <= 100.0

    def test_confidence_increases_with_signals(self):
        few = compute_risk_score([
            Signal(signal_id="T1", category="auth", severity=0.5,
                   risk_contribution=5, source="rule", explanation="test"),
        ])
        many = compute_risk_score([
            Signal(signal_id=f"T{i}", category=cat, severity=0.8,
                   risk_contribution=10, source="rule", explanation="test")
            for i, cat in enumerate(["auth", "url", "content", "sender", "html"])
        ])
        assert many["confidence"] >= few["confidence"]

    def test_deception_score_boost(self):
        signals = [
            Signal(signal_id="T1", category="auth", severity=0.7,
                   risk_contribution=20, source="rule", explanation="test"),
        ]
        high_deception = compute_risk_score(signals, deception_score=0.8)
        low_deception = compute_risk_score(signals, deception_score=0.1)
        assert high_deception["score"] > low_deception["score"]

    def test_breakdown_present(self):
        score = compute_risk_score([
            Signal(signal_id="T1", category="auth", severity=0.7,
                   risk_contribution=15, source="rule", explanation="test"),
        ], ml_probability=0.5)
        assert "breakdown" in score
        assert "rule_contribution" in score["breakdown"]
        assert "ml_contribution" in score["breakdown"]


class TestSignalFusion:
    def test_deduplication(self):
        s1 = Signal(signal_id="AUTH-S001", category="auth", severity=0.7,
                     risk_contribution=10, source="rule", explanation="v1")
        s2 = Signal(signal_id="AUTH-S001", category="auth", severity=0.8,
                     risk_contribution=15, source="ml", explanation="v2")
        fused = fuse_signals([s1, s2])
        assert len(fused) == 1
        assert fused[0].risk_contribution == 15  # Higher one kept

    def test_category_cap(self):
        signals = [
            Signal(signal_id=f"URL-{i}", category="url", severity=0.8,
                   risk_contribution=10, source="rule", explanation=f"test {i}")
            for i in range(5)
        ]
        fused = fuse_signals(signals)
        total = sum(s.risk_contribution for s in fused)
        assert total <= 30  # URL category cap is 30

    def test_empty_signals(self):
        fused = fuse_signals([])
        assert fused == []

    def test_ml_signal_included(self):
        rule_sig = Signal(signal_id="AUTH-S001", category="auth", severity=0.7,
                          risk_contribution=10, source="rule", explanation="test")
        ml_sig = Signal(signal_id="ML-S001", category="ml", severity=0.8,
                        risk_contribution=15, source="ml", explanation="ML prediction")
        fused = fuse_signals([rule_sig], ml_signal=ml_sig)
        assert len(fused) == 2
        categories = {s.category for s in fused}
        assert "ml" in categories
