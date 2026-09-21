"""
Pydantic schemas for analysis request/response models.
"""

from __future__ import annotations

from typing import Any, Literal
from pydantic import BaseModel, Field


class Signal(BaseModel):
    """A single detection signal."""
    signal_id: str
    category: str
    severity: float = Field(ge=0, le=1)
    risk_contribution: float = Field(ge=0)
    source: Literal["rule", "ml", "relationship"]
    explanation: str
    evidence: dict[str, Any] = {}


class RiskBreakdown(BaseModel):
    """Breakdown of how the risk score was computed."""
    rule_contribution: float = 0.0
    ml_contribution: float = 0.0
    relationship_contribution: float = 0.0


class RiskResult(BaseModel):
    """Final risk assessment."""
    score: float = Field(ge=0, le=100)
    confidence: float | None = Field(default=None, ge=0, le=1)
    classification: str
    breakdown: RiskBreakdown = RiskBreakdown()


class PrimaryIndicator(BaseModel):
    """A primary indicator in the explanation."""
    category: str
    explanation: str
    severity: float
    risk_contribution: float


class ExplanationResult(BaseModel):
    """Human-readable explanation."""
    risk_label: str
    risk_score: float
    classification: str
    primary_indicators: list[PrimaryIndicator]
    signals_by_category: dict[str, list[dict[str, Any]]]
    narrative: str
    recommended_action: str
    total_signals: int
    categories_triggered: int


class AnalysisResponse(BaseModel):
    """Complete analysis response."""
    schema_version: str
    analysis_id: str
    metadata: dict[str, Any]
    sender: dict[str, Any]
    authentication: dict[str, Any]
    headers: dict[str, Any]
    urls: list[dict[str, Any]]
    content: dict[str, Any]
    html: dict[str, Any]
    attachments: list[dict[str, Any]]
    sender_features: dict[str, Any] | None = None
    domain_features: dict[str, Any] | None = None
    relationships: dict[str, Any]
    signals: list[Signal]
    risk: RiskResult
    verdict: dict[str, Any]
    explanation: ExplanationResult | None = None
    ml_prediction: dict[str, Any] | None = None


class FeedbackRequest(BaseModel):
    """Analyst feedback request."""
    analyst_id: str | None = None
    verdict_agreement: Literal["agree", "disagree", "partial"]
    actual_classification: str | None = None
    notes: str | None = None


class FeedbackResponse(BaseModel):
    """Feedback submission response."""
    feedback_id: str
    status: str


class AnalysisListItem(BaseModel):
    """Summary of an analysis for listing."""
    analysis_id: str
    subject: str | None
    risk_score: float
    classification: str
    created_at: str | None


class HealthResponse(BaseModel):
    """Health check response."""
    status: str
    version: str
    ml_loaded: bool
    rule_version: str
