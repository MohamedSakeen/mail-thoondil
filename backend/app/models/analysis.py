"""
SQLAlchemy ORM models for storing analysis results.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import relationship

from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> uuid.UUID:
    return uuid.uuid4()


class Analysis(Base):
    """Stores the top-level analysis result for one email."""

    __tablename__ = "analyses"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    message_id = Column(String(512), index=True, nullable=True)
    subject = Column(Text, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    # Result
    risk_score = Column(Float, nullable=False, default=0.0)
    confidence = Column(Float, nullable=True)
    classification = Column(String(32), nullable=False, default="benign")

    # Versioning
    schema_version = Column(String(16), nullable=False, default="1.0")
    parser_version = Column(String(32), nullable=False, default="1.0.0")
    rule_version = Column(String(32), nullable=False, default="1.0.0")
    model_version = Column(String(64), nullable=False, default="baseline-v1")

    # Full feature snapshot (JSONB for flexible querying)
    features_json = Column(JSONB, nullable=True, default=dict)

    # Metadata
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    # Relationships
    signals = relationship("SignalModel", back_populates="analysis", cascade="all, delete-orphan")
    feedback = relationship("Feedback", back_populates="analysis", cascade="all, delete-orphan")

    def __repr__(self) -> str:
        return f"<Analysis {self.id} score={self.risk_score} class={self.classification}>"


class SignalModel(Base):
    """Individual detection signal linked to an analysis."""

    __tablename__ = "signals"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    analysis_id = Column(UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    signal_id = Column(String(64), nullable=False)
    category = Column(String(32), nullable=False)
    severity = Column(Float, nullable=False, default=0.0)
    risk_contribution = Column(Float, nullable=False, default=0.0)
    source = Column(String(16), nullable=False)  # rule | ml | relationship
    explanation = Column(Text, nullable=False)
    evidence = Column(JSONB, nullable=True, default=dict)

    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    analysis = relationship("Analysis", back_populates="signals")

    def __repr__(self) -> str:
        return f"<Signal {self.signal_id} cat={self.category} risk={self.risk_contribution}>"


class Feedback(Base):
    """Analyst feedback on an analysis result."""

    __tablename__ = "feedback"

    id = Column(UUID(as_uuid=True), primary_key=True, default=_uuid)
    analysis_id = Column(UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), nullable=False)
    analyst_id = Column(String(128), nullable=True)
    verdict_agreement = Column(String(16), nullable=False)  # agree | disagree | partial
    actual_classification = Column(String(32), nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    analysis = relationship("Analysis", back_populates="feedback")

    def __repr__(self) -> str:
        return f"<Feedback analysis={self.analysis_id} verdict={self.verdict_agreement}>"
