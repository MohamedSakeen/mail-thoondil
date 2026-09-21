"""
CRUD operations for analysis persistence.
"""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.analysis import Analysis, Feedback, SignalModel


async def save_analysis(db: AsyncSession, result: dict[str, Any]) -> uuid.UUID:
    """Persist a complete analysis result and return its ID."""
    analysis = Analysis(
        id=uuid.UUID(result["analysis_id"]),
        message_id=result.get("metadata", {}).get("message_id"),
        subject=result.get("metadata", {}).get("subject"),
        risk_score=result["risk"]["score"],
        confidence=result["risk"].get("confidence"),
        classification=result["verdict"]["classification"],
        schema_version=result["schema_version"],
        features_json=result,
    )
    db.add(analysis)

    for sig in result.get("signals", []):
        signal = SignalModel(
            analysis_id=analysis.id,
            signal_id=sig["signal_id"],
            category=sig["category"],
            severity=sig["severity"],
            risk_contribution=sig["risk_contribution"],
            source=sig["source"],
            explanation=sig["explanation"],
            evidence=sig.get("evidence", {}),
        )
        db.add(signal)

    await db.flush()
    return analysis.id


async def get_analysis(db: AsyncSession, analysis_id: uuid.UUID) -> dict[str, Any] | None:
    """Retrieve a full analysis result by ID."""
    result = await db.execute(
        select(Analysis).where(Analysis.id == analysis_id)
    )
    analysis = result.scalar_one_or_none()
    if not analysis:
        return None

    # Fetch signals
    sig_result = await db.execute(
        select(SignalModel).where(SignalModel.analysis_id == analysis.id)
    )
    signals = sig_result.scalars().all()

    return {
        "analysis_id": str(analysis.id),
        "schema_version": analysis.schema_version,
        "metadata": {
            "message_id": analysis.message_id,
            "subject": analysis.subject,
            "timestamp": analysis.timestamp.isoformat() if analysis.timestamp else None,
        },
        "risk": {"score": analysis.risk_score, "confidence": analysis.confidence},
        "verdict": {
            "classification": analysis.classification,
            "reasons": [s.explanation for s in signals],
        },
        "signals": [
            {
                "signal_id": s.signal_id,
                "category": s.category,
                "severity": s.severity,
                "risk_contribution": s.risk_contribution,
                "source": s.source,
                "explanation": s.explanation,
                "evidence": s.evidence,
            }
            for s in signals
        ],
        "features_json": analysis.features_json,
        "created_at": analysis.created_at.isoformat() if analysis.created_at else None,
    }


async def list_analyses(
    db: AsyncSession, limit: int = 50, offset: int = 0
) -> list[dict[str, Any]]:
    """List analyses ordered by most recent."""
    result = await db.execute(
        select(Analysis).order_by(Analysis.created_at.desc()).offset(offset).limit(limit)
    )
    analyses = result.scalars().all()
    return [
        {
            "analysis_id": str(a.id),
            "subject": a.subject,
            "risk_score": a.risk_score,
            "classification": a.classification,
            "created_at": a.created_at.isoformat() if a.created_at else None,
        }
        for a in analyses
    ]


async def save_feedback(
    db: AsyncSession,
    analysis_id: uuid.UUID,
    analyst_id: str | None,
    verdict_agreement: str,
    actual_classification: str | None,
    notes: str | None,
) -> uuid.UUID:
    """Save analyst feedback on an analysis."""
    fb = Feedback(
        analysis_id=analysis_id,
        analyst_id=analyst_id,
        verdict_agreement=verdict_agreement,
        actual_classification=actual_classification,
        notes=notes,
    )
    db.add(fb)
    await db.flush()
    return fb.id
