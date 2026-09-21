"""
API routes for the Phishing Mail Detector.

Endpoints:
  POST /api/v1/analyze          — Analyze an email (.eml upload)
  GET  /api/v1/analyses        — List recent analyses
  GET  /api/v1/analyses/{id}   — Retrieve a specific analysis
  POST /api/v1/analyses/{id}/feedback — Submit analyst feedback
  GET  /api/v1/stats           — System statistics
"""

from __future__ import annotations

import uuid
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.core.security import validate_email_size
from app.schemas.analysis import (
    AnalysisResponse,
    FeedbackRequest,
    FeedbackResponse,
    HealthResponse,
)
from app.services.pipeline import analyze_email_bytes
from app.services import crud
from app.ml.model import get_predictor
from app.core.config import SCHEMA_VERSION, RULE_VERSION

router = APIRouter()


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze(
    email: UploadFile = File(...),
    db: AsyncSession | None = Depends(get_db),
) -> dict[str, Any]:
    """Analyze an uploaded .eml email file."""
    if not email.filename:
        raise HTTPException(400, "Email filename is required")

    # Read and validate
    data = await email.read()
    try:
        validate_email_size(data)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    # Analyze
    try:
        result = analyze_email_bytes(data)
    except Exception as exc:
        raise HTTPException(500, f"Analysis failed: {exc}") from exc

    # Persist (gracefully skip if no DB)
    if db is not None:
        try:
            await crud.save_analysis(db, result)
        except Exception:
            pass

    return result


@router.get("/analyses")
async def list_analyses(
    limit: int = 50,
    offset: int = 0,
    db: AsyncSession | None = Depends(get_db),
) -> list[dict[str, Any]]:
    """List recent analyses."""
    if db is None:
        return []
    return await crud.list_analyses(db, limit=limit, offset=offset)


@router.get("/analyses/{analysis_id}")
async def get_analysis(
    analysis_id: str,
    db: AsyncSession | None = Depends(get_db),
) -> dict[str, Any]:
    """Retrieve a specific analysis by ID."""
    try:
        aid = uuid.UUID(analysis_id)
    except ValueError:
        raise HTTPException(400, "Invalid analysis ID format")

    if db is None:
        raise HTTPException(503, "Database not available")

    result = await crud.get_analysis(db, aid)
    if not result:
        raise HTTPException(404, "Analysis not found")
    return result


@router.post("/analyses/{analysis_id}/feedback", response_model=FeedbackResponse)
async def submit_feedback(
    analysis_id: str,
    feedback: FeedbackRequest,
    db: AsyncSession | None = Depends(get_db),
) -> dict[str, str]:
    """Submit analyst feedback on an analysis result."""
    if db is None:
        raise HTTPException(503, "Database not available")

    try:
        aid = uuid.UUID(analysis_id)
    except ValueError:
        raise HTTPException(400, "Invalid analysis ID format")

    # Verify analysis exists
    existing = await crud.get_analysis(db, aid)
    if not existing:
        raise HTTPException(404, "Analysis not found")

    fb_id = await crud.save_feedback(
        db, aid, feedback.analyst_id,
        feedback.verdict_agreement,
        feedback.actual_classification,
        feedback.notes,
    )

    return {"feedback_id": str(fb_id), "status": "accepted"}


@router.get("/stats")
async def get_stats() -> dict[str, Any]:
    """Get system statistics."""
    predictor = get_predictor()
    return {
        "schema_version": SCHEMA_VERSION,
        "rule_version": RULE_VERSION,
        "ml_model_version": predictor.model_version,
        "ml_model_loaded": predictor.is_loaded,
    }
