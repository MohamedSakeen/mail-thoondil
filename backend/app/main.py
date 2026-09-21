"""
FastAPI application entry point.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.core.config import CORS_ORIGINS

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle."""
    # Startup
    logger.info("Starting Phishing Mail Detector v%s", "0.1.0")

    # Initialize database tables
    try:
        from app.core.database import init_db
        await init_db()
        logger.info("Database initialized successfully")
    except Exception as exc:
        logger.warning("Database initialization failed: %s (continuing without persistence)", exc)

    # Load ML model
    try:
        from app.ml.model import get_predictor
        predictor = get_predictor()
        if predictor.is_loaded:
            logger.info("ML model loaded (version: %s)", predictor.model_version)
        else:
            logger.info("No trained ML model found; using fallback heuristic")
    except Exception as exc:
        logger.warning("ML model loading failed: %s", exc)

    yield

    # Shutdown
    logger.info("Shutting down Phishing Mail Detector")


app = FastAPI(
    title="Phishing Mail Detector",
    description="Enterprise-grade explainable phishing email detection engine",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routes
app.include_router(router, prefix="/api/v1")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
