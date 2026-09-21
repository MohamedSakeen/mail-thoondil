"""
Database connection — testable via environment override.

When DATABASE_URL is not reachable, the app still functions:
analysis results are returned but not persisted.
"""

from __future__ import annotations

import os

from sqlalchemy.ext.asyncio import (
    AsyncAttrs,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://phishing:phishing@localhost:5432/phishing_detector",
)

# Skip DB if it looks unavailable (e.g. in tests without Postgres)
_SKIP_DB = os.getenv("SKIP_DB", "0") == "1"

if _SKIP_DB:
    engine = None
    async_session = None  # type: ignore[assignment]
else:
    engine = create_async_engine(DATABASE_URL, echo=False, pool_size=10, max_overflow=20)
    async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


class Base(AsyncAttrs, DeclarativeBase):
    """Base class for all ORM models."""
    pass


async def get_db():  # type: ignore[misc]
    """FastAPI dependency that yields a database session.

    If the database is unavailable, yields None and lets callers
    handle the missing session gracefully.
    """
    if async_session is None:
        yield None
        return

    async with async_session() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def init_db() -> None:
    """Create all tables (for development; use Alembic in production)."""
    if engine is None:
        return
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
