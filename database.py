"""
app/database.py — Async database connection and session management.

We use SQLAlchemy 2.0 async style throughout.
In Python/JS terms: this is like a connection pool manager.
Every request gets its own session (like a transaction scope),
which is automatically committed or rolled back when done.
"""
from collections.abc import AsyncGenerator

from loguru import logger
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings

settings = get_settings()

# ── Engine ───────────────────────────────────────────────────────────────────
# The engine manages the connection pool.
# pool_size=10: keep 10 connections warm (avoids TCP handshake on each request)
# max_overflow=20: allow 20 more connections under heavy load
# pool_pre_ping=True: test connections before using them (avoids stale conn errors)
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,
    echo=(not settings.is_production),  # Log SQL queries in dev, not prod
)

# ── Session Factory ───────────────────────────────────────────────────────────
# async_sessionmaker creates new sessions from the engine.
# expire_on_commit=False: keep objects usable after commit (important for async)
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ── Base Model ────────────────────────────────────────────────────────────────
class Base(DeclarativeBase):
    """All SQLAlchemy models inherit from this."""
    pass


# ── FastAPI Dependency ────────────────────────────────────────────────────────
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    FastAPI dependency that provides a database session per request.

    Usage in a route:
        @router.get("/balance")
        async def get_balance(db: AsyncSession = Depends(get_db)):
            ...

    The session is automatically closed when the request ends,
    even if an exception was raised (the finally block guarantees this).
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def create_tables() -> None:
    """Create all tables on startup (dev only). Use Alembic in production."""
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables created/verified")


async def close_db() -> None:
    """Close the connection pool on shutdown."""
    await engine.dispose()
    logger.info("Database connections closed")
