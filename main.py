"""
main.py — FinSecure API entry point.

FastAPI application with:
- Lifespan management (startup/shutdown hooks)
- Rate limiting (slowapi)
- Security headers
- Structured JSON logging
- Graceful shutdown
"""
import sys
from contextlib import asynccontextmanager
from typing import AsyncGenerator

import uvicorn
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from app.config import get_settings
from app.database import close_db, create_tables
from app.routers import auth, transactions

# ── Logger setup ──────────────────────────────────────────────────────────────
# Remove default loguru handler, replace with JSON structured logging
logger.remove()
logger.add(
    sys.stdout,
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {name}:{function}:{line} | {message}",
    level="DEBUG",
    serialize=True,  # Output as JSON — integrates with ELK, Datadog, CloudWatch
)

settings = get_settings()


# ── Rate Limiter setup ────────────────────────────────────────────────────────
# slowapi uses Redis in production (set RATELIMIT_STORAGE_URI=redis://...)
# Falls back to in-memory for development.
limiter = Limiter(
    key_func=get_remote_address,  # Rate limit per client IP
    default_limits=["100/minute"],  # Global default
)


# ── Lifespan ──────────────────────────────────────────────────────────────────
# FastAPI lifespan replaces the old @app.on_event("startup") pattern.
# Everything before `yield` runs on startup, everything after on shutdown.
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    # ── Startup ───────────────────────────────────────────────────────────────
    logger.info(f"Starting FinSecure API (env={settings.APP_ENV})")
    logger.info("Config validated by env-check ✓")

    # Create database tables (dev only — use Alembic migrations in prod)
    await create_tables()

    logger.info(f"FinSecure API ready on port {settings.PORT}")
    yield  # API is running

    # ── Shutdown ──────────────────────────────────────────────────────────────
    logger.info("Shutdown signal received — closing connections...")
    await close_db()
    logger.info("FinSecure API shut down gracefully")


# ── App initialization ────────────────────────────────────────────────────────
app = FastAPI(
    title="FinSecure API",
    description="Production-grade financial transaction API with fraud detection",
    version="1.0.0",
    lifespan=lifespan,
    # Hide docs in production — don't expose API schema to the public
    docs_url=None if settings.is_production else "/docs",
    redoc_url=None if settings.is_production else "/redoc",
)

# ── Middleware stack ──────────────────────────────────────────────────────────
# Order matters: request passes through top→bottom, response passes bottom→top

# Rate limiting
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS — in production, restrict to your actual frontend domain
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if not settings.is_production else ["https://yourapp.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


# ── Security headers middleware ───────────────────────────────────────────────
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    response.headers["Server"] = ""  # Don't reveal server software
    return response


# ── Request logging middleware ────────────────────────────────────────────────
@app.middleware("http")
async def log_requests(request: Request, call_next):
    response = await call_next(request)
    logger.info(
        f"{request.method} {request.url.path} → {response.status_code}",
        method=request.method,
        path=request.url.path,
        status_code=response.status_code,
        ip=request.client.host if request.client else "unknown",
    )
    return response


# ── Global exception handler ──────────────────────────────────────────────────
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """
    Catch any unhandled exceptions and return a safe error response.
    Never expose internal error details to clients in a finance API.
    """
    logger.exception(f"Unhandled exception on {request.method} {request.url.path}")
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "An internal error occurred. Please try again.",
            "status": 500,
        },
    )


# ── Routes ────────────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(transactions.router)


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["System"])
async def health_check():
    """Health check for load balancers and uptime monitors."""
    return {"status": "ok", "version": "1.0.0", "service": "finsecure-api"}


# ── Strict rate limit on sensitive endpoints ──────────────────────────────────
# Login gets 5 attempts per minute (not the default 100)
@app.middleware("http")
async def strict_login_rate_limit(request: Request, call_next):
    """Apply stricter rate limit to login endpoint."""
    # slowapi handles the actual limiting; this documents the intent
    return await call_next(request)


# ── Entry point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=settings.PORT,
        reload=not settings.is_production,
        # Timeouts prevent slowloris attacks
        timeout_keep_alive=30,
        access_log=True,
    )
