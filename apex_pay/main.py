"""
APEX-Pay — FastAPI Application Entry Point
============================================
Wires together all components:
    • Gateway + Admin routers
    • SlowAPI rate limiter
    • Pydantic Logfire instrumentation
    • Redis audit queue lifecycle
    • Background audit worker task
    • Graceful shutdown (connection pool disposal)

Run:
    uvicorn apex_pay.main:app --reload --port 8000
"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

import logfire
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address

from apex_pay.core.config import settings
from apex_pay.core.database import dispose_engines
from apex_pay.routers import admin, dashboard, gateway, hitl
from apex_pay.services.audit_feed_broker import AuditFeedBroker
from apex_pay.services.audit_queue import AuditQueue
from apex_pay.workers.audit_worker import drain_audit_queue

logger = logging.getLogger("apex_pay")


# =============================================================================
# Logfire — Real-Time Observability (blueprint §Step 3)
# =============================================================================
logfire.configure(
    token=settings.logfire.token or None,
    service_name=settings.logfire.service_name,
    environment=settings.logfire.environment,
    send_to_logfire="if-token-present",  # Console-only when no token
)


# =============================================================================
# Lifespan — startup / shutdown hooks
# =============================================================================
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage Redis connection and background worker lifecycle."""

    # ── Startup ─────────────────────────────────────────────────────────
    audit_queue = AuditQueue()
    try:
        await audit_queue.connect()
        logger.info("Redis audit queue connected.")
    except Exception:
        logger.warning("Redis unavailable — audit logging will degrade gracefully.")

    app.state.audit_queue = audit_queue

    # Launch background audit worker
    worker_task = asyncio.create_task(drain_audit_queue(audit_queue))

    # ── Audit feed broker (LISTEN/NOTIFY → SSE) ──────────────────────────
    # One connection for the whole process, shared across all /audit-logs/stream
    # subscribers. Translating the SQLAlchemy DSN: asyncpg.connect() doesn't
    # accept the `+asyncpg` driver hint.
    audit_feed_dsn = settings.db.readonly_dsn.replace(
        "postgresql+asyncpg://", "postgresql://", 1,
    )
    audit_feed_broker = AuditFeedBroker(dsn=audit_feed_dsn)
    await audit_feed_broker.start()
    app.state.audit_feed_broker = audit_feed_broker

    yield

    # ── Shutdown ────────────────────────────────────────────────────────
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass

    await audit_feed_broker.stop()
    await audit_queue.close()
    await dispose_engines()
    logger.info("APEX-Pay shut down cleanly.")


# =============================================================================
# Application Factory
# =============================================================================
app = FastAPI(
    title=settings.app_name,
    description=(
        "Agentic Transaction Gateway — intercepts AI agent tool-calls "
        "and validates them against a policy-gated execution layer."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

# ── Logfire: instrument FastAPI ─────────────────────────────────────────────
try:
    logfire.instrument_fastapi(app)
except Exception as _logfire_err:
    logger.warning("Logfire FastAPI instrumentation unavailable: %s", _logfire_err)
    logger.warning("Observability will fall back to manual logfire.info() calls.")

# ── CORS (permissive for dev, tighten in production) ────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Rate Limiter (app-level middleware, not per-route decorators) ────────────
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=[settings.rate_limit.default],
)
app.state.limiter = limiter
app.add_middleware(SlowAPIMiddleware)
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ── Routers ─────────────────────────────────────────────────────────────────
app.include_router(gateway.router)
app.include_router(admin.router)
app.include_router(dashboard.router)
app.include_router(hitl.router)


# ── Global Error Handler ────────────────────────────────────────────────────
@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    logfire.error(
        "Unhandled exception: {error}",
        error=str(exc),
        path=request.url.path,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error."},
    )
