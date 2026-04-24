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
from starlette.requests import Request as StarletteRequest

from apex_pay.core.config import settings
from apex_pay.core.database import dispose_engines
from apex_pay.routers import admin, dashboard, gateway, hitl
from apex_pay.services.audit_feed_broker import AuditFeedBroker
from apex_pay.services.audit_queue import AuditQueue
from apex_pay.services.correlation import CorrelationIdMiddleware
from apex_pay.services.policy_cache import default_cache as default_policy_cache
from apex_pay.services.replay_guard import ReplayGuard, set_default_guard
from apex_pay.services.semantic_rate_limiter import (
    SemanticRateLimiter,
    set_default_limiter,
)
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

    # ── Policy cache (in-proc TTL + Redis pub/sub invalidation) ──────────
    # Best-effort — if Redis is unavailable the cache still works at the
    # per-replica level, just without cross-replica invalidation. The TTL
    # is the staleness upper bound in that degraded mode.
    try:
        await default_policy_cache().connect(settings.redis.url)
        logger.info("Policy cache connected.")
    except Exception:
        logger.warning("Policy cache Redis pub/sub unavailable — TTL-only mode.")

    # ── Replay guard (only wire when the feature flag is on) ─────────────
    # Lifespan still creates the object when the feature is off so future
    # runtime toggling wouldn't need a restart, but we only connect Redis
    # when it's needed.
    if settings.security.require_nonce:
        replay_guard = ReplayGuard(ttl_seconds=settings.security.nonce_ttl_seconds)
        try:
            await replay_guard.connect(settings.redis.url)
            set_default_guard(replay_guard)
            logger.info("Replay guard connected (TTL=%ds).", settings.security.nonce_ttl_seconds)
        except Exception:
            logger.error(
                "Replay guard Redis unavailable — requests will be rejected (fail-closed).",
            )
            set_default_guard(replay_guard)  # still set so 503s are explicit
    else:
        set_default_guard(None)

    # ── Semantic rate limiter (dollar spend / hour) ──────────────────────
    if settings.rate_limit.semantic_enabled:
        limiter = SemanticRateLimiter(
            redis_url=settings.redis.url,
            window_seconds=settings.rate_limit.semantic_window_seconds,
            default_limit_cents=settings.rate_limit.semantic_default_limit_cents,
        )
        try:
            await limiter.connect()
            set_default_limiter(limiter)
            logger.info(
                "Semantic rate limiter connected (window=%ds, limit=%d cents)",
                settings.rate_limit.semantic_window_seconds,
                settings.rate_limit.semantic_default_limit_cents,
            )
        except Exception:
            logger.error(
                "Semantic rate limiter could not connect — requests will fail "
                "closed (503) when evaluated by the limiter.",
            )
            set_default_limiter(limiter)
    else:
        set_default_limiter(None)

    # ── Shield pipeline startup (Vault AppRole login, transit probe) ─────
    # Fail-closed: if credential_backend=vault and login fails, we raise
    # so the container crash-loops instead of serving traffic with a dead
    # credential manager. Dev backend's startup() is a no-op.
    from apex_pay.routers.gateway import shield_pipeline as _shield
    if _shield is not None:
        try:
            await _shield.startup()
            logger.info("Shield pipeline startup complete.")
        except Exception:
            logger.exception("Shield pipeline startup failed — aborting boot.")
            raise

    yield

    # ── Shutdown ────────────────────────────────────────────────────────
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass

    await audit_feed_broker.stop()
    await default_policy_cache().close()
    from apex_pay.services.replay_guard import default_guard as _dg
    rg = _dg()
    if rg is not None:
        await rg.close()

    from apex_pay.services.semantic_rate_limiter import default_limiter as _dl
    srl = _dl()
    if srl is not None:
        await srl.close()

    # Shield shutdown: close Vault HTTP client, drop service token.
    from apex_pay.routers.gateway import shield_pipeline as _shield
    if _shield is not None:
        try:
            await _shield.shutdown()
        except Exception:
            logger.warning("Shield pipeline shutdown failed (non-fatal).", exc_info=True)

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

# ── Correlation ID (must come before CORS so the header is set on all responses)
app.add_middleware(CorrelationIdMiddleware)

# ── CORS (permissive for dev, tighten in production) ────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID"],
)

# ── Rate Limiter (app-level middleware, not per-route decorators) ────────────
# Key resolution, strongest → weakest:
#   1. X-APEX-Agent-ID header (authenticated, per-agent bucket) — blueprint §7.1
#   2. mTLS client-cert CN if the edge forwarded it (X-Client-Cert-CN)
#   3. Remote IP — the pre-auth fallback
#
# Using agent-scoped keys ensures that a single runaway agent cannot starve
# other agents sharing its source IP (a real risk when agents are fanned out
# behind one egress NAT). The limit string itself (per_agent vs default) is
# still a single value; the stricter per_agent setting governs both paths,
# which is the safe choice.
def _rate_limit_key(request: StarletteRequest) -> str:
    agent_id = request.headers.get("x-apex-agent-id")
    if agent_id:
        return f"agent:{agent_id}"
    cert_cn = request.headers.get("x-client-cert-cn")
    if cert_cn:
        return f"cert:{cert_cn}"
    return f"ip:{get_remote_address(request)}"


limiter = Limiter(
    key_func=_rate_limit_key,
    default_limits=[settings.rate_limit.per_agent, settings.rate_limit.default],
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
    from apex_pay.services.correlation import current_correlation_id

    rid = current_correlation_id()
    logger.exception(
        "Unhandled error on %s %s (request_id=%s)",
        request.method, request.url.path, rid,
    )
    logfire.error(
        "Unhandled exception: {error}",
        error=str(exc),
        path=request.url.path,
        request_id=rid,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error.", "request_id": rid},
        headers={"X-Request-ID": rid} if rid else None,
    )
