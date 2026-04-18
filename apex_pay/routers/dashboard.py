"""
Dashboard Router — Endpoints for the APEX-Command Frontend
============================================================
Read-only endpoints that power the live dashboard. Uses the ReadonlySession
(SELECT-only DB role) wherever possible.

    GET  /dashboard/stats        — Aggregate stat-card numbers
    GET  /dashboard/agents       — Agent list with spend & policy info
    GET  /dashboard/audit-logs   — Paginated audit log feed
    GET  /dashboard/throughput   — 24-hour approved/denied histogram
    PATCH /dashboard/agents/{id}/status — Toggle agent active/suspended
    POST  /dashboard/policies    — Save policy from Policy Studio
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select, func, text, case, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from apex_pay.core.database import ReadonlySession, GatewaySession
from apex_pay.core.models import Agent, AuditLog, Policy, Transaction

logger = logging.getLogger("apex_pay.dashboard")

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


# ── Shared audit-log serializer ─────────────────────────────────────────────
# Used by both the paginated GET /audit-logs endpoint and the SSE
# /audit-logs/stream endpoint so polled and streamed payloads have
# byte-identical shape and the frontend can merge them blindly.
def _serialize_audit_log(log: AuditLog, agent_name: str) -> dict:
    raw = log.raw_intent or {}
    return {
        "id": str(log.id),
        "timestamp": log.created_at.isoformat() if log.created_at else None,
        "agentName": agent_name,
        "agentId": str(log.agent_id),
        "status": log.status,
        "function": raw.get(
            "function", raw.get("tool_call", {}).get("function", "unknown")
        ),
        "domain": log.action_domain or raw.get("target_url", "internal"),
        "cost": float(log.projected_cost) if log.projected_cost else 0,
        "riskScore": round(float(log.risk_score) * 100) if log.risk_score else 0,
        "reason": log.denial_reason or "policy_passed",
        "rawIntent": raw,
        "latencyMs": float(log.latency_ms) if log.latency_ms else None,
        "policySnapshot": log.policy_snapshot,
    }


# The SSE /audit-logs/stream endpoint subscribes to the
# `audit_feed_broker` owned by the FastAPI lifespan (see apex_pay/main.py).
# DSN translation + LISTEN lifecycle lives there — this router only reads
# from the broker's fanout queues.


# ── Dependencies ───────────────────────────────────────────────────────────
async def get_readonly_session() -> AsyncSession:
    async with ReadonlySession() as session:
        yield session


async def get_gateway_session() -> AsyncSession:
    async with GatewaySession() as session:
        yield session


# ==========================================================================
# GET /dashboard/stats — Aggregate numbers for stat cards
# ==========================================================================
@router.get("/stats")
async def get_stats(session: AsyncSession = Depends(get_readonly_session)) -> dict:
    """Returns total spend (24h), active agent count, and denial count."""
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)

    # Total spend: sum of SETTLED/CONSUMED transactions in last 24h
    spend_q = await session.execute(
        select(func.coalesce(func.sum(Transaction.amount), 0)).where(
            Transaction.state.in_(["SETTLED", "CONSUMED"]),
            Transaction.created_at >= day_ago,
        )
    )
    total_spend = float(spend_q.scalar_one())

    # Active agents
    active_q = await session.execute(
        select(func.count()).select_from(Agent).where(Agent.status == "active")
    )
    active_count = active_q.scalar_one()

    # Total agents
    total_q = await session.execute(select(func.count()).select_from(Agent))
    total_agents = total_q.scalar_one()

    # Denials in last 24h
    denied_q = await session.execute(
        select(func.count()).select_from(AuditLog).where(
            AuditLog.status == "DENIED",
            AuditLog.created_at >= day_ago,
        )
    )
    violations = denied_q.scalar_one()

    # Total audit events in last 24h
    events_q = await session.execute(
        select(func.count()).select_from(AuditLog).where(
            AuditLog.created_at >= day_ago,
        )
    )
    total_events = events_q.scalar_one()

    return {
        "total_spend_24h": round(total_spend, 2),
        "active_agents": active_count,
        "total_agents": total_agents,
        "violations_24h": violations,
        "total_events_24h": total_events,
    }


# ==========================================================================
# GET /dashboard/agents — Agent list with daily spend and policy info
# ==========================================================================
@router.get("/agents")
async def get_agents(session: AsyncSession = Depends(get_readonly_session)) -> list[dict]:
    """Returns agents enriched with daily spend, policy limits, and risk avg."""
    now = datetime.now(timezone.utc)
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)

    # All agents
    agents_result = await session.execute(select(Agent).order_by(Agent.created_at.desc()))
    agents = agents_result.scalars().all()

    enriched = []
    for agent in agents:
        # Daily spend from transactions
        spend_q = await session.execute(
            select(func.coalesce(func.sum(Transaction.amount), 0)).where(
                Transaction.agent_id == agent.id,
                Transaction.state.in_(["SETTLED", "CONSUMED"]),
                Transaction.created_at >= today_start,
            )
        )
        daily_spend = float(spend_q.scalar_one())

        # Active policy
        policy_q = await session.execute(
            select(Policy).where(
                Policy.agent_id == agent.id, Policy.is_active.is_(True)
            )
        )
        policy = policy_q.scalar_one_or_none()

        # Tx count (24h)
        tx_count_q = await session.execute(
            select(func.count()).select_from(AuditLog).where(
                AuditLog.agent_id == agent.id,
                AuditLog.created_at >= today_start,
            )
        )
        tx_count = tx_count_q.scalar_one()

        # Average risk score (24h)
        risk_q = await session.execute(
            select(func.coalesce(func.avg(AuditLog.risk_score), 0)).where(
                AuditLog.agent_id == agent.id,
                AuditLog.created_at >= today_start,
            )
        )
        risk_avg = float(risk_q.scalar_one())

        enriched.append({
            "id": str(agent.id),
            "name": agent.name,
            "status": agent.status,
            "balance": float(agent.current_balance),
            "dailySpend": round(daily_spend, 2),
            "dailyLimit": float(policy.daily_limit) if policy else 0,
            "maxPerTxn": float(policy.max_per_transaction) if policy else 0,
            "allowedDomains": policy.allowed_domains if policy else [],
            "riskAvg": round(risk_avg * 100, 1),  # 0-1 → 0-100 for display
            "txCount": tx_count,
        })

    return enriched


# ==========================================================================
# GET /dashboard/audit-logs — Paginated audit feed
# ==========================================================================
@router.get("/audit-logs")
async def get_audit_logs(
    limit: int = Query(default=100, le=500),
    offset: int = Query(default=0, ge=0),
    status: str | None = Query(default=None),
    search: str | None = Query(default=None),
    session: AsyncSession = Depends(get_readonly_session),
) -> dict:
    """Returns recent audit logs with optional status filter and search."""
    query = select(AuditLog).order_by(AuditLog.created_at.desc())

    if status and status != "ALL":
        query = query.where(AuditLog.status == status)

    # For search, we join on agent name
    if search:
        query = query.join(Agent, AuditLog.agent_id == Agent.id).where(
            Agent.name.ilike(f"%{search}%")
        )

    total_q = select(func.count()).select_from(query.subquery())
    total_result = await session.execute(total_q)
    total = total_result.scalar_one()

    query = query.offset(offset).limit(limit)
    result = await session.execute(query)
    logs = result.scalars().all()

    # Resolve agent names
    agent_ids = list({log.agent_id for log in logs})
    if agent_ids:
        agents_q = await session.execute(
            select(Agent.id, Agent.name).where(Agent.id.in_(agent_ids))
        )
        agent_map = {row.id: row.name for row in agents_q.all()}
    else:
        agent_map = {}

    items = [
        _serialize_audit_log(log, agent_map.get(log.agent_id, "Unknown"))
        for log in logs
    ]

    return {"items": items, "total": total}


# ==========================================================================
# GET /dashboard/audit-logs/stream — SSE live tail of audit_logs
# ==========================================================================
# Architecture:
#   audit_logs INSERT → trigger notify_audit_insert → pg_notify('audit_feed', id)
#   ↓
#   ONE process-wide asyncpg LISTEN conn (apex_pay.services.audit_feed_broker)
#   ↓
#   fan-out to per-subscriber asyncio.Queue
#   ↓
#   per-notify SELECT by id (readonly session) + agent name lookup
#   ↓
#   SSE frame to the browser EventSource
#
# Design choices:
#   • Payload on the NOTIFY channel is id-only (8KB NOTIFY cap; raw_intent
#     could blow it). The SSE handler hydrates via SELECT on the readonly
#     role so payload shape matches /audit-logs exactly.
#   • The broker holds one dedicated asyncpg connection for the lifetime
#     of the process. A per-client connection works in principle, but on
#     Supabase's Supavisor pooler a burst of new-connection attempts trips
#     the pooler's own circuit breaker — holding one long-lived conn
#     sidesteps that failure mode and respects the connection cap.
#   • 15-second heartbeat comment frames defeat reverse-proxy idle timeouts
#     (nginx default is 60s, most CDNs 30–60s).
#   • X-Accel-Buffering: no — nginx would otherwise buffer the response
#     and batch-flush, defeating real-time delivery.
#   • Backfill of the last 50 rows so a fresh tab isn't empty; frontend
#     de-dupes by id across the backfill/live boundary.
# ==========================================================================
_SSE_BACKFILL_ROWS = 50
_SSE_HEARTBEAT_SECONDS = 15.0


async def _hydrate_audit_log(log_id: uuid.UUID) -> dict | None:
    """Fetch one audit row + agent name and serialize to the dashboard shape."""
    async with ReadonlySession() as s:
        log_result = await s.execute(
            select(AuditLog).where(AuditLog.id == log_id)
        )
        log = log_result.scalar_one_or_none()
        if log is None:
            return None

        agent_q = await s.execute(
            select(Agent.name).where(Agent.id == log.agent_id)
        )
        agent_name = agent_q.scalar_one_or_none() or "Unknown"
        return _serialize_audit_log(log, agent_name)


@router.get("/audit-logs/stream")
async def stream_audit_logs(request: Request) -> StreamingResponse:
    """SSE live tail of audit_logs.

    Emits each new row as a `data:`-framed JSON object whose shape matches
    `GET /audit-logs` items exactly. Backfills the last 50 rows on connect
    so a freshly-opened tab isn't empty; the client de-dupes by id.
    """
    broker = getattr(request.app.state, "audit_feed_broker", None)
    if broker is None:
        # Unlikely: lifespan startup didn't complete. Fail the request
        # hard so the frontend can show an offline state rather than
        # hanging on an empty stream.
        raise HTTPException(
            status_code=503,
            detail="audit feed broker not initialized",
        )

    queue = broker.subscribe()

    async def event_source():
        try:
            # ── Backfill: last N rows so the UI isn't empty on connect ─────
            async with ReadonlySession() as s:
                result = await s.execute(
                    select(AuditLog)
                    .order_by(AuditLog.created_at.desc())
                    .limit(_SSE_BACKFILL_ROWS)
                )
                backfill_rows = list(result.scalars().all())

                agent_ids = list({r.agent_id for r in backfill_rows})
                if agent_ids:
                    agents_q = await s.execute(
                        select(Agent.id, Agent.name).where(Agent.id.in_(agent_ids))
                    )
                    agent_map = {row.id: row.name for row in agents_q.all()}
                else:
                    agent_map = {}

            # Send oldest-first so the client renders them in chronological
            # order (the UI prepends newer rows, so emit reversed).
            for log in reversed(backfill_rows):
                payload = _serialize_audit_log(
                    log, agent_map.get(log.agent_id, "Unknown")
                )
                yield f"data: {json.dumps(payload)}\n\n"

            # ── Live tail (from the shared broker queue) ───────────────────
            while True:
                try:
                    log_id_str = await asyncio.wait_for(
                        queue.get(), timeout=_SSE_HEARTBEAT_SECONDS,
                    )
                except asyncio.TimeoutError:
                    # SSE heartbeat — comment frames (lines starting with `:`)
                    # are silently ignored by EventSource but keep proxies
                    # from treating the connection as idle.
                    yield ": keepalive\n\n"
                    continue

                # The broker pushes an empty-string sentinel during shutdown
                # to release any blocked consumers. Skip it.
                if not log_id_str:
                    continue

                try:
                    log_id = uuid.UUID(log_id_str)
                except ValueError:
                    logger.warning(
                        "Bad audit_feed payload (not a UUID): %r", log_id_str,
                    )
                    continue

                hydrated = await _hydrate_audit_log(log_id)
                if hydrated is None:
                    # Row was just inserted; if we can't find it via the
                    # readonly role, something is badly off — log and skip.
                    logger.warning("audit_feed notify for missing id %s", log_id)
                    continue
                yield f"data: {json.dumps(hydrated)}\n\n"

        except asyncio.CancelledError:
            # Normal: client disconnected.
            raise
        except Exception:
            logger.exception("SSE audit-logs stream crashed; closing.")
        finally:
            broker.unsubscribe(queue)

    return StreamingResponse(
        event_source(),
        media_type="text/event-stream",
        headers={
            # Prevent any well-behaved proxy (nginx, cloudflare, etc.) from
            # buffering the response and batching frames.
            "Cache-Control": "no-cache, no-transform",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ==========================================================================
# GET /dashboard/throughput — 24-hour histogram (approved vs denied per hour)
# ==========================================================================
@router.get("/throughput")
async def get_throughput(session: AsyncSession = Depends(get_readonly_session)) -> list[dict]:
    """Returns hourly approved/denied counts for the last 24 hours."""
    now = datetime.now(timezone.utc)

    # Build all 24 hour slots
    hours = []
    for i in range(24):
        hour_start = (now - timedelta(hours=23 - i)).replace(
            minute=0, second=0, microsecond=0
        )
        hour_end = hour_start + timedelta(hours=1)
        hours.append((hour_start, hour_end))

    result = []
    for hour_start, hour_end in hours:
        approved_q = await session.execute(
            select(func.count()).select_from(AuditLog).where(
                AuditLog.status == "APPROVED",
                AuditLog.created_at >= hour_start,
                AuditLog.created_at < hour_end,
            )
        )
        denied_q = await session.execute(
            select(func.count()).select_from(AuditLog).where(
                AuditLog.status == "DENIED",
                AuditLog.created_at >= hour_start,
                AuditLog.created_at < hour_end,
            )
        )
        result.append({
            "name": hour_start.strftime("%H:%M"),
            "approved": approved_q.scalar_one(),
            "denied": denied_q.scalar_one(),
        })

    return result


# ==========================================================================
# PATCH /dashboard/agents/{id}/status — Toggle agent active/suspended
# ==========================================================================
@router.patch("/agents/{agent_id}/status")
async def toggle_agent_status(
    agent_id: uuid.UUID,
    session: AsyncSession = Depends(get_gateway_session),
) -> dict:
    """Toggle an agent between 'active' and 'suspended'."""
    result = await session.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")

    new_status = "suspended" if agent.status == "active" else "active"
    agent.status = new_status
    await session.commit()

    return {"id": str(agent.id), "name": agent.name, "status": new_status}


# ==========================================================================
# POST /dashboard/policies — Save policy from Policy Studio
# ==========================================================================
@router.post("/policies")
async def save_policy(
    body: dict,
    session: AsyncSession = Depends(get_gateway_session),
) -> dict:
    """Create or replace a policy for an agent from the dashboard."""
    agent_id = body.get("agent_id")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id required")

    agent_uuid = uuid.UUID(agent_id)

    # Deactivate existing active policy
    existing_q = await session.execute(
        select(Policy).where(
            Policy.agent_id == agent_uuid, Policy.is_active.is_(True)
        )
    )
    existing = existing_q.scalar_one_or_none()
    if existing:
        existing.is_active = False

    policy = Policy(
        agent_id=agent_uuid,
        max_per_transaction=body.get("max_per_transaction", 50.0),
        daily_limit=body.get("daily_limit", 200.0),
        allowed_domains=body.get("allowed_domains", []),
    )
    session.add(policy)
    await session.commit()
    await session.refresh(policy)

    return {
        "id": str(policy.id),
        "agent_id": str(policy.agent_id),
        "max_per_transaction": float(policy.max_per_transaction),
        "daily_limit": float(policy.daily_limit),
        "allowed_domains": policy.allowed_domains,
        "is_active": policy.is_active,
    }
