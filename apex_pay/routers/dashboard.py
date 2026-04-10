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

import uuid
from datetime import datetime, timezone, timedelta

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, func, text, case, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from apex_pay.core.database import ReadonlySession, GatewaySession
from apex_pay.core.models import Agent, AuditLog, Policy, Transaction

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


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

    items = []
    for log in logs:
        raw = log.raw_intent or {}
        items.append({
            "id": str(log.id),
            "timestamp": log.created_at.isoformat() if log.created_at else None,
            "agentName": agent_map.get(log.agent_id, "Unknown"),
            "agentId": str(log.agent_id),
            "status": log.status,
            "function": raw.get("function", raw.get("tool_call", {}).get("function", "unknown")),
            "domain": log.action_domain or raw.get("target_url", "internal"),
            "cost": float(log.projected_cost) if log.projected_cost else 0,
            "riskScore": round(float(log.risk_score) * 100) if log.risk_score else 0,
            "reason": log.denial_reason or "policy_passed",
            "rawIntent": raw,
            "latencyMs": float(log.latency_ms) if log.latency_ms else None,
            "policySnapshot": log.policy_snapshot,
        })

    return {"items": items, "total": total}


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
