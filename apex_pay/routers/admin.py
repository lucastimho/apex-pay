"""
Admin Router — Agent & Policy Management
==========================================
CRUD endpoints for registering agents and configuring spending policies.
These are administrative operations, not part of the agent tool-call flow.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from apex_pay.core.database import GatewaySession
from apex_pay.core.models import Agent, Policy
from apex_pay.core.schemas import AgentCreate, AgentOut, PolicyCreate, PolicyOut

router = APIRouter(prefix="/admin", tags=["admin"])


async def get_session() -> AsyncSession:
    async with GatewaySession() as session:
        yield session


# ── Agents ──────────────────────────────────────────────────────────────────
@router.post("/agents", response_model=AgentOut, status_code=201)
async def register_agent(
    body: AgentCreate,
    session: AsyncSession = Depends(get_session),
) -> AgentOut:
    agent = Agent(
        name=body.name,
        public_key=body.public_key,
        current_balance=body.initial_balance,
    )
    session.add(agent)
    await session.commit()
    await session.refresh(agent)
    return AgentOut.model_validate(agent)


@router.get("/agents", response_model=list[AgentOut])
async def list_agents(session: AsyncSession = Depends(get_session)) -> list[AgentOut]:
    result = await session.execute(select(Agent).order_by(Agent.created_at.desc()))
    return [AgentOut.model_validate(a) for a in result.scalars().all()]


@router.get("/agents/{agent_id}", response_model=AgentOut)
async def get_agent(
    agent_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> AgentOut:
    result = await session.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found.")
    return AgentOut.model_validate(agent)


# ── Policies ────────────────────────────────────────────────────────────────
@router.post("/policies", response_model=PolicyOut, status_code=201)
async def create_policy(
    body: PolicyCreate,
    session: AsyncSession = Depends(get_session),
) -> PolicyOut:
    # Deactivate any existing active policy for this agent
    result = await session.execute(
        select(Policy).where(
            Policy.agent_id == body.agent_id, Policy.is_active.is_(True)
        )
    )
    existing = result.scalar_one_or_none()
    if existing:
        existing.is_active = False

    policy = Policy(
        agent_id=body.agent_id,
        max_per_transaction=body.max_per_transaction,
        daily_limit=body.daily_limit,
        allowed_domains=body.allowed_domains,
    )
    session.add(policy)
    await session.commit()
    await session.refresh(policy)
    return PolicyOut.model_validate(policy)


@router.get("/policies/{agent_id}", response_model=PolicyOut)
async def get_active_policy(
    agent_id: uuid.UUID,
    session: AsyncSession = Depends(get_session),
) -> PolicyOut:
    result = await session.execute(
        select(Policy).where(
            Policy.agent_id == agent_id, Policy.is_active.is_(True)
        )
    )
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="No active policy found.")
    return PolicyOut.model_validate(policy)
