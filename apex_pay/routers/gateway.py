"""
Gateway Router — Primary APEX-Pay Endpoints
=============================================
Implements the policy-gated execution flow from the APEX paper:

    1. POST /execute   — Intercept tool_call → policy check → approve/deny
    2. GET  /data      — Protected data endpoint (returns 402 challenge or data)
    3. POST /pay       — Settlement endpoint (issues HMAC token)
    4. POST /reset     — Reset ledger for reproducible experiments
    5. GET  /health    — Liveness probe

Rate-limited via SlowAPI to prevent DDoS and agent-looping (blueprint §Step 1).
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

import logfire
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from apex_pay.core.config import settings
from apex_pay.core.database import GatewaySession
from apex_pay.core.models import Agent, Policy, Transaction
from apex_pay.core.schemas import (
    ChallengeResponse,
    GatewayResponse,
    HealthResponse,
    PolicyDecision,
    SettlementRequest,
    SettlementResponse,
    ToolCallPayload,
)
from apex_pay.services.audit_queue import AuditQueue
from apex_pay.services.policy_engine import PolicyEngine
from apex_pay.services.token_service import TokenService

router = APIRouter()
policy_engine = PolicyEngine()
token_service = TokenService()

_start_time = time.time()


# ── Dependency: DB session ──────────────────────────────────────────────────
async def get_session() -> AsyncSession:
    async with GatewaySession() as session:
        yield session


# ── Dependency: Audit queue (from app state) ────────────────────────────────
def get_audit_queue(request: Request) -> AuditQueue:
    return request.app.state.audit_queue


# =============================================================================
# POST /execute — Primary Policy-Gated Endpoint
# =============================================================================
@router.post(
    "/execute",
    response_model=GatewayResponse,
    summary="Intercept an agent tool-call and validate against policy",
    tags=["gateway"],
)
async def execute_tool_call(
    request: Request,
    payload: ToolCallPayload,
    session: AsyncSession = Depends(get_session),
    audit_queue: AuditQueue = Depends(get_audit_queue),
) -> GatewayResponse:
    """The main APEX-Pay gateway endpoint.

    Intercepts the agent's tool_call JSON payload, runs it through the
    Policy Enforcement Engine, and returns an APPROVED or DENIED decision.
    """
    request_id = uuid.uuid4()
    start = time.perf_counter()

    # ── Back-pressure check (blueprint §Step 2) ────────────────────────
    if await audit_queue.is_saturated():
        raise HTTPException(
            status_code=503,
            detail="Audit queue saturated — retry later.",
        )

    # ── Logfire: trace the intent ──────────────────────────────────────
    with logfire.span(
        "policy_evaluation",
        agent_id=str(payload.agent_id),
        tool_call=payload.tool_call,
    ):
        decision: PolicyDecision = await policy_engine.evaluate(payload, session)

    elapsed_ms = (time.perf_counter() - start) * 1000

    # ── Build response ─────────────────────────────────────────────────
    status = "APPROVED" if decision.allowed else "DENIED"

    response = GatewayResponse(
        request_id=request_id,
        allowed=decision.allowed,
        status=status,
        reason=decision.reason,
        latency_ms=round(elapsed_ms, 2),
    )

    # ── Async audit log (non-blocking) ─────────────────────────────────
    await audit_queue.push(
        agent_id=payload.agent_id,
        raw_intent=payload.tool_call,
        projected_cost=decision.projected_cost,
        action_domain=decision.action_domain,
        risk_score=decision.risk_score,
        status=status,
        denial_reason=decision.reason if not decision.allowed else None,
        policy_snapshot=decision.policy_snapshot,
        latency_ms=round(elapsed_ms, 2),
    )

    # ── Logfire: record decision ───────────────────────────────────────
    logfire.info(
        "Policy decision: {status} for agent {agent_id} — {reason}",
        status=status,
        agent_id=str(payload.agent_id),
        reason=decision.reason,
        latency_ms=round(elapsed_ms, 2),
        projected_cost=decision.projected_cost,
    )

    return response


# =============================================================================
# GET /data — Protected Data Endpoint (HTTP 402 Challenge Flow)
# =============================================================================
@router.get(
    "/data",
    summary="Access protected data — returns 402 challenge or data",
    tags=["gateway"],
)
async def get_data(
    request: Request,
    baseline: str = "payment_with_policy",
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Implements the APEX /data endpoint.

    - If baseline is `no_policy`, returns data directly.
    - If no payment token header, returns HTTP 402 with a challenge.
    - If valid token, verifies and consumes it, then returns data.
    """
    # no_policy baseline — direct access
    if baseline == "no_policy":
        return {
            "status": "ok",
            "baseline": baseline,
            "data": {"title": "Protected research data", "content": "..."},
        }

    # Check for payment token
    token = request.headers.get("x-payment-token")

    if not token:
        # Issue HTTP 402 challenge
        ref_id = str(uuid.uuid4())
        amount = 10.0

        # Create challenge record
        txn = Transaction(
            agent_id=uuid.UUID("00000000-0000-0000-0000-000000000000"),  # placeholder
            ref_id=ref_id,
            amount=amount,
            state="CHALLENGED",
        )
        session.add(txn)
        await session.commit()

        raise HTTPException(
            status_code=402,
            detail={
                "amount": amount,
                "ref_id": ref_id,
                "baseline": baseline,
                "upi_link": f"upi://pay?ref={ref_id}&amount={amount}",
                "message": "Payment Required",
            },
        )

    # Verify and consume token
    is_valid, reason, payload = token_service.verify(token)
    if not is_valid:
        raise HTTPException(status_code=403, detail={"allowed": False, "reason": reason})

    ref_id = payload.get("ref_id")
    if ref_id:
        # Consume the token (state → CONSUMED)
        result = await session.execute(
            select(Transaction).where(
                Transaction.ref_id == ref_id,
                Transaction.state == "SETTLED",
            )
        )
        txn = result.scalar_one_or_none()
        if txn is None:
            raise HTTPException(
                status_code=403,
                detail={"allowed": False, "reason": "token_already_consumed"},
            )
        txn.state = "CONSUMED"
        txn.consumed_at = datetime.now(timezone.utc)
        await session.commit()

    return {
        "status": "ok",
        "baseline": baseline,
        "data": {"title": "Protected research data", "content": "..."},
    }


# =============================================================================
# POST /pay — Settlement Endpoint
# =============================================================================
@router.post(
    "/pay",
    response_model=SettlementResponse,
    summary="Settle a payment challenge and receive a signed token",
    tags=["gateway"],
)
async def settle_payment(
    request: Request,
    body: SettlementRequest,
    session: AsyncSession = Depends(get_session),
    audit_queue: AuditQueue = Depends(get_audit_queue),
) -> SettlementResponse:
    """Implements the APEX /pay settlement endpoint.

    Evaluates policy, settles payment state, and issues a signed token.
    """
    # Load the challenge record
    result = await session.execute(
        select(Transaction).where(Transaction.ref_id == body.ref_id)
    )
    txn = result.scalar_one_or_none()

    if txn is None:
        raise HTTPException(status_code=404, detail="Unknown ref_id.")

    # Idempotency: if already settled with same key, return existing token
    if txn.state == "SETTLED" and body.idempotency_key and txn.idempotency_key == body.idempotency_key:
        return SettlementResponse(
            status="success",
            ref_id=txn.ref_id,
            amount=float(txn.amount),
            token=txn.token,
            token_expiry=int(txn.token_expiry.timestamp()) if txn.token_expiry else None,
            state=txn.state,
        )

    if txn.state not in ("CHALLENGED", "INITIATED"):
        raise HTTPException(
            status_code=409,
            detail=f"Transaction in state '{txn.state}' cannot be settled.",
        )

    # Policy check (if payment_with_policy baseline)
    if body.baseline == "payment_with_policy":
        # Load agent's policy for per-request and daily checks
        policy_result = await session.execute(
            select(Policy).where(Policy.agent_id == txn.agent_id, Policy.is_active.is_(True))
        )
        policy = policy_result.scalar_one_or_none()

        if policy:
            # Per-request check
            if body.amount > float(policy.max_per_transaction):
                await audit_queue.push(
                    agent_id=txn.agent_id,
                    raw_intent={"ref_id": body.ref_id, "amount": body.amount},
                    projected_cost=body.amount,
                    action_domain=None,
                    risk_score=0.0,
                    status="DENIED",
                    denial_reason="exceeds_per_transaction_limit",
                )
                return SettlementResponse(
                    status="blocked",
                    ref_id=body.ref_id,
                    amount=body.amount,
                    allowed=False,
                    reason="exceeds_per_transaction_limit",
                )

            # Daily budget check
            today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            spend_result = await session.execute(
                text("""
                    SELECT COALESCE(SUM(amount), 0) FROM transactions
                    WHERE agent_id = :agent_id
                      AND state IN ('SETTLED', 'CONSUMED')
                      AND created_at >= :today
                """),
                {"agent_id": str(txn.agent_id), "today": today_start},
            )
            spent_today = float(spend_result.scalar_one())

            if spent_today + body.amount > float(policy.daily_limit):
                await audit_queue.push(
                    agent_id=txn.agent_id,
                    raw_intent={"ref_id": body.ref_id, "amount": body.amount},
                    projected_cost=body.amount,
                    action_domain=None,
                    risk_score=0.0,
                    status="DENIED",
                    denial_reason="daily_budget_exceeded",
                )
                return SettlementResponse(
                    status="blocked",
                    ref_id=body.ref_id,
                    amount=body.amount,
                    allowed=False,
                    reason=f"daily_budget exceeded ({spent_today + body.amount:.2f} > {float(policy.daily_limit):.2f})",
                )

    # Issue signed token
    token, expiry = token_service.issue(body.ref_id, body.amount)

    # Transition state: CHALLENGED/INITIATED → SETTLED
    txn.state = "SETTLED"
    txn.token = token
    txn.token_expiry = datetime.fromtimestamp(expiry, tz=timezone.utc)
    txn.idempotency_key = body.idempotency_key
    await session.commit()

    logfire.info(
        "Payment settled: ref_id={ref_id}, amount={amount}",
        ref_id=body.ref_id,
        amount=body.amount,
    )

    return SettlementResponse(
        status="success",
        ref_id=body.ref_id,
        amount=body.amount,
        token=token,
        token_expiry=expiry,
        state="SETTLED",
    )


# =============================================================================
# POST /reset — Ledger Reset (for reproducible experiments)
# =============================================================================
@router.post("/reset", summary="Clear ledger for experiment boundaries", tags=["admin"])
async def reset_ledger(session: AsyncSession = Depends(get_session)) -> dict:
    await session.execute(text("DELETE FROM transactions"))
    await session.commit()
    return {"status": "ok", "message": "Ledger cleared."}


# =============================================================================
# GET /health — Liveness Probe
# =============================================================================
@router.get("/health", response_model=HealthResponse, tags=["ops"])
async def health() -> HealthResponse:
    from apex_pay import __version__

    return HealthResponse(
        status="ok",
        version=__version__,
        uptime_seconds=round(time.time() - _start_time, 2),
    )
