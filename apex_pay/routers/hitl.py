"""Human-in-the-Loop router.

Endpoints:
    GET  /hitl/pending       — list intents currently escalated to HITL
    GET  /hitl/{request_id}  — fetch one pending request
    POST /hitl/{id}/approve  — approve (still subject to post-approval replay of pipeline)
    POST /hitl/{id}/deny     — deny

Approve/deny here only sets the resolution state; the agent must retry
its original /execute call to actually run the intent. This keeps the
gateway's APPROVED path the single place where credentials are minted
and receipts are signed.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, HTTPException, Query

from apex_pay.shield.hitl_store import default_store

router = APIRouter(prefix="/hitl", tags=["shield"])


def _serialise(req) -> dict:
    return {
        "id": str(req.id),
        "agent_id": str(req.agent_id),
        "intent_hash": req.intent_hash,
        "reason": req.reason,
        "violations": req.violations,
        "risk_score": req.risk_score,
        "risk_entropy": req.risk_entropy,
        "created_at": req.created_at,
        "resolution": req.resolution,
        "resolver": req.resolver,
        "resolved_at": req.resolved_at,
    }


@router.get("/pending")
async def list_pending() -> dict:
    items = await default_store().list_pending()
    return {"items": [_serialise(r) for r in items]}


@router.get("/{request_id}")
async def get_request(request_id: uuid.UUID) -> dict:
    req = await default_store().get(request_id)
    if req is None:
        raise HTTPException(status_code=404, detail="HITL request not found or expired.")
    return _serialise(req)


@router.post("/{request_id}/approve")
async def approve(
    request_id: uuid.UUID,
    resolver: str = Query(..., min_length=1, max_length=128),
) -> dict:
    req = await default_store().resolve(
        request_id, resolution="approved", resolver=resolver,
    )
    if req is None:
        raise HTTPException(
            status_code=409,
            detail="HITL request is already resolved or does not exist.",
        )
    return _serialise(req)


@router.post("/{request_id}/deny")
async def deny(
    request_id: uuid.UUID,
    resolver: str = Query(..., min_length=1, max_length=128),
) -> dict:
    req = await default_store().resolve(
        request_id, resolution="denied", resolver=resolver,
    )
    if req is None:
        raise HTTPException(
            status_code=409,
            detail="HITL request is already resolved or does not exist.",
        )
    return _serialise(req)
