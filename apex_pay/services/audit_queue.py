"""
Redis-Backed Async Audit Queue
================================
Non-blocking audit logging so the critical transaction path never waits
on slow I/O. Every DENIED (and APPROVED) decision is pushed onto a Redis
list. A background worker drains the queue and INSERTs into `audit_logs`
using the INSERT-only `apex_auditor` database role.

Back-pressure: if the queue exceeds `max_queue_depth`, the gateway returns
HTTP 503 to the agent to prevent database congestion (blueprint §Step 2).
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

import redis.asyncio as aioredis

from apex_pay.core.config import settings


class AuditQueue:
    """Async interface to the Redis audit queue."""

    def __init__(self, redis_client: aioredis.Redis | None = None):
        self._redis = redis_client
        self._queue = settings.redis.audit_queue_name
        self._max_depth = settings.redis.max_queue_depth

    async def connect(self) -> None:
        if self._redis is None:
            self._redis = aioredis.from_url(
                settings.redis.url,
                decode_responses=True,
                max_connections=10,
            )

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()

    # ── Back-Pressure Check ─────────────────────────────────────────────
    async def is_saturated(self) -> bool:
        """Return True if queue depth exceeds the threshold.

        The gateway should return HTTP 503 when this is True.
        """
        if self._redis is None:
            return False
        depth = await self._redis.llen(self._queue)
        return depth >= self._max_depth

    # ── Enqueue ─────────────────────────────────────────────────────────
    async def push(
        self,
        *,
        agent_id: uuid.UUID,
        raw_intent: dict[str, Any],
        projected_cost: float | None,
        action_domain: str | None,
        risk_score: float,
        status: str,
        denial_reason: str | None,
        transaction_id: uuid.UUID | None = None,
        policy_snapshot: dict[str, Any] | None = None,
        latency_ms: float | None = None,
    ) -> None:
        """Serialize and push an audit record onto the Redis queue."""
        if self._redis is None:
            return  # graceful degradation when Redis unavailable

        record = {
            "id": str(uuid.uuid4()),
            "agent_id": str(agent_id),
            "raw_intent": raw_intent,
            "projected_cost": projected_cost,
            "action_domain": action_domain,
            "risk_score": risk_score,
            "status": status,
            "denial_reason": denial_reason,
            "transaction_id": str(transaction_id) if transaction_id else None,
            "policy_snapshot": policy_snapshot,
            "latency_ms": latency_ms,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        await self._redis.rpush(self._queue, json.dumps(record))

    # ── Dequeue (used by the worker) ────────────────────────────────────
    async def pop(self, timeout: int = 5) -> dict[str, Any] | None:
        """Blocking pop — returns None on timeout."""
        if self._redis is None:
            return None
        result = await self._redis.blpop(self._queue, timeout=timeout)
        if result:
            _, raw = result
            return json.loads(raw)
        return None

    async def depth(self) -> int:
        if self._redis is None:
            return 0
        return await self._redis.llen(self._queue)
