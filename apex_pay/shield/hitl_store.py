"""Human-in-the-Loop escalation store.

When OPA returns `escalate=True`, the shield stashes the full pending
decision here keyed by `hitl_request_id` and returns HTTP 202 to the
agent. An operator (or another service) then calls POST /hitl/{id}/approve
or /hitl/{id}/deny and the pending intent is executed or rejected.

This implementation is process-local: it works for single-node testing
and for small deployments where the gateway is run as one process. For
HA deployments, swap this for a Redis or Postgres-backed store — the
interface is small enough to port.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from typing import Any


@dataclass
class HITLRequest:
    id: uuid.UUID
    agent_id: uuid.UUID
    intent_hash: str
    reason: str
    violations: list[str]
    opa_input: dict[str, Any]
    risk_score: float
    risk_entropy: float
    created_at: float = field(default_factory=time.time)
    resolution: str | None = None   # "approved" | "denied" | None
    resolver: str | None = None
    resolved_at: float | None = None


class HITLStore:
    """In-memory pending/resolved HITL request tracker."""

    def __init__(self, *, ttl_seconds: int = 3600):
        self._ttl = ttl_seconds
        self._items: dict[uuid.UUID, HITLRequest] = {}
        self._lock = asyncio.Lock()

    async def create(
        self,
        *,
        agent_id: uuid.UUID,
        intent_hash: str,
        reason: str,
        violations: list[str],
        opa_input: dict[str, Any],
        risk_score: float,
        risk_entropy: float,
    ) -> HITLRequest:
        req = HITLRequest(
            id=uuid.uuid4(),
            agent_id=agent_id,
            intent_hash=intent_hash,
            reason=reason,
            violations=list(violations),
            opa_input=opa_input,
            risk_score=risk_score,
            risk_entropy=risk_entropy,
        )
        async with self._lock:
            self._purge_expired_locked()
            self._items[req.id] = req
        return req

    async def get(self, request_id: uuid.UUID) -> HITLRequest | None:
        async with self._lock:
            self._purge_expired_locked()
            return self._items.get(request_id)

    async def resolve(
        self, request_id: uuid.UUID, *, resolution: str, resolver: str,
    ) -> HITLRequest | None:
        if resolution not in {"approved", "denied"}:
            raise ValueError(f"Unknown resolution: {resolution}")
        async with self._lock:
            req = self._items.get(request_id)
            if req is None or req.resolution is not None:
                return None
            req.resolution = resolution
            req.resolver = resolver
            req.resolved_at = time.time()
            return req

    async def list_pending(self) -> list[HITLRequest]:
        async with self._lock:
            self._purge_expired_locked()
            return [r for r in self._items.values() if r.resolution is None]

    def _purge_expired_locked(self) -> None:
        cutoff = time.time() - self._ttl
        expired = [rid for rid, r in self._items.items() if r.created_at < cutoff]
        for rid in expired:
            del self._items[rid]


# Module-level singleton so the gateway and /hitl routers share state.
_default_store: HITLStore | None = None


def default_store() -> HITLStore:
    global _default_store
    if _default_store is None:
        _default_store = HITLStore()
    return _default_store
