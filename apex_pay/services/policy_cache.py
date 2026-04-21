"""In-process policy cache with Redis pub/sub invalidation.

Blueprint §7.2 and §8: the gateway must not hit Postgres on every decision
for policy lookups. We cache the active `Policy` row per `agent_id` in a
process-local dict with a short TTL, and we invalidate on policy edits by
publishing to a Redis channel that every gateway replica subscribes to.

Design:

* **In-proc dict, not Redis-backed cache.** Reading Postgres on a cache
  miss is fine — the DB lookup is microseconds. What we must avoid is
  paying a Redis roundtrip on every decision.
* **TTL is the upper bound on staleness.** Even if a pub/sub message is
  lost (pub/sub is fire-and-forget), the cache expires after `ttl_seconds`
  and the next reader reloads from the DB. Default: 5 s.
* **Invalidation is an explicit channel.** When the admin router updates
  or deactivates a policy it calls `invalidate(agent_id)`, which both
  evicts the local entry AND publishes on `apex.policies.invalidate` so
  peer replicas evict too.
* **No negative caching.** If the agent has no active policy we simply
  don't cache — an admin will fix it soon enough, and a missing policy is
  treated as fail-closed by the policy engine, so staleness is safe.

The cache intentionally stores plain dicts (the snapshot format used by
the shield pipeline), not SQLAlchemy ORM instances. ORM objects carry
hidden state (detached session, lazy loaders) that we don't want to keep
alive between requests.
"""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any

import redis.asyncio as aioredis

logger = logging.getLogger("apex_pay.policy_cache")

INVALIDATE_CHANNEL = "apex.policies.invalidate"


@dataclass
class _Entry:
    snapshot: dict[str, Any]
    expires_at: float


class PolicyCache:
    """Process-local cache of active policy snapshots, keyed by agent_id.

    `snapshot` is the dict shape consumed by `PolicySnapshot(**snap)` — the
    same thing the legacy `PolicyEngine._snapshot` returns.
    """

    def __init__(self, *, ttl_seconds: float = 5.0) -> None:
        self._ttl = float(ttl_seconds)
        self._entries: dict[uuid.UUID, _Entry] = {}
        self._lock = asyncio.Lock()
        self._redis: aioredis.Redis | None = None
        self._pubsub_task: asyncio.Task[None] | None = None

    # ── Lifecycle ───────────────────────────────────────────────────────
    async def connect(self, redis_url: str) -> None:
        """Attach to Redis and start the pub/sub invalidation listener.

        Safe to call without Redis — if `connect` fails the cache still
        works, it just loses cross-replica invalidation. Staleness is
        then bounded by `ttl_seconds`.
        """
        try:
            self._redis = aioredis.from_url(redis_url, decode_responses=True)
            self._pubsub_task = asyncio.create_task(
                self._listen(), name="policy_cache_invalidator",
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("PolicyCache pub/sub unavailable (%s); TTL-only.", exc)
            self._redis = None

    async def close(self) -> None:
        if self._pubsub_task is not None:
            self._pubsub_task.cancel()
            try:
                await self._pubsub_task
            except asyncio.CancelledError:
                pass
            self._pubsub_task = None
        if self._redis is not None:
            try:
                await self._redis.aclose()
            finally:
                self._redis = None

    # ── Hot path ────────────────────────────────────────────────────────
    def get(self, agent_id: uuid.UUID) -> dict[str, Any] | None:
        entry = self._entries.get(agent_id)
        if entry is None:
            return None
        if entry.expires_at < time.monotonic():
            # Lazy expiry — cheaper than scanning the dict on a timer.
            self._entries.pop(agent_id, None)
            return None
        return entry.snapshot

    def put(self, agent_id: uuid.UUID, snapshot: dict[str, Any]) -> None:
        self._entries[agent_id] = _Entry(
            snapshot=snapshot,
            expires_at=time.monotonic() + self._ttl,
        )

    # ── Invalidation ────────────────────────────────────────────────────
    async def invalidate(self, agent_id: uuid.UUID) -> None:
        """Evict locally AND notify peers."""
        self._entries.pop(agent_id, None)
        if self._redis is not None:
            try:
                await self._redis.publish(INVALIDATE_CHANNEL, str(agent_id))
            except Exception as exc:  # noqa: BLE001
                logger.warning("PolicyCache publish failed (%s)", exc)

    def invalidate_local(self, agent_id: uuid.UUID) -> None:
        self._entries.pop(agent_id, None)

    # ── Background task ─────────────────────────────────────────────────
    async def _listen(self) -> None:
        assert self._redis is not None
        pubsub = self._redis.pubsub()
        try:
            await pubsub.subscribe(INVALIDATE_CHANNEL)
            logger.info("PolicyCache subscribed to %s", INVALIDATE_CHANNEL)
            while True:
                msg = await pubsub.get_message(
                    ignore_subscribe_messages=True, timeout=5.0,
                )
                if msg is None:
                    continue
                try:
                    agent_id = uuid.UUID(str(msg.get("data", "")))
                except (ValueError, TypeError):
                    continue
                self.invalidate_local(agent_id)
        except asyncio.CancelledError:
            pass
        except Exception as exc:  # noqa: BLE001
            logger.warning("PolicyCache listener stopped (%s)", exc)
        finally:
            try:
                await pubsub.unsubscribe(INVALIDATE_CHANNEL)
                await pubsub.aclose()
            except Exception:  # noqa: BLE001
                pass


# Module-level singleton. Not ideal for unit tests (they should construct
# their own), but matches how AuditQueue/metrics are used elsewhere.
_default_cache = PolicyCache()


def default_cache() -> PolicyCache:
    return _default_cache


# ── SQLAlchemy safety net ──────────────────────────────────────────────────
# If a code path writes a Policy row directly via the ORM (admin endpoints,
# tests, ad-hoc scripts) and forgets to call `invalidate()`, the ORM event
# here still evicts the local entry so the next read is fresh. Cross-replica
# invalidation still only happens when `invalidate()` is called explicitly —
# other replicas fall back to TTL expiry for direct-DB edits.
def _install_orm_hooks() -> None:
    from sqlalchemy import event

    from apex_pay.core.models import Policy

    def _after_flush(_mapper, _connection, target: Policy) -> None:
        try:
            _default_cache.invalidate_local(target.agent_id)
        except Exception:  # pragma: no cover
            pass

    event.listen(Policy, "after_update", _after_flush)
    event.listen(Policy, "after_insert", _after_flush)
    event.listen(Policy, "after_delete", _after_flush)


_install_orm_hooks()
