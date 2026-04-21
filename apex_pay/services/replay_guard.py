"""Nonce + timestamp replay guard.

Blueprint §5.1 and §12: a signed request replayed later still has a valid
signature. Defense is a two-part freshness check:

  1. `issued_at` must be within ±`nonce_ttl_seconds` of the server clock.
  2. `(agent_id, nonce)` must be unseen within the TTL window.

Nonce storage is Redis with a TTL equal to the replay window. `SET NX` is
the atomic "claim this nonce or fail" primitive — no race between check
and insert. If Redis is unavailable we fail CLOSED (reject), because the
whole point is to prevent replay; degrading open would defeat the feature.

This module is deliberately decoupled from FastAPI — it takes raw fields
and returns a verdict so it can be unit tested without a request context.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Literal

import redis.asyncio as aioredis

logger = logging.getLogger("apex_pay.replay_guard")


ReplayVerdict = Literal["ok", "nonce_reused", "timestamp_out_of_window", "unavailable"]


@dataclass
class ReplayCheckResult:
    verdict: ReplayVerdict
    reason: str


class ReplayGuard:
    """Redis-backed nonce store with a moving TTL window."""

    def __init__(self, *, ttl_seconds: int, redis_client: aioredis.Redis | None = None) -> None:
        self._ttl = int(ttl_seconds)
        self._redis = redis_client
        self._key_prefix = "apex:nonce:"

    async def connect(self, url: str) -> None:
        if self._redis is None:
            self._redis = aioredis.from_url(url, decode_responses=True)

    async def close(self) -> None:
        if self._redis is not None:
            try:
                await self._redis.aclose()
            finally:
                self._redis = None

    async def check(self, *, agent_id: str, nonce: str, issued_at: int) -> ReplayCheckResult:
        """Return ok, or a structured reason for rejection."""
        now = int(time.time())
        if abs(now - int(issued_at)) > self._ttl:
            return ReplayCheckResult(
                verdict="timestamp_out_of_window",
                reason=(
                    f"issued_at={issued_at} is outside ±{self._ttl}s of server "
                    f"time={now}"
                ),
            )

        if self._redis is None:
            # Fail-closed: no backing store means no replay protection.
            logger.warning("ReplayGuard called with no Redis client — rejecting.")
            return ReplayCheckResult(
                verdict="unavailable",
                reason="replay_guard_redis_unavailable",
            )

        key = f"{self._key_prefix}{agent_id}:{nonce}"
        try:
            claimed = await self._redis.set(key, str(now), ex=self._ttl, nx=True)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ReplayGuard Redis error (%s) — rejecting.", exc)
            return ReplayCheckResult(
                verdict="unavailable",
                reason="replay_guard_redis_error",
            )

        if not claimed:
            return ReplayCheckResult(verdict="nonce_reused", reason="nonce_replay_detected")
        return ReplayCheckResult(verdict="ok", reason="fresh")


_default_guard: ReplayGuard | None = None


def default_guard() -> ReplayGuard | None:
    return _default_guard


def set_default_guard(guard: ReplayGuard | None) -> None:
    global _default_guard
    _default_guard = guard
