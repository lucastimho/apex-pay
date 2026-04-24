"""Semantic (dollar-spend) rate limiter with a Redis sliding window.

Blueprint §2.C — "Semantic Rate Limiting & Back Pressure"
---------------------------------------------------------
Prevents agentic loops from draining accounts. We throttle by cumulative
dollar spend per agent over a rolling window (default 1 hour / $100). If
adding the new intent would push the window total past the ceiling, the
gateway returns **503** with a `Retry-After` header computed from the
earliest entry in the window.

Why this and not just request-count limiting
--------------------------------------------
A compromised agent that keeps every request under the per-transaction
cap can still drain the budget. SlowAPI already caps request frequency;
this limiter caps the BLAST RADIUS of a burst that slips through.

Atomicity
---------
A naïve "check then record" has a race: two concurrent requests can both
read the same under-limit state and both record, blowing past the cap by
the sum of their amounts. We close this with a single Lua script that
does the age-out, sum, check, and ZADD in one atomic Redis round-trip.

Fail-closed on Redis outage
---------------------------
If Redis is unreachable, `check_and_record` raises. The gateway turns
that into a 503 rather than silently allowing spend. Rate limiting is
fundamentally a safety feature; degrading open would defeat the point.

Units
-----
Amounts are stored as **integer cents** in Redis. Floats never cross the
Redis boundary — the Python side converts Decimal → cents on the way in
and back on the way out. Prevents accumulation error over long windows.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from decimal import Decimal
from typing import Any

import redis.asyncio as aioredis

logger = logging.getLogger("apex_pay.semantic_rate_limiter")


# ── Lua script ──────────────────────────────────────────────────────────────
# Sorted-set sliding window. Each member is "<now_ms>:<uuid>:<cents>".
# Score = now_ms, so ZREMRANGEBYSCORE can expire entries atomically.
#
# Returns {allowed_int, current_spend_cents, window_earliest_ms}.
# allowed_int is 1 on accept, 0 on reject.
# window_earliest_ms is 0 when the window is empty.
_LUA_CHECK_AND_RECORD = """
local key          = KEYS[1]
local now_ms       = tonumber(ARGV[1])
local window_ms    = tonumber(ARGV[2])
local limit_cents  = tonumber(ARGV[3])
local amount_cents = tonumber(ARGV[4])
local request_id   = ARGV[5]

-- Age out anything older than the window.
redis.call('ZREMRANGEBYSCORE', key, 0, now_ms - window_ms)

-- Sum remaining. Member format: "<timestamp>:<uuid>:<cents>".
local members = redis.call('ZRANGE', key, 0, -1)
local current = 0
for i = 1, #members do
    local colon2 = 0
    local _, _, amt_str = string.find(members[i], ':[^:]+:(%d+)$')
    if amt_str then current = current + tonumber(amt_str) end
end

local earliest_ms = 0
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
if #oldest >= 2 then earliest_ms = tonumber(oldest[2]) end

if current + amount_cents > limit_cents then
    return {0, current, earliest_ms}
end

local member = now_ms .. ':' .. request_id .. ':' .. amount_cents
redis.call('ZADD', key, now_ms, member)
-- Extra second so a single in-flight entry doesn't vanish mid-window.
redis.call('PEXPIRE', key, window_ms + 1000)
return {1, current + amount_cents, earliest_ms}
"""


# ── Result ──────────────────────────────────────────────────────────────────
@dataclass
class RateLimitResult:
    allowed: bool
    current_spend_cents: int
    limit_cents: int
    window_ms: int
    retry_after_seconds: int  # 0 when allowed

    @property
    def current_spend_usd(self) -> Decimal:
        return Decimal(self.current_spend_cents) / Decimal(100)

    @property
    def limit_usd(self) -> Decimal:
        return Decimal(self.limit_cents) / Decimal(100)


# ── The limiter ─────────────────────────────────────────────────────────────
class SemanticRateLimiter:
    """Atomic dollar-spend sliding window."""

    def __init__(
        self,
        *,
        redis_url: str | None = None,
        redis_client: aioredis.Redis | None = None,
        window_seconds: int = 3600,
        default_limit_cents: int = 10_000,     # $100.00
        key_prefix: str = "apex:ratelimit:semantic:",
    ) -> None:
        if redis_client is None and redis_url is None:
            raise ValueError("Need redis_url or redis_client")
        self._redis_url = redis_url
        self._redis: aioredis.Redis | None = redis_client
        self._window_ms = int(window_seconds) * 1000
        self._default_limit_cents = int(default_limit_cents)
        self._prefix = key_prefix
        self._script: Any = None

    async def connect(self) -> None:
        if self._redis is None:
            self._redis = aioredis.from_url(self._redis_url, decode_responses=True)
        # register_script() returns a callable that uses EVALSHA + fallback.
        self._script = self._redis.register_script(_LUA_CHECK_AND_RECORD)

    async def close(self) -> None:
        if self._redis is not None:
            try:
                await self._redis.aclose()
            finally:
                self._redis = None

    def _key(self, agent_id: str) -> str:
        return f"{self._prefix}{agent_id}"

    async def check_and_record(
        self,
        *,
        agent_id: str,
        amount: Decimal,
        limit_cents: int | None = None,
    ) -> RateLimitResult:
        """Atomically check if `amount` fits and record it if it does.

        Raises `ConnectionError` on Redis unavailability — caller should
        convert to 503 (fail-closed).
        """
        if self._redis is None or self._script is None:
            raise ConnectionError("SemanticRateLimiter not connected to Redis")

        limit = int(limit_cents if limit_cents is not None else self._default_limit_cents)
        # Decimal → int cents. Round half-up so sub-cent amounts don't go free.
        cents = int((amount * 100).to_integral_value(rounding="ROUND_HALF_UP"))
        if cents < 0:
            raise ValueError("amount must be >= 0")
        now_ms = int(time.time() * 1000)
        request_id = uuid.uuid4().hex

        try:
            raw = await self._script(
                keys=[self._key(agent_id)],
                args=[now_ms, self._window_ms, limit, cents, request_id],
            )
        except aioredis.RedisError as exc:
            raise ConnectionError(f"Semantic rate limiter Redis error: {exc}") from exc

        allowed_int, current, earliest_ms = (int(raw[0]), int(raw[1]), int(raw[2]))
        allowed = bool(allowed_int)
        retry_after = 0
        if not allowed and earliest_ms > 0:
            # When the oldest entry ages out, `amount` might fit. Retry then.
            retry_after = max(1, ((earliest_ms + self._window_ms) - now_ms + 999) // 1000)
        return RateLimitResult(
            allowed=allowed,
            current_spend_cents=current,
            limit_cents=limit,
            window_ms=self._window_ms,
            retry_after_seconds=retry_after,
        )

    async def current_spend(self, agent_id: str) -> Decimal:
        """Introspection only — returns the current window spend in USD.

        Not atomic with `check_and_record`; use only for dashboards/metrics.
        """
        if self._redis is None:
            raise ConnectionError("SemanticRateLimiter not connected to Redis")
        now_ms = int(time.time() * 1000)
        await self._redis.zremrangebyscore(
            self._key(agent_id), 0, now_ms - self._window_ms,
        )
        members = await self._redis.zrange(self._key(agent_id), 0, -1)
        total = 0
        for m in members:
            try:
                total += int(m.rsplit(":", 1)[-1])
            except (ValueError, IndexError):
                continue
        return Decimal(total) / Decimal(100)


# ── Module singleton ────────────────────────────────────────────────────────

_default_limiter: SemanticRateLimiter | None = None


def default_limiter() -> SemanticRateLimiter | None:
    return _default_limiter


def set_default_limiter(limiter: SemanticRateLimiter | None) -> None:
    global _default_limiter
    _default_limiter = limiter
