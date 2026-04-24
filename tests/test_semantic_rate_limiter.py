"""Tests for apex_pay.services.semantic_rate_limiter.SemanticRateLimiter.

We use fakeredis[lua] so these tests run fully in-process — no Redis
process needed. The Lua script runs on fakeredis's embedded Lua
interpreter, so we're exercising the real atomic flow, not a Python
re-implementation.
"""

from __future__ import annotations

import asyncio
from decimal import Decimal

import fakeredis.aioredis
import pytest

from apex_pay.services.semantic_rate_limiter import SemanticRateLimiter


@pytest.fixture
async def limiter():
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    rl = SemanticRateLimiter(
        redis_client=client,
        window_seconds=60,
        default_limit_cents=10_000,  # $100.00
    )
    await rl.connect()
    yield rl
    await client.aclose()


# ── Happy path ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_single_under_limit_allowed(limiter):
    r = await limiter.check_and_record(agent_id="a1", amount=Decimal("10.00"))
    assert r.allowed is True
    assert r.current_spend_cents == 1000
    assert r.retry_after_seconds == 0


@pytest.mark.asyncio
async def test_sum_up_to_but_not_over(limiter):
    # $99.99 should be allowed at the $100 ceiling.
    r1 = await limiter.check_and_record(agent_id="a1", amount=Decimal("99.99"))
    assert r1.allowed is True
    # One more cent — exactly at ceiling — still allowed.
    r2 = await limiter.check_and_record(agent_id="a1", amount=Decimal("0.01"))
    assert r2.allowed is True
    assert r2.current_spend_cents == 10_000


@pytest.mark.asyncio
async def test_over_limit_rejected_with_retry_after(limiter):
    await limiter.check_and_record(agent_id="a1", amount=Decimal("50.00"))
    r2 = await limiter.check_and_record(agent_id="a1", amount=Decimal("50.01"))
    assert r2.allowed is False
    assert r2.current_spend_cents == 5000         # unchanged on reject
    assert r2.retry_after_seconds > 0


# ── Atomicity (the race scenario the Lua script guards against) ─────────────


@pytest.mark.asyncio
async def test_concurrent_requests_respect_ceiling(limiter):
    """Fire 20 concurrent requests of $10 each at a $100 ceiling.
    At most 10 must succeed. No race allows the 11th through."""
    results = await asyncio.gather(*[
        limiter.check_and_record(agent_id="a1", amount=Decimal("10.00"))
        for _ in range(20)
    ])
    allowed = [r for r in results if r.allowed]
    rejected = [r for r in results if not r.allowed]
    assert len(allowed) == 10
    assert len(rejected) == 10
    # All allowed ones should sum to exactly the ceiling.
    assert allowed[-1].current_spend_cents == 10_000


@pytest.mark.asyncio
async def test_per_agent_isolation(limiter):
    """Two different agents each get their own window."""
    for _ in range(10):
        r = await limiter.check_and_record(agent_id="a1", amount=Decimal("10.00"))
        assert r.allowed
    # a1 is now at $100. a2 should still have the full budget.
    r_other = await limiter.check_and_record(agent_id="a2", amount=Decimal("50.00"))
    assert r_other.allowed
    assert r_other.current_spend_cents == 5000


# ── Window aging ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_window_aging_releases_budget():
    """Set a very short window and confirm entries age out."""
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    rl = SemanticRateLimiter(
        redis_client=client,
        window_seconds=1,
        default_limit_cents=10_000,
    )
    await rl.connect()
    try:
        r1 = await rl.check_and_record(agent_id="a1", amount=Decimal("100.00"))
        assert r1.allowed
        # Fill up — any more should reject.
        r2 = await rl.check_and_record(agent_id="a1", amount=Decimal("0.01"))
        assert not r2.allowed
        await asyncio.sleep(1.1)
        # After the window fully passes, budget is back.
        r3 = await rl.check_and_record(agent_id="a1", amount=Decimal("100.00"))
        assert r3.allowed
    finally:
        await client.aclose()


# ── Introspection ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_current_spend_reflects_records(limiter):
    assert (await limiter.current_spend("a1")) == Decimal("0")
    await limiter.check_and_record(agent_id="a1", amount=Decimal("7.50"))
    await limiter.check_and_record(agent_id="a1", amount=Decimal("2.50"))
    spend = await limiter.current_spend("a1")
    assert spend == Decimal("10.00")


# ── Edge cases ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_zero_amount_allowed_no_record(limiter):
    # Zero-amount checks are legitimate for probes / previews.
    r = await limiter.check_and_record(agent_id="a1", amount=Decimal("0"))
    assert r.allowed
    assert r.current_spend_cents == 0


@pytest.mark.asyncio
async def test_negative_amount_raises(limiter):
    with pytest.raises(ValueError, match=">= 0"):
        await limiter.check_and_record(agent_id="a1", amount=Decimal("-1.00"))


@pytest.mark.asyncio
async def test_sub_cent_rounding(limiter):
    """$0.005 rounds to 1 cent (half-up), not to 0."""
    r = await limiter.check_and_record(agent_id="a1", amount=Decimal("0.005"))
    assert r.allowed
    assert r.current_spend_cents == 1


@pytest.mark.asyncio
async def test_custom_limit_per_request(limiter):
    """Caller can pass a tighter limit than the default for VIP tiers."""
    r = await limiter.check_and_record(
        agent_id="a1", amount=Decimal("10.00"), limit_cents=500,
    )
    assert not r.allowed


# ── Fail-closed on disconnect ───────────────────────────────────────────────


@pytest.mark.asyncio
async def test_fails_closed_if_not_connected():
    rl = SemanticRateLimiter(
        redis_client=fakeredis.aioredis.FakeRedis(),
        window_seconds=60,
        default_limit_cents=10_000,
    )
    # NOT connected — _script is None.
    with pytest.raises(ConnectionError):
        await rl.check_and_record(agent_id="a1", amount=Decimal("1.00"))
