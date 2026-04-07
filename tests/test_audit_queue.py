"""
Tests for the in-memory FakeAuditQueue (used by all other tests)
and for the AuditQueue interface contract.
"""

from __future__ import annotations

import uuid

import pytest

from tests.conftest import FakeAuditQueue


@pytest.fixture
def queue() -> FakeAuditQueue:
    return FakeAuditQueue()


class TestFakeAuditQueue:
    @pytest.mark.asyncio
    async def test_push_and_pop(self, queue: FakeAuditQueue):
        await queue.push(
            agent_id=uuid.uuid4(),
            raw_intent={"function": "test"},
            projected_cost=10.0,
            action_domain="api.stripe.com",
            risk_score=0.0,
            status="APPROVED",
            denial_reason=None,
        )
        assert await queue.depth() == 1

        record = await queue.pop()
        assert record is not None
        assert record["status"] == "APPROVED"
        assert await queue.depth() == 0

    @pytest.mark.asyncio
    async def test_pop_empty_returns_none(self, queue: FakeAuditQueue):
        assert await queue.pop() is None

    @pytest.mark.asyncio
    async def test_saturation_flag(self, queue: FakeAuditQueue):
        assert await queue.is_saturated() is False
        queue._saturated = True
        assert await queue.is_saturated() is True

    @pytest.mark.asyncio
    async def test_fifo_ordering(self, queue: FakeAuditQueue):
        for i in range(3):
            await queue.push(
                agent_id=uuid.uuid4(),
                raw_intent={"seq": i},
                projected_cost=float(i),
                action_domain=None,
                risk_score=0.0,
                status="DENIED",
                denial_reason="test",
            )

        r0 = await queue.pop()
        r1 = await queue.pop()
        r2 = await queue.pop()
        assert r0["raw_intent"]["seq"] == 0
        assert r1["raw_intent"]["seq"] == 1
        assert r2["raw_intent"]["seq"] == 2

    @pytest.mark.asyncio
    async def test_depth_tracking(self, queue: FakeAuditQueue):
        assert await queue.depth() == 0
        for _ in range(5):
            await queue.push(
                agent_id=uuid.uuid4(),
                raw_intent={},
                projected_cost=1.0,
                action_domain=None,
                risk_score=0.0,
                status="APPROVED",
                denial_reason=None,
            )
        assert await queue.depth() == 5
        await queue.pop()
        assert await queue.depth() == 4
