"""
Tests for the Policy Enforcement Engine.

Covers all three policy gates from the APEX paper:
    1. Domain allowlist check
    2. Per-transaction cap  (a ≤ M)
    3. Daily budget ceiling (Σ c_i ≤ B_d)

Also tests edge cases: missing agent, suspended agent, no policy,
empty allowlist, missing cost field, and cumulative daily spend.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession

from apex_pay.core.models import Agent, AuditLog, Policy
from apex_pay.core.schemas import ToolCallPayload
from apex_pay.services.policy_engine import PolicyEngine
from tests.conftest import TEST_AGENT_ID

engine = PolicyEngine()


# ── Helper ──────────────────────────────────────────────────────────────────
def _payload(
    agent_id=TEST_AGENT_ID,
    amount=10.0,
    target_url="https://api.stripe.com/v1/charges",
    function="charge_card",
) -> ToolCallPayload:
    tc = {"function": function, "target_url": target_url, "parameters": {"amount": amount}}
    return ToolCallPayload(agent_id=agent_id, tool_call=tc)


# ── Happy Path ──────────────────────────────────────────────────────────────
class TestApproval:
    @pytest.mark.asyncio
    async def test_valid_request_approved(self, seeded_session: AsyncSession):
        decision = await engine.evaluate(_payload(amount=25.0), seeded_session)
        assert decision.allowed is True
        assert decision.reason == "policy_passed"
        assert decision.projected_cost == 25.0
        assert decision.action_domain == "api.stripe.com"

    @pytest.mark.asyncio
    async def test_exact_max_per_transaction(self, seeded_session: AsyncSession):
        """amount == max_per_transaction (50.0) should be allowed."""
        decision = await engine.evaluate(_payload(amount=50.0), seeded_session)
        assert decision.allowed is True


# ── Domain Allowlist ────────────────────────────────────────────────────────
class TestDomainAllowlist:
    @pytest.mark.asyncio
    async def test_blocked_domain(self, seeded_session: AsyncSession):
        decision = await engine.evaluate(
            _payload(target_url="https://evil.example.com/steal"),
            seeded_session,
        )
        assert decision.allowed is False
        assert decision.reason == "domain_not_allowed"

    @pytest.mark.asyncio
    async def test_allowed_domain(self, seeded_session: AsyncSession):
        decision = await engine.evaluate(
            _payload(target_url="https://api.openai.com/v1/chat"),
            seeded_session,
        )
        assert decision.allowed is True

    @pytest.mark.asyncio
    async def test_no_target_url_passes_domain_check(self, seeded_session: AsyncSession):
        """A tool_call without a target_url is an internal call — allowed."""
        payload = ToolCallPayload(
            agent_id=TEST_AGENT_ID,
            tool_call={"function": "internal_lookup", "parameters": {"amount": 5.0}},
        )
        decision = await engine.evaluate(payload, seeded_session)
        assert decision.allowed is True

    @pytest.mark.asyncio
    async def test_empty_allowlist_permits_all(self, seeded_session: AsyncSession):
        """If allowed_domains is empty, all domains should be permitted."""
        from sqlalchemy import select

        result = await seeded_session.execute(
            select(Policy).where(Policy.agent_id == TEST_AGENT_ID)
        )
        policy = result.scalar_one()
        policy.allowed_domains = []
        await seeded_session.commit()

        decision = await engine.evaluate(
            _payload(target_url="https://any.domain.com/api"),
            seeded_session,
        )
        assert decision.allowed is True


# ── Per-Transaction Cap ─────────────────────────────────────────────────────
class TestPerTransactionCap:
    @pytest.mark.asyncio
    async def test_over_limit_denied(self, seeded_session: AsyncSession):
        """max_per_transaction is 50.0 — a $75 request should be denied."""
        decision = await engine.evaluate(_payload(amount=75.0), seeded_session)
        assert decision.allowed is False
        assert decision.reason == "exceeds_per_transaction_limit"

    @pytest.mark.asyncio
    async def test_just_over_limit(self, seeded_session: AsyncSession):
        decision = await engine.evaluate(_payload(amount=50.01), seeded_session)
        assert decision.allowed is False
        assert decision.reason == "exceeds_per_transaction_limit"


# ── Daily Budget ────────────────────────────────────────────────────────────
class TestDailyBudget:
    @pytest.mark.asyncio
    async def test_cumulative_spend_exceeds_daily_limit(self, seeded_session: AsyncSession):
        """Seed $180 of approved spend, then a $25 request should bust the $200 limit."""
        # Insert approved audit logs to simulate prior spend
        for i in range(6):
            seeded_session.add(
                AuditLog(
                    agent_id=TEST_AGENT_ID,
                    raw_intent={"function": "prior_charge", "parameters": {"amount": 30.0}},
                    projected_cost=30.0,
                    status="APPROVED",
                    created_at=datetime.now(timezone.utc),
                )
            )
        await seeded_session.commit()  # 6 × $30 = $180 spent

        decision = await engine.evaluate(_payload(amount=25.0), seeded_session)
        assert decision.allowed is False
        assert "daily_budget_exceeded" in decision.reason

    @pytest.mark.asyncio
    async def test_under_daily_limit_with_prior_spend(self, seeded_session: AsyncSession):
        """$100 prior spend + $25 request = $125, under $200 limit."""
        for i in range(5):
            seeded_session.add(
                AuditLog(
                    agent_id=TEST_AGENT_ID,
                    raw_intent={"function": "prior", "parameters": {"amount": 20.0}},
                    projected_cost=20.0,
                    status="APPROVED",
                    created_at=datetime.now(timezone.utc),
                )
            )
        await seeded_session.commit()  # 5 × $20 = $100

        decision = await engine.evaluate(_payload(amount=25.0), seeded_session)
        assert decision.allowed is True

    @pytest.mark.asyncio
    async def test_denied_transactions_dont_count(self, seeded_session: AsyncSession):
        """DENIED audit records should NOT count toward daily spend."""
        for i in range(10):
            seeded_session.add(
                AuditLog(
                    agent_id=TEST_AGENT_ID,
                    raw_intent={"function": "denied", "parameters": {"amount": 50.0}},
                    projected_cost=50.0,
                    status="DENIED",
                    denial_reason="testing",
                    created_at=datetime.now(timezone.utc),
                )
            )
        await seeded_session.commit()

        decision = await engine.evaluate(_payload(amount=10.0), seeded_session)
        assert decision.allowed is True  # $0 approved + $10 request < $200


# ── Agent Status ────────────────────────────────────────────────────────────
class TestAgentStatus:
    @pytest.mark.asyncio
    async def test_unknown_agent_denied(self, seeded_session: AsyncSession):
        fake_id = uuid.UUID("deadbeef-dead-beef-dead-beefdeadbeef")
        decision = await engine.evaluate(_payload(agent_id=fake_id), seeded_session)
        assert decision.allowed is False
        assert decision.reason == "agent_not_found"

    @pytest.mark.asyncio
    async def test_suspended_agent_denied(self, seeded_session: AsyncSession):
        from sqlalchemy import select

        result = await seeded_session.execute(
            select(Agent).where(Agent.id == TEST_AGENT_ID)
        )
        agent = result.scalar_one()
        agent.status = "suspended"
        await seeded_session.commit()

        decision = await engine.evaluate(_payload(), seeded_session)
        assert decision.allowed is False
        assert decision.reason == "agent_suspended"

    @pytest.mark.asyncio
    async def test_no_active_policy_denied(self, seeded_session: AsyncSession):
        from sqlalchemy import select

        result = await seeded_session.execute(
            select(Policy).where(Policy.agent_id == TEST_AGENT_ID)
        )
        policy = result.scalar_one()
        policy.is_active = False
        await seeded_session.commit()

        decision = await engine.evaluate(_payload(), seeded_session)
        assert decision.allowed is False
        assert decision.reason == "no_active_policy"


# ── Cost Extraction ─────────────────────────────────────────────────────────
class TestCostExtraction:
    @pytest.mark.asyncio
    async def test_no_cost_field_still_approved(self, seeded_session: AsyncSession):
        """A tool_call with no amount/cost/price should still pass if domain is OK."""
        payload = ToolCallPayload(
            agent_id=TEST_AGENT_ID,
            tool_call={
                "function": "list_files",
                "target_url": "https://api.stripe.com/v1/files",
                "parameters": {"limit": 10},
            },
        )
        decision = await engine.evaluate(payload, seeded_session)
        assert decision.allowed is True
        assert decision.projected_cost is None

    @pytest.mark.asyncio
    async def test_alternate_cost_keys(self, seeded_session: AsyncSession):
        """Engine should recognize 'price' and 'cost' in addition to 'amount'."""
        for key in ("price", "cost", "projected_cost"):
            payload = ToolCallPayload(
                agent_id=TEST_AGENT_ID,
                tool_call={
                    "function": "buy",
                    "target_url": "https://api.stripe.com/v1/charges",
                    "parameters": {key: 15.0},
                },
            )
            decision = await engine.evaluate(payload, seeded_session)
            assert decision.projected_cost == 15.0, f"Failed for cost key '{key}'"


# ── Policy Snapshot ─────────────────────────────────────────────────────────
class TestPolicySnapshot:
    @pytest.mark.asyncio
    async def test_snapshot_included_in_decision(self, seeded_session: AsyncSession):
        decision = await engine.evaluate(_payload(amount=10.0), seeded_session)
        snap = decision.policy_snapshot

        assert snap is not None
        assert snap["max_per_transaction"] == 50.0
        assert snap["daily_limit"] == 200.0
        assert "api.stripe.com" in snap["allowed_domains"]
