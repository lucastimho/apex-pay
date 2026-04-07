"""
Tests for Pydantic v2 request/response schemas.

Validates that the API boundary contracts enforce structural
correctness before any business logic runs.
"""

from __future__ import annotations

import uuid

import pytest
from pydantic import ValidationError

from apex_pay.core.schemas import (
    AgentCreate,
    GatewayResponse,
    PolicyCreate,
    PolicyDecision,
    SettlementRequest,
    ToolCallPayload,
)


# ── ToolCallPayload ─────────────────────────────────────────────────────────
class TestToolCallPayload:
    def test_valid_payload(self):
        p = ToolCallPayload(
            agent_id=uuid.uuid4(),
            tool_call={"function": "buy", "target_url": "https://api.stripe.com"},
        )
        assert p.tool_call["function"] == "buy"

    def test_missing_agent_id_fails(self):
        with pytest.raises(ValidationError):
            ToolCallPayload(tool_call={"function": "buy"})  # type: ignore

    def test_missing_tool_call_fails(self):
        with pytest.raises(ValidationError):
            ToolCallPayload(agent_id=uuid.uuid4())  # type: ignore

    def test_tool_call_must_have_function_or_target_url(self):
        with pytest.raises(ValidationError, match="target_url.*function"):
            ToolCallPayload(
                agent_id=uuid.uuid4(),
                tool_call={"parameters": {"amount": 5}},  # no function or target_url
            )

    def test_tool_call_with_only_function_is_valid(self):
        p = ToolCallPayload(
            agent_id=uuid.uuid4(),
            tool_call={"function": "list_items"},
        )
        assert p.tool_call["function"] == "list_items"

    def test_tool_call_with_only_target_url_is_valid(self):
        p = ToolCallPayload(
            agent_id=uuid.uuid4(),
            tool_call={"target_url": "https://api.example.com"},
        )
        assert "target_url" in p.tool_call

    def test_idempotency_key_max_length(self):
        with pytest.raises(ValidationError):
            ToolCallPayload(
                agent_id=uuid.uuid4(),
                tool_call={"function": "buy"},
                idempotency_key="x" * 200,  # exceeds 128
            )

    def test_string_stripping(self):
        p = ToolCallPayload(
            agent_id=uuid.uuid4(),
            tool_call={"function": "buy"},
            idempotency_key="  key-123  ",
        )
        assert p.idempotency_key == "key-123"


# ── PolicyDecision ──────────────────────────────────────────────────────────
class TestPolicyDecision:
    def test_approved(self):
        d = PolicyDecision(allowed=True, reason="policy_passed", projected_cost=10.0)
        assert d.allowed is True
        assert d.risk_score == 0.0

    def test_denied(self):
        d = PolicyDecision(
            allowed=False,
            reason="daily_budget_exceeded",
            projected_cost=50.0,
            risk_score=0.8,
        )
        assert d.allowed is False
        assert d.risk_score == 0.8


# ── SettlementRequest ───────────────────────────────────────────────────────
class TestSettlementRequest:
    def test_valid(self):
        s = SettlementRequest(ref_id="ref-001", amount=10.0)
        assert s.baseline == "payment_with_policy"

    def test_amount_must_be_positive(self):
        with pytest.raises(ValidationError):
            SettlementRequest(ref_id="ref-002", amount=0)

        with pytest.raises(ValidationError):
            SettlementRequest(ref_id="ref-003", amount=-5.0)

    def test_ref_id_required(self):
        with pytest.raises(ValidationError):
            SettlementRequest(amount=10.0)  # type: ignore

    def test_ref_id_max_length(self):
        with pytest.raises(ValidationError):
            SettlementRequest(ref_id="x" * 300, amount=10.0)


# ── GatewayResponse ─────────────────────────────────────────────────────────
class TestGatewayResponse:
    def test_approved_response(self):
        r = GatewayResponse(
            request_id=uuid.uuid4(),
            allowed=True,
            status="APPROVED",
            reason="policy_passed",
            latency_ms=12.5,
        )
        assert r.status == "APPROVED"
        assert r.transaction_id is None

    def test_denied_response(self):
        r = GatewayResponse(
            request_id=uuid.uuid4(),
            allowed=False,
            status="DENIED",
            reason="daily_budget_exceeded",
        )
        assert r.allowed is False


# ── AgentCreate ─────────────────────────────────────────────────────────────
class TestAgentCreate:
    def test_valid(self):
        a = AgentCreate(name="bot-1", public_key="ssh-rsa AAAA...")
        assert a.initial_balance == 0.0

    def test_empty_name_fails(self):
        with pytest.raises(ValidationError):
            AgentCreate(name="", public_key="key")

    def test_negative_balance_fails(self):
        with pytest.raises(ValidationError):
            AgentCreate(name="bot-2", public_key="key", initial_balance=-10)


# ── PolicyCreate ────────────────────────────────────────────────────────────
class TestPolicyCreate:
    def test_valid(self):
        p = PolicyCreate(
            agent_id=uuid.uuid4(),
            max_per_transaction=25.0,
            daily_limit=500.0,
            allowed_domains=["api.stripe.com"],
        )
        assert p.allowed_domains == ["api.stripe.com"]

    def test_zero_limits_fail(self):
        with pytest.raises(ValidationError):
            PolicyCreate(
                agent_id=uuid.uuid4(),
                max_per_transaction=0,
                daily_limit=100.0,
            )

        with pytest.raises(ValidationError):
            PolicyCreate(
                agent_id=uuid.uuid4(),
                max_per_transaction=10.0,
                daily_limit=0,
            )

    def test_defaults(self):
        p = PolicyCreate(agent_id=uuid.uuid4())
        assert p.max_per_transaction == 10.0
        assert p.daily_limit == 100.0
        assert p.allowed_domains == []
