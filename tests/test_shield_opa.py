"""Tests for apex_pay.shield.opa_client.EmbeddedOPAEvaluator.

The Rego file `policies/apex_test.rego` has matching tests — the fixtures
here are copies of the Rego `base_input`. If you change these fixtures,
update the Rego tests too.
"""

from __future__ import annotations

import copy

import pytest

from apex_pay.shield.opa_client import EmbeddedOPAEvaluator


def _base_input() -> dict:
    return {
        "intent": {
            "agent_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
            "function": "charge_card",
            "target_url": "https://api.stripe.com/v1/charges",
            "action_domain": "api.stripe.com",
            "parameters": {"amount": 25.0, "currency": "USD"},
            "projected_cost": 25.0,
            "intent_hash": "deadbeef",
            "speech_act": "imperative",
        },
        "policy": {
            "max_per_transaction": 50.0,
            "daily_limit": 200.0,
            "allowed_domains": ["api.stripe.com", "api.openai.com"],
            "spent_today": 47.50,
        },
        "risk": {"score": 0.1, "entropy": 0.2, "labels": ["benign"]},
        "thresholds": {
            "risk_block": 0.8, "risk_escalate": 0.4, "entropy_escalate": 0.65,
        },
        "policy_version": "2026.04.17",
    }


@pytest.fixture
def opa():
    return EmbeddedOPAEvaluator()


# ── Allow ──────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_allows_benign_request(opa):
    d = await opa.evaluate(_base_input())
    assert d.allow
    assert d.reason == "policy_passed"
    assert d.escalate is False


# ── Hard denies ────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_denies_domain_not_allowed(opa):
    inp = _base_input()
    inp["intent"]["target_url"] = "https://evil.example.com/exfil"
    inp["intent"]["action_domain"] = "evil.example.com"
    d = await opa.evaluate(inp)
    assert not d.allow
    assert d.reason == "domain_not_allowed"
    assert d.escalate is False


@pytest.mark.asyncio
async def test_denies_over_per_transaction_cap(opa):
    inp = _base_input()
    inp["intent"]["projected_cost"] = 100.0
    d = await opa.evaluate(inp)
    assert not d.allow
    assert "exceeds_per_transaction_limit" in d.violations


@pytest.mark.asyncio
async def test_denies_over_daily_limit(opa):
    inp = _base_input()
    inp["policy"]["spent_today"] = 190.0
    inp["intent"]["projected_cost"] = 20.0
    d = await opa.evaluate(inp)
    assert not d.allow
    assert "daily_budget_exceeded" in d.violations


@pytest.mark.asyncio
async def test_denies_credential_forwarding_via_key_name(opa):
    inp = _base_input()
    inp["intent"]["parameters"] = {"amount": 1.0, "api_key": "sk_live_abc123"}
    d = await opa.evaluate(inp)
    assert not d.allow
    assert d.reason == "credential_forwarding_blocked"


@pytest.mark.asyncio
async def test_denies_credential_forwarding_via_value_pattern(opa):
    inp = _base_input()
    inp["intent"]["parameters"] = {
        "amount": 1.0,
        "description": "Bearer abcdefghijklmnopqrstuvwxyz",
    }
    d = await opa.evaluate(inp)
    assert not d.allow
    assert d.reason == "credential_forwarding_blocked"


@pytest.mark.asyncio
async def test_denies_destructive_function(opa):
    inp = _base_input()
    inp["intent"]["function"] = "delete_account"
    d = await opa.evaluate(inp)
    assert not d.allow
    assert d.reason == "destructive_action_blocked"


@pytest.mark.asyncio
async def test_denies_destructive_admin_delete(opa):
    inp = _base_input()
    inp["intent"]["function"] = "do_thing"
    inp["intent"]["target_url"] = "https://api.example.com/admin/users/123"
    inp["intent"]["action_domain"] = "api.example.com"
    # OPA is evaluated against allowed_domains — add it for this test
    inp["policy"]["allowed_domains"].append("api.example.com")
    inp["intent"]["parameters"] = {"method": "DELETE"}
    d = await opa.evaluate(inp)
    assert not d.allow
    assert d.reason == "destructive_action_blocked"


@pytest.mark.asyncio
async def test_denies_risk_above_hard_block(opa):
    inp = _base_input()
    inp["risk"]["score"] = 0.95
    d = await opa.evaluate(inp)
    assert not d.allow
    assert "risk_above_hard_block" in d.violations


# ── Escalations ────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_escalates_on_high_entropy(opa):
    inp = _base_input()
    inp["risk"]["entropy"] = 0.8
    d = await opa.evaluate(inp)
    assert not d.allow
    assert d.escalate
    assert "risk_uncertainty_escalation" in d.violations


@pytest.mark.asyncio
async def test_escalates_on_moderate_risk(opa):
    inp = _base_input()
    inp["risk"]["score"] = 0.55
    d = await opa.evaluate(inp)
    assert not d.allow
    assert d.escalate
    assert "risk_moderate_escalation" in d.violations


@pytest.mark.asyncio
async def test_escalates_on_declarative_framing(opa):
    inp = _base_input()
    inp["intent"]["speech_act"] = "declarative"
    d = await opa.evaluate(inp)
    assert not d.allow
    assert d.escalate
    assert "declarative_framing_escalation" in d.violations


@pytest.mark.asyncio
async def test_hard_deny_beats_escalation(opa):
    """Violations take precedence over escalations — a bad domain still
    hard-denies even if risk/entropy would otherwise escalate."""
    inp = _base_input()
    inp["intent"]["target_url"] = "https://evil.example.com/x"
    inp["intent"]["action_domain"] = "evil.example.com"
    inp["intent"]["speech_act"] = "declarative"
    inp["risk"]["entropy"] = 0.9
    d = await opa.evaluate(inp)
    assert not d.allow
    assert not d.escalate
    assert d.reason == "domain_not_allowed"
