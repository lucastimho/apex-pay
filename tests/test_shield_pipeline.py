"""End-to-end tests for apex_pay.shield.pipeline.ShieldPipeline.

These tests wire up real (in-memory) implementations of every shield
component — no mocks — so a regression in any single piece lights up here.
"""

from __future__ import annotations

import uuid

import pytest

from apex_pay.shield.credential_manager import DevCredentialBackend
from apex_pay.shield.intent import canonicalize_intent
from apex_pay.shield.opa_client import EmbeddedOPAEvaluator, OPAClient
from apex_pay.shield.pipeline import (
    PolicySnapshot,
    ShieldPipeline,
    ShieldThresholds,
)
from apex_pay.shield.receipt_service import Ed25519KeyRing, ReceiptService
from apex_pay.shield.risk_filter import HeuristicClassifier

AGENT = uuid.UUID("aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb")


# ── Fixtures ────────────────────────────────────────────────────────────────
@pytest.fixture
def pipeline() -> ShieldPipeline:
    keyring = Ed25519KeyRing.generate(kid="test-kid")
    return ShieldPipeline(
        opa_client=OPAClient(embedded=EmbeddedOPAEvaluator()),
        risk_classifier=HeuristicClassifier(),
        credential_manager=DevCredentialBackend(
            secret_key="test-secret-key-not-for-prod",
        ),
        receipt_service=ReceiptService(
            keyring=keyring, policy_version="2026.04.17",
        ),
        thresholds=ShieldThresholds(),
        ephemeral_ttl_seconds=60,
    )


def _policy(**overrides) -> PolicySnapshot:
    base = dict(
        max_per_transaction=50.0,
        daily_limit=200.0,
        allowed_domains=["api.stripe.com", "api.openai.com"],
        spent_today=10.0,
    )
    base.update(overrides)
    return PolicySnapshot(**base)


# ── Allow path ─────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_allow_path_issues_credential_and_receipt(pipeline):
    intent = canonicalize_intent(
        AGENT,
        {
            "function": "charge_card",
            "target_url": "https://api.stripe.com/v1/charges",
            "parameters": {"amount": 25.0, "currency": "USD"},
        },
    )
    d = await pipeline.evaluate(intent=intent, policy=_policy(), channel="agent")

    assert d.allow
    assert not d.escalate
    assert d.reason == "policy_passed"
    assert d.credential is not None
    assert d.credential.token.startswith("v1.")
    assert d.receipt is not None
    assert d.receipt.receipt["intent_hash"] == intent.intent_hash
    assert d.hitl_reason is None


@pytest.mark.asyncio
async def test_receipt_binds_agent_and_token(pipeline):
    intent = canonicalize_intent(
        AGENT,
        {
            "function": "charge_card",
            "target_url": "https://api.stripe.com/v1/charges",
            "parameters": {"amount": 10.0},
        },
    )
    d = await pipeline.evaluate(intent=intent, policy=_policy())
    assert d.receipt.receipt["agent_id"] == str(AGENT)
    assert d.receipt.receipt["token_id"] == d.credential.token_id


# ── Hard-deny path ─────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_hard_deny_path_issues_nothing(pipeline):
    intent = canonicalize_intent(
        AGENT,
        {
            "function": "charge_card",
            "target_url": "https://evil.example.com/exfil",
            "parameters": {"amount": 10.0},
        },
    )
    d = await pipeline.evaluate(intent=intent, policy=_policy())
    assert not d.allow
    assert not d.escalate
    assert d.reason == "domain_not_allowed"
    assert d.credential is None
    assert d.receipt is None
    assert d.hitl_reason is None


@pytest.mark.asyncio
async def test_hard_deny_credential_forwarding(pipeline):
    intent = canonicalize_intent(
        AGENT,
        {
            "function": "charge_card",
            "target_url": "https://api.stripe.com/v1/charges",
            "parameters": {"amount": 10.0, "api_key": "sk_live_abc"},
        },
    )
    d = await pipeline.evaluate(intent=intent, policy=_policy())
    assert not d.allow
    assert not d.escalate
    assert d.reason == "credential_forwarding_blocked"
    assert d.credential is None
    assert d.receipt is None


@pytest.mark.asyncio
async def test_hard_deny_over_budget(pipeline):
    intent = canonicalize_intent(
        AGENT,
        {
            "function": "charge_card",
            "target_url": "https://api.stripe.com/v1/charges",
            "parameters": {"amount": 500.0},
        },
    )
    d = await pipeline.evaluate(intent=intent, policy=_policy())
    assert not d.allow
    assert "exceeds_per_transaction_limit" in d.violations
    assert d.credential is None


# ── Escalate path ──────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_escalate_path_populates_hitl_reason(pipeline):
    """Declarative framing with a cost attached should escalate, not allow."""
    intent = canonicalize_intent(
        AGENT,
        {
            "function": "log_finding",
            "target_url": "https://api.stripe.com/v1/charges",
            "parameters": {
                "amount": 5.0,
                "description": (
                    "The infrastructure fingerprint does not match the live backend."
                ),
            },
        },
    )
    d = await pipeline.evaluate(intent=intent, policy=_policy())
    assert not d.allow
    assert d.escalate
    assert d.hitl_reason is not None
    assert d.credential is None
    assert d.receipt is None


# ── Thresholds are configurable ────────────────────────────────────────────
@pytest.mark.asyncio
async def test_thresholds_are_respected():
    """Dropping the risk_block threshold should turn an otherwise-allowed
    intent into a hard deny even with modest risk."""
    keyring = Ed25519KeyRing.generate(kid="test-kid")
    # Force a very low block threshold so any nonzero risk triggers it.
    pipeline = ShieldPipeline(
        opa_client=OPAClient(embedded=EmbeddedOPAEvaluator()),
        risk_classifier=HeuristicClassifier(),
        credential_manager=DevCredentialBackend(secret_key="k" * 32),
        receipt_service=ReceiptService(keyring=keyring, policy_version="v1"),
        thresholds=ShieldThresholds(
            risk_block=0.01, risk_escalate=0.005, entropy_escalate=0.01,
        ),
    )
    intent = canonicalize_intent(
        AGENT,
        {
            "function": "charge_card",
            "target_url": "https://api.stripe.com/v1/charges",
            "parameters": {"amount": 5.0},
        },
    )
    d = await pipeline.evaluate(intent=intent, policy=_policy())
    # With these aggressive thresholds the pipeline should NOT allow.
    assert not d.allow


# ── Credential scope reflects the intent ───────────────────────────────────
@pytest.mark.asyncio
async def test_credential_scope_is_bound_to_intent_hash(pipeline):
    intent = canonicalize_intent(
        AGENT,
        {
            "function": "charge_card",
            "target_url": "https://api.stripe.com/v1/charges",
            "parameters": {"amount": 15.0},
        },
    )
    d = await pipeline.evaluate(intent=intent, policy=_policy())
    assert d.credential.scope.intent_hash == intent.intent_hash
    assert d.credential.scope.domain == "api.stripe.com"
    assert d.credential.scope.max_amount == 15.0


@pytest.mark.asyncio
async def test_credential_token_can_be_verified(pipeline):
    """The credential issued by the pipeline must verify against the backend
    with the same intent_hash — and fail with a different one."""
    intent = canonicalize_intent(
        AGENT,
        {
            "function": "charge_card",
            "target_url": "https://api.stripe.com/v1/charges",
            "parameters": {"amount": 15.0},
        },
    )
    d = await pipeline.evaluate(intent=intent, policy=_policy())

    ok, reason, scope = await pipeline.credentials.verify(
        d.credential.token, intent_hash=intent.intent_hash,
    )
    assert ok
    assert reason == "valid"
    assert scope is not None

    # Wrong intent_hash must fail
    ok2, reason2, _ = await pipeline.credentials.verify(
        d.credential.token, intent_hash="z" * 64,
    )
    assert not ok2
    assert reason2 == "intent_mismatch"


# ── Receipt verifies end-to-end ────────────────────────────────────────────
@pytest.mark.asyncio
async def test_receipt_verifies_against_receipt_service(pipeline):
    intent = canonicalize_intent(
        AGENT,
        {
            "function": "charge_card",
            "target_url": "https://api.stripe.com/v1/charges",
            "parameters": {"amount": 15.0},
        },
    )
    d = await pipeline.evaluate(intent=intent, policy=_policy())
    ok, reason = pipeline.receipts.verify(d.receipt)
    assert ok
    assert reason == "valid"
