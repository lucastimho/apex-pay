"""End-to-end test: financial_action_hash flows from sanitizer → audit row.

Uses the same test harness as test_gateway_endpoints.py — in-memory
SQLite + FakeAuditQueue — so we can assert the exact push arguments
the gateway made.
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from apex_pay.core.models import Agent, Base, Policy
from apex_pay.shield.financial_action import FinancialAction
from tests.conftest import TEST_AGENT_ID, TEST_AGENT_NAME, TEST_PUBLIC_KEY


async def _seed(db_engine):
    Session = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as s:
        s.add(Agent(
            id=TEST_AGENT_ID,
            name=TEST_AGENT_NAME,
            public_key=TEST_PUBLIC_KEY,
            current_balance=500.0,
            status="active",
        ))
        s.add(Policy(
            agent_id=TEST_AGENT_ID,
            max_per_transaction=50.0,
            daily_limit=200.0,
            allowed_domains=["api.stripe.com", "api.openai.com"],
            is_active=True,
        ))
        await s.commit()


@pytest.mark.asyncio
async def test_audit_push_includes_financial_action_hash(
    db_engine, client: AsyncClient, fake_audit_queue,
):
    """A valid monetary intent produces an audit record whose
    financial_action_hash equals FinancialAction.content_hash()."""
    await _seed(db_engine)

    tool_call = {
        "action_type": "charge",
        "amount": 25.00,
        "currency": "USD",
        "target_domain": "api.stripe.com",
        "target_url": "https://api.stripe.com/v1/charges",
        "idempotency_key": "req_hash_test_01",
    }
    # Compute the expected hash at the test's boundary so we're verifying
    # the exact field flows from sanitiser → audit row.
    expected = FinancialAction.from_tool_call(tool_call).content_hash()

    resp = await client.post(
        "/execute",
        json={
            "agent_id": str(TEST_AGENT_ID),
            "tool_call": tool_call,
        },
    )
    assert resp.status_code == 200, resp.text

    # Exactly one record pushed for this request.
    assert len(fake_audit_queue.records) == 1
    record = fake_audit_queue.records[-1]
    assert record["financial_action_hash"] == expected


@pytest.mark.asyncio
async def test_audit_push_financial_hash_is_none_for_non_monetary(
    db_engine, client: AsyncClient, fake_audit_queue,
):
    """A non-monetary call leaves financial_action_hash as None."""
    await _seed(db_engine)
    resp = await client.post(
        "/execute",
        json={
            "agent_id": str(TEST_AGENT_ID),
            "tool_call": {"function": "get_balance"},
        },
    )
    assert resp.status_code == 200
    assert len(fake_audit_queue.records) == 1
    record = fake_audit_queue.records[-1]
    assert record["financial_action_hash"] is None


@pytest.mark.asyncio
async def test_audit_hash_stable_across_equivalent_intents(
    db_engine, client: AsyncClient, fake_audit_queue,
):
    """Two different tool_call shapes that describe the same FinancialAction
    produce the same financial_action_hash (content-addressable property)."""
    await _seed(db_engine)

    flat = {
        "action_type": "charge",
        "amount": 25.00,
        "currency": "USD",
        "target_domain": "api.stripe.com",
        "target_url": "https://api.stripe.com/v1/charges",
        "idempotency_key": "req_eq_01",
    }
    nested = {
        "function": "charge",
        "target_url": "https://api.stripe.com/v1/charges",
        "parameters": {
            "amount": 25.00,
            "currency": "USD",
            "idempotency_key": "req_eq_01",
        },
    }

    r1 = await client.post("/execute", json={
        "agent_id": str(TEST_AGENT_ID),
        "tool_call": flat,
    })
    r2 = await client.post("/execute", json={
        "agent_id": str(TEST_AGENT_ID),
        "tool_call": nested,
    })
    assert r1.status_code == 200
    assert r2.status_code == 200

    assert len(fake_audit_queue.records) == 2
    h1 = fake_audit_queue.records[0]["financial_action_hash"]
    h2 = fake_audit_queue.records[1]["financial_action_hash"]
    assert h1 is not None
    assert h1 == h2
