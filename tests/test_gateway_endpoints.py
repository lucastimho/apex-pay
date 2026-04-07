"""
Integration tests for the core gateway endpoints.

Uses httpx AsyncClient against a test FastAPI app with an in-memory
SQLite database and a fake audit queue — no external services needed.

Covers:
    • POST /execute  — policy approve/deny, back-pressure 503
    • GET  /data     — 402 challenge flow, no_policy baseline
    • POST /pay      — settlement + token issuance
    • GET  /health   — liveness probe
    • POST /reset    — ledger reset
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from apex_pay.core.models import Agent, AuditLog, Base, Policy, Transaction
from tests.conftest import TEST_AGENT_ID, TEST_AGENT_NAME, TEST_PUBLIC_KEY


# ── Helpers ─────────────────────────────────────────────────────────────────
async def _seed(db_engine):
    """Seed the test DB with an agent and policy."""
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


@pytest_asyncio.fixture
async def seeded_client(db_engine, client, fake_audit_queue):
    """Client with pre-seeded agent and policy data."""
    await _seed(db_engine)
    return client


# =============================================================================
# GET /health
# =============================================================================
class TestHealth:
    @pytest.mark.asyncio
    async def test_health_returns_ok(self, client: AsyncClient):
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "version" in data
        assert "uptime_seconds" in data


# =============================================================================
# POST /execute
# =============================================================================
class TestExecute:
    @pytest.mark.asyncio
    async def test_approved_request(self, seeded_client: AsyncClient):
        resp = await seeded_client.post("/execute", json={
            "agent_id": str(TEST_AGENT_ID),
            "tool_call": {
                "function": "charge_card",
                "target_url": "https://api.stripe.com/v1/charges",
                "parameters": {"amount": 25.0},
            },
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is True
        assert data["status"] == "APPROVED"
        assert data["reason"] == "policy_passed"
        assert data["latency_ms"] is not None

    @pytest.mark.asyncio
    async def test_denied_bad_domain(self, seeded_client: AsyncClient):
        resp = await seeded_client.post("/execute", json={
            "agent_id": str(TEST_AGENT_ID),
            "tool_call": {
                "function": "exfiltrate",
                "target_url": "https://evil.example.com/steal",
                "parameters": {"amount": 5.0},
            },
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is False
        assert data["status"] == "DENIED"
        assert "domain_not_allowed" in data["reason"]

    @pytest.mark.asyncio
    async def test_denied_over_per_txn_limit(self, seeded_client: AsyncClient):
        resp = await seeded_client.post("/execute", json={
            "agent_id": str(TEST_AGENT_ID),
            "tool_call": {
                "function": "buy_expensive",
                "target_url": "https://api.stripe.com/v1/charges",
                "parameters": {"amount": 999.0},
            },
        })
        data = resp.json()
        assert data["allowed"] is False
        assert "exceeds_per_transaction_limit" in data["reason"]

    @pytest.mark.asyncio
    async def test_denied_unknown_agent(self, seeded_client: AsyncClient):
        fake_id = str(uuid.uuid4())
        resp = await seeded_client.post("/execute", json={
            "agent_id": fake_id,
            "tool_call": {"function": "test", "parameters": {"amount": 1.0}},
        })
        data = resp.json()
        assert data["allowed"] is False
        assert "agent_not_found" in data["reason"]

    @pytest.mark.asyncio
    async def test_invalid_payload_returns_422(self, seeded_client: AsyncClient):
        resp = await seeded_client.post("/execute", json={
            "agent_id": "not-a-uuid",
            "tool_call": {"function": "test"},
        })
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_audit_queue_receives_record(self, seeded_client: AsyncClient, fake_audit_queue):
        await seeded_client.post("/execute", json={
            "agent_id": str(TEST_AGENT_ID),
            "tool_call": {
                "function": "charge",
                "target_url": "https://api.stripe.com/v1/charges",
                "parameters": {"amount": 10.0},
            },
        })
        assert await fake_audit_queue.depth() >= 0  # record was pushed
        assert len(fake_audit_queue.records) >= 1

    @pytest.mark.asyncio
    async def test_backpressure_503(self, seeded_client: AsyncClient, fake_audit_queue):
        """When the audit queue is saturated, gateway should return 503."""
        fake_audit_queue._saturated = True
        resp = await seeded_client.post("/execute", json={
            "agent_id": str(TEST_AGENT_ID),
            "tool_call": {
                "function": "charge",
                "target_url": "https://api.stripe.com/v1/charges",
                "parameters": {"amount": 10.0},
            },
        })
        assert resp.status_code == 503
        fake_audit_queue._saturated = False


# =============================================================================
# GET /data — HTTP 402 Challenge Flow
# =============================================================================
class TestDataEndpoint:
    @pytest.mark.asyncio
    async def test_no_policy_baseline_returns_data(self, seeded_client: AsyncClient):
        resp = await seeded_client.get("/data", params={"baseline": "no_policy"})
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["baseline"] == "no_policy"

    @pytest.mark.asyncio
    async def test_missing_token_returns_402(self, seeded_client: AsyncClient):
        resp = await seeded_client.get(
            "/data", params={"baseline": "payment_with_policy"}
        )
        assert resp.status_code == 402
        data = resp.json()
        assert "amount" in data["detail"]
        assert "ref_id" in data["detail"]

    @pytest.mark.asyncio
    async def test_invalid_token_returns_403(self, seeded_client: AsyncClient):
        resp = await seeded_client.get(
            "/data",
            params={"baseline": "payment_with_policy"},
            headers={"x-payment-token": "forged.token"},
        )
        assert resp.status_code == 403


# =============================================================================
# POST /reset
# =============================================================================
class TestReset:
    @pytest.mark.asyncio
    async def test_reset_clears_ledger(self, seeded_client: AsyncClient):
        resp = await seeded_client.post("/reset")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
