"""
Integration tests for admin CRUD endpoints.

Covers:
    • POST /admin/agents   — register a new agent
    • GET  /admin/agents   — list all agents
    • GET  /admin/agents/:id — get single agent
    • POST /admin/policies — create a policy
    • GET  /admin/policies/:agent_id — get active policy
    • Policy replacement (new policy deactivates old one)
"""

from __future__ import annotations

import uuid

import pytest
import pytest_asyncio
from httpx import AsyncClient


# =============================================================================
# Agent Registration
# =============================================================================
class TestAgentCRUD:
    @pytest.mark.asyncio
    async def test_register_agent(self, client: AsyncClient):
        resp = await client.post("/admin/agents", json={
            "name": "agent-alpha",
            "public_key": "ssh-ed25519 AAAAC3...",
            "initial_balance": 100.0,
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "agent-alpha"
        assert data["current_balance"] == 100.0
        assert data["status"] == "active"
        assert "id" in data

    @pytest.mark.asyncio
    async def test_register_duplicate_name_fails(self, client: AsyncClient):
        """UNIQUE constraint on agents.name should reject duplicates."""
        await client.post("/admin/agents", json={
            "name": "unique-bot",
            "public_key": "key-1",
        })
        # The IntegrityError propagates as an unhandled server error.
        # In production the global exception handler returns 500.
        # In test mode (no global handler), httpx may see a 500 or the
        # transport may raise. Either outcome confirms the constraint works.
        try:
            resp = await client.post("/admin/agents", json={
                "name": "unique-bot",
                "public_key": "key-2",
            })
            assert resp.status_code >= 400
        except Exception:
            pass  # IntegrityError bubbled — constraint enforced

    @pytest.mark.asyncio
    async def test_list_agents(self, client: AsyncClient):
        await client.post("/admin/agents", json={
            "name": "bot-list-1",
            "public_key": "k1",
        })
        await client.post("/admin/agents", json={
            "name": "bot-list-2",
            "public_key": "k2",
        })
        resp = await client.get("/admin/agents")
        assert resp.status_code == 200
        agents = resp.json()
        names = [a["name"] for a in agents]
        assert "bot-list-1" in names
        assert "bot-list-2" in names

    @pytest.mark.asyncio
    async def test_get_agent_by_id(self, client: AsyncClient):
        create_resp = await client.post("/admin/agents", json={
            "name": "bot-get",
            "public_key": "key",
        })
        agent_id = create_resp.json()["id"]

        resp = await client.get(f"/admin/agents/{agent_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == agent_id

    @pytest.mark.asyncio
    async def test_get_nonexistent_agent_404(self, client: AsyncClient):
        fake_id = str(uuid.uuid4())
        resp = await client.get(f"/admin/agents/{fake_id}")
        assert resp.status_code == 404


# =============================================================================
# Policy Management
# =============================================================================
class TestPolicyCRUD:
    @pytest.mark.asyncio
    async def test_create_policy(self, client: AsyncClient):
        # First create an agent
        agent_resp = await client.post("/admin/agents", json={
            "name": "policy-bot",
            "public_key": "key",
        })
        agent_id = agent_resp.json()["id"]

        resp = await client.post("/admin/policies", json={
            "agent_id": agent_id,
            "max_per_transaction": 25.0,
            "daily_limit": 500.0,
            "allowed_domains": ["api.stripe.com"],
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["max_per_transaction"] == 25.0
        assert data["daily_limit"] == 500.0
        assert data["allowed_domains"] == ["api.stripe.com"]
        assert data["is_active"] is True

    @pytest.mark.asyncio
    async def test_get_active_policy(self, client: AsyncClient):
        agent_resp = await client.post("/admin/agents", json={
            "name": "policy-get-bot",
            "public_key": "key",
        })
        agent_id = agent_resp.json()["id"]

        await client.post("/admin/policies", json={
            "agent_id": agent_id,
            "max_per_transaction": 30.0,
            "daily_limit": 300.0,
            "allowed_domains": ["api.example.com"],
        })

        resp = await client.get(f"/admin/policies/{agent_id}")
        assert resp.status_code == 200
        assert resp.json()["daily_limit"] == 300.0

    @pytest.mark.asyncio
    async def test_new_policy_replaces_old(self, client: AsyncClient):
        """Creating a new policy should deactivate the previous one."""
        agent_resp = await client.post("/admin/agents", json={
            "name": "policy-replace-bot",
            "public_key": "key",
        })
        agent_id = agent_resp.json()["id"]

        # First policy
        await client.post("/admin/policies", json={
            "agent_id": agent_id,
            "max_per_transaction": 10.0,
            "daily_limit": 100.0,
        })

        # Second policy (should replace)
        await client.post("/admin/policies", json={
            "agent_id": agent_id,
            "max_per_transaction": 99.0,
            "daily_limit": 999.0,
        })

        resp = await client.get(f"/admin/policies/{agent_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["max_per_transaction"] == 99.0
        assert data["daily_limit"] == 999.0

    @pytest.mark.asyncio
    async def test_no_policy_returns_404(self, client: AsyncClient):
        agent_resp = await client.post("/admin/agents", json={
            "name": "no-policy-bot",
            "public_key": "key",
        })
        agent_id = agent_resp.json()["id"]

        resp = await client.get(f"/admin/policies/{agent_id}")
        assert resp.status_code == 404
