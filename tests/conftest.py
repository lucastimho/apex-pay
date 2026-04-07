"""
Shared test fixtures for the APEX-Pay test suite.

Uses an in-memory SQLite database and a mock Redis queue so tests
run without external infrastructure (no Postgres, no Redis needed).
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone
from typing import AsyncGenerator
from unittest.mock import AsyncMock

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apex_pay.core.models import Agent, AuditLog, Base, Policy, Transaction
from apex_pay.services.audit_queue import AuditQueue
from apex_pay.services.token_service import TokenService

# ── Test constants ──────────────────────────────────────────────────────────
TEST_AGENT_ID = uuid.UUID("aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb")
TEST_AGENT_NAME = "test-agent"
TEST_PUBLIC_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI test-key"
TEST_HMAC_KEY = "test-secret-key-for-hmac-signing"


# ── Async SQLite engine (in-memory) ────────────────────────────────────────
@pytest_asyncio.fixture
async def db_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:", echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    Session = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with Session() as session:
        yield session


# ── Seed data ───────────────────────────────────────────────────────────────
@pytest_asyncio.fixture
async def seeded_session(db_session: AsyncSession) -> AsyncSession:
    """Session with a test agent and active policy pre-loaded."""
    agent = Agent(
        id=TEST_AGENT_ID,
        name=TEST_AGENT_NAME,
        public_key=TEST_PUBLIC_KEY,
        current_balance=500.0,
        status="active",
    )
    db_session.add(agent)

    policy = Policy(
        agent_id=TEST_AGENT_ID,
        max_per_transaction=50.0,
        daily_limit=200.0,
        allowed_domains=["api.stripe.com", "api.openai.com"],
        is_active=True,
    )
    db_session.add(policy)
    await db_session.commit()
    return db_session


# ── Mock Audit Queue ────────────────────────────────────────────────────────
class FakeAuditQueue:
    """In-memory audit queue for tests — no Redis required."""

    def __init__(self):
        self.records: list[dict] = []
        self._saturated = False

    async def connect(self):
        pass

    async def close(self):
        pass

    async def is_saturated(self) -> bool:
        return self._saturated

    async def push(self, **kwargs):
        self.records.append(kwargs)

    async def pop(self, timeout=5):
        if self.records:
            return self.records.pop(0)
        return None

    async def depth(self) -> int:
        return len(self.records)


@pytest.fixture
def fake_audit_queue() -> FakeAuditQueue:
    return FakeAuditQueue()


# ── Token Service ───────────────────────────────────────────────────────────
@pytest.fixture
def token_service() -> TokenService:
    return TokenService(secret_key=TEST_HMAC_KEY, ttl=300)


# ── FastAPI test client ─────────────────────────────────────────────────────
@pytest_asyncio.fixture
async def test_app(db_engine, fake_audit_queue):
    """Build a test FastAPI app with in-memory DB and fake audit queue."""
    from contextlib import asynccontextmanager

    from fastapi import FastAPI

    from apex_pay.routers import admin, gateway

    Session = async_sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)

    # Override session dependencies
    async def override_gateway_session():
        async with Session() as s:
            yield s

    async def override_audit_queue(request):
        return fake_audit_queue

    @asynccontextmanager
    async def test_lifespan(app: FastAPI):
        app.state.audit_queue = fake_audit_queue
        yield

    app = FastAPI(lifespan=test_lifespan)

    # No rate limiter in tests — rate limiting is applied via middleware
    # in main.py, not on individual routes, so the test app is clean.
    app.include_router(gateway.router)
    app.include_router(admin.router)

    # Override deps
    app.dependency_overrides[gateway.get_session] = override_gateway_session
    app.dependency_overrides[gateway.get_audit_queue] = lambda: fake_audit_queue
    app.dependency_overrides[admin.get_session] = override_gateway_session

    return app


@pytest_asyncio.fixture
async def client(test_app) -> AsyncGenerator[AsyncClient, None]:
    transport = ASGITransport(app=test_app)
    async with AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"X-Forwarded-For": "127.0.0.1"},
    ) as ac:
        yield ac
