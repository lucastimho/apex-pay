"""Tests for apex_pay.shield.vault_client.VaultClient.

These tests use httpx.MockTransport so they need neither a real Vault
nor network access. Each test pins one specific behaviour — auth flow,
token renewal, circuit breaker state transitions, fail-closed on 5xx,
response wrapping header propagation.
"""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest

from apex_pay.shield.vault_client import (
    VaultAuthError,
    VaultCircuitOpenError,
    VaultClient,
    VaultClientError,
    _CircuitBreaker,
)

# ── MockTransport helpers ───────────────────────────────────────────────────


def _make_client(
    handler,
    *,
    failure_threshold: int = 3,
    cooldown_seconds: float = 0.1,
) -> VaultClient:
    transport = httpx.MockTransport(handler)
    client = VaultClient(
        addr="https://vault.test",
        failure_threshold=failure_threshold,
        cooldown_seconds=cooldown_seconds,
    )
    # Swap in the mock transport *after* construction.
    client._client = httpx.AsyncClient(base_url="https://vault.test", transport=transport)
    return client


def _login_response(ttl: int = 3600, renewable: bool = True) -> dict[str, Any]:
    return {
        "auth": {
            "client_token": "s.test-token",
            "lease_duration": ttl,
            "renewable": renewable,
            "policies": ["apex-shield"],
        }
    }


# ── AppRole auth ────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_login_approle_success():
    async def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/auth/approle/login"
        body = request.read()
        assert b"role_id" in body
        return httpx.Response(200, json=_login_response())

    client = _make_client(handler)
    await client.login_approle(role_id="r", secret_id="s")
    assert client.is_authenticated
    await client.aclose()


@pytest.mark.asyncio
async def test_login_approle_bad_credentials_raises_auth_error():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, json={"errors": ["invalid role or secret ID"]})

    client = _make_client(handler)
    with pytest.raises(VaultAuthError):
        await client.login_approle(role_id="r", secret_id="bad")
    assert not client.is_authenticated
    await client.aclose()


@pytest.mark.asyncio
async def test_login_approle_missing_token_field_raises():
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"auth": {"lease_duration": 3600}})

    client = _make_client(handler)
    with pytest.raises(VaultAuthError, match="no client_token"):
        await client.login_approle(role_id="r", secret_id="s")
    await client.aclose()


# ── Authenticated requests ──────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_read_sends_token_header():
    seen_headers: dict[str, str] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json=_login_response())
        seen_headers.update(dict(request.headers))
        return httpx.Response(200, json={"data": {"value": "ok"}})

    client = _make_client(handler)
    await client.login_approle(role_id="r", secret_id="s")
    await client.read("secret/data/foo")
    assert seen_headers.get("x-vault-token") == "s.test-token"
    await client.aclose()


@pytest.mark.asyncio
async def test_wrap_ttl_header_propagated():
    seen_wrap: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json=_login_response())
        seen_wrap.append(request.headers.get("x-vault-wrap-ttl", ""))
        return httpx.Response(200, json={"wrap_info": {"token": "wrap.abc"}})

    client = _make_client(handler)
    await client.login_approle(role_id="r", secret_id="s")
    await client.read("database/creds/apex", wrap_ttl="60s")
    assert seen_wrap == ["60s"]
    await client.aclose()


# ── Circuit breaker ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_circuit_opens_after_consecutive_5xx():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json=_login_response())
        return httpx.Response(500, text="boom")

    client = _make_client(handler, failure_threshold=2, cooldown_seconds=0.05)
    await client.login_approle(role_id="r", secret_id="s")
    # First two failures trip the breaker.
    for _ in range(2):
        with pytest.raises(VaultClientError):
            await client.read("secret/x")
    # Third request is refused fast.
    with pytest.raises(VaultCircuitOpenError):
        await client.read("secret/x")
    assert client.circuit_state == "open"
    await client.aclose()


@pytest.mark.asyncio
async def test_circuit_recovers_after_cooldown():
    call_count = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json=_login_response())
        call_count["n"] += 1
        if call_count["n"] <= 2:
            return httpx.Response(500)
        return httpx.Response(200, json={"data": {"ok": True}})

    client = _make_client(handler, failure_threshold=2, cooldown_seconds=0.05)
    await client.login_approle(role_id="r", secret_id="s")
    for _ in range(2):
        with pytest.raises(VaultClientError):
            await client.read("secret/x")
    assert client.circuit_state == "open"
    await asyncio.sleep(0.1)
    # Half-open probe — this one succeeds, so the breaker closes.
    result = await client.read("secret/x")
    assert result["data"]["ok"] is True
    assert client.circuit_state == "closed"
    await client.aclose()


# ── Token renewal ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_token_refresh_when_expired():
    login_calls = {"n": 0}

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            login_calls["n"] += 1
            # Very short TTL so the next op triggers renewal / re-login.
            return httpx.Response(200, json=_login_response(ttl=0, renewable=False))
        return httpx.Response(200, json={"data": {"ok": True}})

    client = _make_client(handler)
    await client.login_approle(role_id="r", secret_id="s")
    # TTL is 0 so the token is immediately "expired" — next request should
    # trigger a re-login because the token is non-renewable.
    await client.read("secret/x")
    assert login_calls["n"] == 2
    await client.aclose()


# ── Transit signing ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_transit_sign_returns_signature():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json=_login_response())
        assert request.url.path == "/v1/transit/sign/test-key"
        return httpx.Response(200, json={"data": {"signature": "vault:v1:abc123=="}})

    client = _make_client(handler)
    await client.login_approle(role_id="r", secret_id="s")
    sig = await client.transit_sign(key_name="test-key", input_b64="aGVsbG8=")
    assert sig == "vault:v1:abc123=="
    await client.aclose()


@pytest.mark.asyncio
async def test_transit_sign_missing_signature_raises():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json=_login_response())
        return httpx.Response(200, json={"data": {}})

    client = _make_client(handler)
    await client.login_approle(role_id="r", secret_id="s")
    with pytest.raises(VaultClientError, match="no signature"):
        await client.transit_sign(key_name="k", input_b64="x")
    await client.aclose()


# ── Unit tests on the breaker helper itself ─────────────────────────────────


class TestCircuitBreaker:
    def test_starts_closed(self):
        b = _CircuitBreaker(failure_threshold=2, cooldown_seconds=0.1)
        assert b.state == "closed"
        assert b.allow()

    def test_opens_on_threshold(self):
        b = _CircuitBreaker(failure_threshold=2, cooldown_seconds=0.1)
        b.record_failure()
        assert b.state == "closed"
        b.record_failure()
        assert b.state == "open"
        assert not b.allow()

    def test_half_open_probe_then_close(self):
        b = _CircuitBreaker(failure_threshold=1, cooldown_seconds=0.0)
        b.record_failure()
        assert b.state == "open"
        # With cooldown_seconds=0.0 we transition to half_open on first allow.
        assert b.allow()
        assert b.state == "half_open"
        b.record_success()
        assert b.state == "closed"

    def test_half_open_failure_re_opens(self):
        b = _CircuitBreaker(failure_threshold=1, cooldown_seconds=0.0)
        b.record_failure()
        b.allow()                     # transitions to half_open
        b.record_failure()            # failure in half_open → open again
        assert b.state == "open"
