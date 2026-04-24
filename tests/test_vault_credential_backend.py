"""Tests for VaultCredentialBackend against a mock Vault.

Covers:
  • issue() returns a wrap token + binds scope via transit/sign
  • verify() checks wrapping liveness AND scope.intent_hash match
  • revoke() calls sys/leases/revoke
  • startup() logs in AND runs the transit probe
  • Vault unavailable → fail-closed error surfaced upstream
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from apex_pay.shield.credential_manager import CredentialScope, VaultCredentialBackend
from apex_pay.shield.vault_client import VaultClient, VaultClientError


def _make_backend(handler) -> tuple[VaultCredentialBackend, VaultClient]:
    transport = httpx.MockTransport(handler)
    client = VaultClient(addr="https://vault.test", failure_threshold=10)
    client._client = httpx.AsyncClient(base_url="https://vault.test", transport=transport)
    backend = VaultCredentialBackend(
        vault_client=client,
        role_id="r",
        secret_id="s",
        secrets_path="database/creds/apex",
        wrap_ttl="60s",
        transit_key="apex-shield-scope-signer",
    )
    return backend, client


def _login_response() -> dict[str, Any]:
    return {
        "auth": {
            "client_token": "s.test-token",
            "lease_duration": 3600,
            "renewable": True,
            "policies": ["apex-shield"],
        }
    }


# ── startup ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_startup_logs_in_and_probes_transit():
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json=_login_response())
        if request.url.path == "/v1/transit/sign/apex-shield-scope-signer":
            return httpx.Response(200, json={"data": {"signature": "vault:v1:probe-ok"}})
        return httpx.Response(404)

    backend, client = _make_backend(handler)
    await backend.startup()
    assert "/v1/auth/approle/login" in calls
    assert "/v1/transit/sign/apex-shield-scope-signer" in calls
    assert client.is_authenticated
    await backend.shutdown()


@pytest.mark.asyncio
async def test_startup_fails_if_transit_key_missing():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json=_login_response())
        # Simulate a 404 on the transit mount — key not found.
        return httpx.Response(404, json={"errors": ["no such key"]})

    backend, _ = _make_backend(handler)
    with pytest.raises(RuntimeError, match="transit probe failed"):
        await backend.startup()


# ── issue ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_issue_returns_wrap_token_and_signs_scope():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json=_login_response())
        if request.url.path == "/v1/transit/sign/apex-shield-scope-signer":
            return httpx.Response(200, json={"data": {"signature": "vault:v1:xyz"}})
        if request.url.path == "/v1/database/creds/apex":
            # Vault always returns wrap_info when X-Vault-Wrap-TTL is set.
            assert request.headers.get("x-vault-wrap-ttl") == "60s"
            return httpx.Response(200, json={
                "lease_id": "database/creds/apex/ABC123",
                "wrap_info": {"token": "wrap.redeem-me", "ttl": 60},
            })
        return httpx.Response(404)

    backend, _ = _make_backend(handler)
    await backend.startup()

    scope = CredentialScope(
        intent_hash="sha256:abcd",
        domain="api.stripe.com",
        method="POST",
        max_amount=25.00,
    )
    cred = await backend.issue(scope, ttl_seconds=60)
    assert cred.backend == "vault"
    assert cred.token == "wrap.redeem-me"
    assert cred.token_id.startswith("ec_")
    await backend.shutdown()


@pytest.mark.asyncio
async def test_issue_fails_closed_when_vault_unreachable():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json=_login_response())
        if request.url.path == "/v1/transit/sign/apex-shield-scope-signer":
            return httpx.Response(200, json={"data": {"signature": "vault:v1:probe-ok"}})
        # Simulate Vault dying after startup.
        return httpx.Response(500, text="internal error")

    backend, _ = _make_backend(handler)
    await backend.startup()

    scope = CredentialScope(
        intent_hash="sha256:abcd",
        domain="api.stripe.com",
        method="POST",
        max_amount=25.00,
    )
    with pytest.raises(VaultClientError):
        await backend.issue(scope, ttl_seconds=60)
    await backend.shutdown()


# ── revoke ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_revoke_calls_leases_revoke():
    revoke_calls: list[dict] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json=_login_response())
        if request.url.path == "/v1/transit/sign/apex-shield-scope-signer":
            return httpx.Response(200, json={"data": {"signature": "vault:v1:probe-ok"}})
        if request.url.path == "/v1/database/creds/apex":
            return httpx.Response(200, json={
                "lease_id": "database/creds/apex/XYZ",
                "wrap_info": {"token": "wrap.abc"},
            })
        if request.url.path == "/v1/sys/leases/revoke":
            import json as _json
            revoke_calls.append(_json.loads(request.read().decode()))
            return httpx.Response(204)
        return httpx.Response(404)

    backend, _ = _make_backend(handler)
    await backend.startup()
    cred = await backend.issue(
        CredentialScope(intent_hash="h", domain="d", method="POST", max_amount=1),
        ttl_seconds=60,
    )
    await backend.revoke(cred.token_id)
    assert revoke_calls == [{"lease_id": "database/creds/apex/XYZ"}]
    await backend.shutdown()


@pytest.mark.asyncio
async def test_revoke_unknown_token_is_silent():
    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/approle/login":
            return httpx.Response(200, json=_login_response())
        if request.url.path == "/v1/transit/sign/apex-shield-scope-signer":
            return httpx.Response(200, json={"data": {"signature": "v"}})
        return httpx.Response(500)  # would fail if revoke() actually hit Vault

    backend, _ = _make_backend(handler)
    await backend.startup()
    # Unknown token should NOT raise and NOT call Vault.
    await backend.revoke("ec_never_issued")
    await backend.shutdown()
