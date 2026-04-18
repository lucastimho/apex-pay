"""Tests for apex_pay.shield.credential_manager.DevCredentialBackend."""

from __future__ import annotations

import asyncio
import time

import pytest

from apex_pay.shield.credential_manager import (
    CredentialScope,
    DevCredentialBackend,
)


@pytest.fixture
def backend() -> DevCredentialBackend:
    return DevCredentialBackend(secret_key="unit-test-secret-key-should-be-long-enough")


def _scope(intent_hash: str = "h" * 64, domain: str = "api.stripe.com") -> CredentialScope:
    return CredentialScope(
        intent_hash=intent_hash, domain=domain, method="POST", max_amount=25.0,
    )


@pytest.mark.asyncio
async def test_issue_verify_roundtrip(backend):
    cred = await backend.issue(_scope(), ttl_seconds=60)
    assert cred.token.startswith("v1.")
    assert cred.token_id.startswith("ec_")
    assert not cred.is_expired

    ok, reason, scope = await backend.verify(cred.token, intent_hash="h" * 64)
    assert ok
    assert reason == "valid"
    assert scope is not None
    assert scope.domain == "api.stripe.com"
    assert scope.max_amount == 25.0


@pytest.mark.asyncio
async def test_verify_rejects_wrong_intent_hash(backend):
    cred = await backend.issue(_scope(intent_hash="a" * 64), ttl_seconds=60)
    ok, reason, _ = await backend.verify(cred.token, intent_hash="b" * 64)
    assert not ok
    assert reason == "intent_mismatch"


@pytest.mark.asyncio
async def test_verify_rejects_tampered_payload(backend):
    cred = await backend.issue(_scope(), ttl_seconds=60)
    # Flip one character in the payload segment
    parts = cred.token.split(".")
    parts[2] = parts[2][:-1] + ("A" if parts[2][-1] != "A" else "B")
    tampered = ".".join(parts)
    ok, reason, _ = await backend.verify(tampered, intent_hash="h" * 64)
    assert not ok
    assert reason in {"invalid_signature", "invalid_format"}


@pytest.mark.asyncio
async def test_revoke_invalidates_token(backend):
    cred = await backend.issue(_scope(), ttl_seconds=60)
    await backend.revoke(cred.token_id)
    ok, reason, _ = await backend.verify(cred.token, intent_hash="h" * 64)
    assert not ok
    assert reason == "revoked"


@pytest.mark.asyncio
async def test_ttl_is_capped(backend):
    # Requesting 10000s should be capped to the hard max (300s).
    cred = await backend.issue(_scope(), ttl_seconds=10_000)
    ttl_granted = cred.expires_at - int(time.time())
    assert ttl_granted <= 300


@pytest.mark.asyncio
async def test_expired_token_rejected(backend):
    cred = await backend.issue(_scope(), ttl_seconds=1)
    # Sleep > TTL + 1s of integer-truncation slack so we always cross the
    # stored expiry second regardless of when inside the second we issued.
    await asyncio.sleep(2.1)
    ok, reason, _ = await backend.verify(cred.token, intent_hash="h" * 64)
    assert not ok
    assert reason == "expired"


@pytest.mark.asyncio
async def test_token_id_is_logsafe(backend):
    """token_id must be opaque; it cannot embed the HMAC signature or secret."""
    cred = await backend.issue(_scope(), ttl_seconds=60)
    assert "ec_" in cred.token_id
    assert cred.token_id not in cred.token.split(".")[2:]  # not in payload/sig segments
