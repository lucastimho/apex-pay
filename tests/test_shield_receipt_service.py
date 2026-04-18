"""Tests for apex_pay.shield.receipt_service — Ed25519 signed receipts."""

from __future__ import annotations

import base64
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from apex_pay.shield.receipt_service import (
    RECEIPT_VERSION,
    Ed25519KeyRing,
    ReceiptService,
    SignedReceipt,
)


# ── Fixtures ────────────────────────────────────────────────────────────────
@pytest.fixture
def keyring() -> Ed25519KeyRing:
    return Ed25519KeyRing.generate(kid="key-2026-04")


@pytest.fixture
def service(keyring: Ed25519KeyRing) -> ReceiptService:
    return ReceiptService(
        keyring=keyring, policy_version="2026.04.17", default_ttl_seconds=60,
    )


def _sign(service: ReceiptService, **overrides) -> SignedReceipt:
    defaults = dict(
        intent_hash="h" * 64,
        agent_id="aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        token_id="ec_test123",
        risk_score=0.12,
    )
    defaults.update(overrides)
    return service.sign(**defaults)


# ── Roundtrip ──────────────────────────────────────────────────────────────
def test_sign_then_verify_roundtrip(service):
    signed = _sign(service)
    assert signed.receipt["v"] == RECEIPT_VERSION
    assert signed.receipt["policy_version"] == "2026.04.17"
    assert signed.kid == "key-2026-04"

    ok, reason = service.verify(signed)
    assert ok
    assert reason == "valid"


def test_receipt_includes_expected_fields(service):
    signed = _sign(service)
    for key in ("v", "intent_hash", "agent_id", "policy_version",
                "risk_score", "token_id", "kid", "issued_at", "expires_at"):
        assert key in signed.receipt


def test_extra_payload_roundtrips_through_signature(service):
    signed = _sign(
        service, extra={"action_domain": "api.stripe.com", "projected_cost": 25.0},
    )
    ok, _ = service.verify(signed)
    assert ok
    assert signed.receipt["extra"]["action_domain"] == "api.stripe.com"


# ── Tamper detection ───────────────────────────────────────────────────────
def test_verify_rejects_tampered_payload(service):
    signed = _sign(service)
    # Mutate the receipt body — signature no longer matches
    signed.receipt["risk_score"] = 0.99
    ok, reason = service.verify(signed)
    assert not ok
    assert reason == "invalid_signature"


def test_verify_rejects_swapped_intent_hash(service):
    signed = _sign(service)
    signed.receipt["intent_hash"] = "b" * 64
    ok, reason = service.verify(signed)
    assert not ok
    assert reason == "invalid_signature"


def test_verify_rejects_malformed_signature(service):
    signed = _sign(service)
    signed.signature_b64 = "not-base64!!!"
    ok, reason = service.verify(signed)
    assert not ok
    assert reason == "malformed_signature"


# ── Expiry ─────────────────────────────────────────────────────────────────
def test_verify_rejects_expired_receipt(service):
    signed = _sign(service, ttl_seconds=1)
    # Sleep > TTL + 1s integer-truncation slack so we always cross the
    # stored expiry second regardless of issue-time fractional offset.
    time.sleep(2.1)
    ok, reason = service.verify(signed)
    assert not ok
    assert reason == "expired"


# ── Key / version handling ─────────────────────────────────────────────────
def test_verify_rejects_unsupported_version(service):
    signed = _sign(service)
    signed.receipt["v"] = 999
    ok, reason = service.verify(signed)
    assert not ok
    assert reason == "unsupported_receipt_version"


def test_verify_rejects_unknown_kid(service, keyring):
    signed = _sign(service)
    # Point at a kid that isn't in the keyring
    signed.kid = "key-does-not-exist"
    ok, reason = service.verify(signed)
    assert not ok
    assert reason == "unknown_kid"


# ── Key rotation ───────────────────────────────────────────────────────────
def test_kid_rotation_allows_verification_of_old_receipts():
    """After rotating the signing key, receipts signed with the old kid must
    still verify as long as the old public key remains in the keyring."""
    old_priv = Ed25519PrivateKey.generate()
    keyring = Ed25519KeyRing(
        signing_kid="key-old",
        signing_key=old_priv,
        public_keys={"key-old": old_priv.public_key()},
    )
    svc = ReceiptService(keyring=keyring, policy_version="v1")
    signed_old = _sign(svc)

    # Rotate: new signing key, keep old public key for verification
    new_priv = Ed25519PrivateKey.generate()
    keyring.signing_kid = "key-new"
    keyring.signing_key = new_priv
    keyring.public_keys["key-new"] = new_priv.public_key()

    # Old receipt still verifies
    ok, reason = svc.verify(signed_old)
    assert ok
    assert reason == "valid"

    # New receipts use the new kid
    signed_new = _sign(svc)
    assert signed_new.kid == "key-new"
    ok, _ = svc.verify(signed_new)
    assert ok


# ── Keyring helpers ────────────────────────────────────────────────────────
def test_export_public_key_b64_decodes_to_32_bytes(keyring):
    b64 = keyring.export_public_key_b64()
    raw = base64.b64decode(b64)
    assert len(raw) == 32  # Ed25519 public key is 32 bytes


def test_export_private_key_b64_decodes_to_32_bytes(keyring):
    b64 = keyring.export_private_key_b64()
    raw = base64.b64decode(b64)
    assert len(raw) == 32


def test_from_env_generates_ephemeral_when_missing(monkeypatch):
    monkeypatch.delenv("APEX_SHIELD_ED25519_PRIV_B64", raising=False)
    kr = Ed25519KeyRing.from_env()
    assert kr.signing_key is not None
    assert kr.signing_kid in kr.public_keys


def test_from_env_reads_private_key(monkeypatch):
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes(
        encoding=__import__("cryptography").hazmat.primitives.serialization.Encoding.Raw,
        format=__import__("cryptography").hazmat.primitives.serialization.PrivateFormat.Raw,
        encryption_algorithm=__import__("cryptography").hazmat.primitives.serialization.NoEncryption(),
    )
    monkeypatch.setenv("APEX_SHIELD_ED25519_PRIV_B64", base64.b64encode(raw).decode())
    monkeypatch.setenv("APEX_SHIELD_ED25519_KID", "key-from-env")
    kr = Ed25519KeyRing.from_env()
    assert kr.signing_kid == "key-from-env"
    assert "key-from-env" in kr.public_keys


# ── SignedReceipt serialization ─────────────────────────────────────────────
def test_signed_receipt_to_from_dict_roundtrips(service):
    signed = _sign(service)
    data = signed.to_dict()
    rebuilt = SignedReceipt.from_dict(data)
    assert rebuilt.receipt == signed.receipt
    assert rebuilt.signature_b64 == signed.signature_b64
    assert rebuilt.kid == signed.kid
    ok, _ = service.verify(rebuilt)
    assert ok
