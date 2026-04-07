"""
Tests for the HMAC-SHA256 Token Service.

Covers:
    • Token issue → verify roundtrip
    • Payload integrity (ref_id, amount preserved)
    • Expiry enforcement
    • Signature tampering detection
    • Malformed token handling
    • Distinct tokens for distinct inputs
"""

from __future__ import annotations

import base64
import json
import time
from unittest.mock import patch

import pytest

from apex_pay.services.token_service import TokenService

SECRET = "test-hmac-secret-key"


@pytest.fixture
def svc() -> TokenService:
    return TokenService(secret_key=SECRET, ttl=300)


# ── Roundtrip ───────────────────────────────────────────────────────────────
class TestIssueAndVerify:
    def test_roundtrip_valid(self, svc: TokenService):
        token, expiry = svc.issue("ref-001", 25.50)
        valid, reason, payload = svc.verify(token)

        assert valid is True
        assert reason == "valid"
        assert payload["ref_id"] == "ref-001"
        assert payload["amount"] == 25.50
        assert payload["exp"] == expiry

    def test_expiry_is_in_future(self, svc: TokenService):
        _, expiry = svc.issue("ref-002", 10.0)
        assert expiry > int(time.time())
        assert expiry <= int(time.time()) + 301  # ttl=300 + small drift

    def test_distinct_refs_produce_distinct_tokens(self, svc: TokenService):
        t1, _ = svc.issue("ref-A", 10.0)
        t2, _ = svc.issue("ref-B", 10.0)
        assert t1 != t2

    def test_distinct_amounts_produce_distinct_tokens(self, svc: TokenService):
        t1, _ = svc.issue("ref-X", 10.0)
        t2, _ = svc.issue("ref-X", 20.0)
        assert t1 != t2

    def test_token_has_two_dot_separated_parts(self, svc: TokenService):
        token, _ = svc.issue("ref-003", 5.0)
        parts = token.split(".")
        assert len(parts) == 2, "Token must be <payload>.<signature>"


# ── Expiry ──────────────────────────────────────────────────────────────────
class TestExpiry:
    def test_expired_token_is_rejected(self):
        svc = TokenService(secret_key=SECRET, ttl=1)
        token, _ = svc.issue("ref-exp", 10.0)

        # Fast-forward time past expiry
        with patch("apex_pay.services.token_service.time") as mock_time:
            mock_time.time.return_value = time.time() + 10
            valid, reason, _ = svc.verify(token)

        assert valid is False
        assert reason == "token_expired"

    def test_token_just_before_expiry_is_valid(self):
        svc = TokenService(secret_key=SECRET, ttl=60)
        token, _ = svc.issue("ref-margin", 10.0)
        valid, reason, _ = svc.verify(token)
        assert valid is True


# ── Tampering ───────────────────────────────────────────────────────────────
class TestTampering:
    def test_modified_payload_fails_signature(self, svc: TokenService):
        token, _ = svc.issue("ref-tamper", 10.0)
        payload_b64, sig = token.split(".")

        # Decode, modify, re-encode
        padding = 4 - len(payload_b64) % 4
        raw = base64.urlsafe_b64decode(payload_b64 + "=" * padding)
        data = json.loads(raw)
        data["amount"] = 99999.99
        forged_payload = base64.urlsafe_b64encode(
            json.dumps(data, sort_keys=True, separators=(",", ":")).encode()
        ).rstrip(b"=").decode()

        forged_token = f"{forged_payload}.{sig}"
        valid, reason, _ = svc.verify(forged_token)

        assert valid is False
        assert reason == "invalid_signature"

    def test_wrong_secret_key_fails(self, svc: TokenService):
        token, _ = svc.issue("ref-key", 10.0)

        other_svc = TokenService(secret_key="different-key", ttl=300)
        valid, reason, _ = other_svc.verify(token)

        assert valid is False
        assert reason == "invalid_signature"


# ── Malformed Input ─────────────────────────────────────────────────────────
class TestMalformedTokens:
    def test_empty_string(self, svc: TokenService):
        valid, reason, _ = svc.verify("")
        assert valid is False
        assert reason == "invalid_token_format"

    def test_no_dot_separator(self, svc: TokenService):
        valid, reason, _ = svc.verify("nodothere")
        assert valid is False
        assert reason == "invalid_token_format"

    def test_three_dots(self, svc: TokenService):
        valid, reason, _ = svc.verify("a.b.c")
        assert valid is False
        assert reason == "invalid_token_format"

    def test_garbage_base64(self, svc: TokenService):
        valid, reason, _ = svc.verify("!!!.!!!")
        assert valid is False
        assert reason in ("invalid_token_format", "invalid_signature")

    def test_none_input_rejected(self, svc: TokenService):
        valid, reason, _ = svc.verify(None)  # type: ignore
        assert valid is False
        assert reason == "invalid_token_format"
