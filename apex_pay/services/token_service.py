"""
Cryptographic Token Service
============================
Implements HMAC-SHA256 signed, expiring, single-use payment tokens
as described in the APEX paper (§V.B, §VII.D):

    Token payload = (ref_id, amount, exp)
    VerifyHMAC(payload, signature, key) == True
    exp ≥ t_now
    state(ref_id) == SETTLED  (before consumption)
    state(ref_id) ← CONSUMED  (after consumption)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timezone

from apex_pay.core.config import settings


class TokenService:
    """Issue and verify HMAC-signed payment tokens."""

    def __init__(self, secret_key: str | None = None, ttl: int | None = None):
        self._key = (secret_key or settings.security.hmac_secret_key).encode()
        self._ttl = ttl or settings.security.token_ttl_seconds

    # ── Issue ───────────────────────────────────────────────────────────
    def issue(self, ref_id: str, amount: float) -> tuple[str, int]:
        """Create a signed token for a settled payment.

        Returns:
            (token_string, expiry_unix_timestamp)
        """
        expiry = int(time.time()) + self._ttl
        payload = self._canonical_payload(ref_id, amount, expiry)
        signature = self._sign(payload)
        token = self._encode(payload, signature)
        return token, expiry

    # ── Verify ──────────────────────────────────────────────────────────
    def verify(self, token: str) -> tuple[bool, str, dict]:
        """Verify token signature and expiry.

        Returns:
            (is_valid, reason, decoded_payload)
        """
        try:
            payload_bytes, sig_bytes = self._decode(token)
        except Exception:
            return False, "invalid_token_format", {}

        # Signature check
        expected_sig = self._sign(payload_bytes)
        if not hmac.compare_digest(sig_bytes, expected_sig):
            return False, "invalid_signature", {}

        # Parse payload
        try:
            payload = json.loads(payload_bytes)
        except json.JSONDecodeError:
            return False, "invalid_token_format", {}

        # Expiry check
        if payload.get("exp", 0) < time.time():
            return False, "token_expired", payload

        return True, "valid", payload

    # ── Internal helpers ────────────────────────────────────────────────
    @staticmethod
    def _canonical_payload(ref_id: str, amount: float, expiry: int) -> bytes:
        """Stable JSON serialisation — keys sorted, no whitespace."""
        return json.dumps(
            {"ref_id": ref_id, "amount": amount, "exp": expiry},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()

    def _sign(self, data: bytes) -> bytes:
        return hmac.new(self._key, data, hashlib.sha256).digest()

    @staticmethod
    def _encode(payload: bytes, signature: bytes) -> str:
        """URL-safe base64:  <payload>.<signature>"""
        p = base64.urlsafe_b64encode(payload).rstrip(b"=").decode()
        s = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
        return f"{p}.{s}"

    @staticmethod
    def _decode(token: str) -> tuple[bytes, bytes]:
        parts = token.split(".")
        if len(parts) != 2:
            raise ValueError("Token must have exactly two dot-separated parts.")

        def _pad(b64: str) -> bytes:
            padding = 4 - len(b64) % 4
            return base64.urlsafe_b64decode(b64 + "=" * padding)

        return _pad(parts[0]), _pad(parts[1])
