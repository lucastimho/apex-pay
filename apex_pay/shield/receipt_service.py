"""Ed25519 Signed Execution Receipts — non-repudiation for approved intents.

For every approved tool-call the gateway emits a Signed Receipt:

    ReceiptV1 = {
        "v":              1,
        "intent_hash":    "sha256-hex",
        "agent_id":       "uuid",
        "policy_version": "2026.04.17",
        "risk_score":     0.12,
        "token_id":       "ec_…",            # the ephemeral credential handle
        "kid":            "key-2026-04",     # signing-key identifier
        "issued_at":      1713369600,
        "expires_at":     1713369660,
    }

    signature = Ed25519(priv_key, canonical_json(ReceiptV1))

The receipt is:
  * stored in the audit log (non-repudiation for operators)
  * returned to the agent (non-repudiation for the agent)
  * verifiable by any third party holding the public key

Math: V(A) = P(A) ∧ Sig_{K_priv}(H(A))
  where P(A) is the OPA decision and H(A) is `intent_hash`.

Keys are loaded via `Ed25519KeyRing`:
  * From raw base64 in env (APEX_SHIELD_ED25519_PRIV_B64) for dev
  * From a JSON keyring file for staging
  * Or wrapped — from Vault's transit engine — in production. The
    KeyRing is deliberately replaceable so you never need to leak a
    private key into the Python process.

Rotation: multiple public keys are kept in the verification map keyed by
`kid`; the current signing key is one of them. Rotating is "issue new
kid, stop signing with old kid, keep verifying with old kid until all
receipts expire".
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

logger = logging.getLogger("apex_pay.shield.receipt")

RECEIPT_VERSION = 1


# ── Data ────────────────────────────────────────────────────────────────────
@dataclass
class SignedReceipt:
    receipt: dict[str, Any]
    signature_b64: str
    kid: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "receipt": self.receipt,
            "signature": self.signature_b64,
            "kid": self.kid,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SignedReceipt":
        return cls(
            receipt=data["receipt"],
            signature_b64=data["signature"],
            kid=data["kid"],
        )


# ── Keyring ─────────────────────────────────────────────────────────────────
@dataclass
class Ed25519KeyRing:
    """Holds the current signing key and a map of kid -> public key."""

    signing_kid: str
    signing_key: Ed25519PrivateKey
    public_keys: dict[str, Ed25519PublicKey] = field(default_factory=dict)

    def verify_key_for(self, kid: str) -> Ed25519PublicKey | None:
        return self.public_keys.get(kid)

    @classmethod
    def generate(cls, kid: str = "key-ephemeral") -> "Ed25519KeyRing":
        priv = Ed25519PrivateKey.generate()
        pub = priv.public_key()
        return cls(signing_kid=kid, signing_key=priv, public_keys={kid: pub})

    @classmethod
    def from_env(cls, *, env_priv: str = "APEX_SHIELD_ED25519_PRIV_B64",
                 env_kid: str = "APEX_SHIELD_ED25519_KID") -> "Ed25519KeyRing":
        priv_b64 = os.getenv(env_priv, "")
        kid = os.getenv(env_kid, "key-env")
        if not priv_b64:
            logger.warning(
                "No %s set — generating an ephemeral signing key. Receipts will "
                "verify within this process but not across restarts.",
                env_priv,
            )
            return cls.generate(kid=kid)
        raw = base64.b64decode(priv_b64)
        priv = Ed25519PrivateKey.from_private_bytes(raw)
        return cls(
            signing_kid=kid,
            signing_key=priv,
            public_keys={kid: priv.public_key()},
        )

    def export_public_key_b64(self, kid: str | None = None) -> str:
        k = self.public_keys[kid or self.signing_kid]
        raw = k.public_bytes(Encoding.Raw, PublicFormat.Raw)
        return base64.b64encode(raw).decode("ascii")

    def export_private_key_b64(self) -> str:
        raw = self.signing_key.private_bytes(
            Encoding.Raw, PrivateFormat.Raw, NoEncryption(),
        )
        return base64.b64encode(raw).decode("ascii")


# ── Service ─────────────────────────────────────────────────────────────────
class ReceiptService:
    """Sign approved intents and verify incoming receipts."""

    def __init__(
        self,
        *,
        keyring: Ed25519KeyRing,
        policy_version: str,
        default_ttl_seconds: int = 300,
    ):
        self._keyring = keyring
        self._policy_version = policy_version
        self._ttl = default_ttl_seconds

    # ── Issue ───────────────────────────────────────────────────────────
    def sign(
        self,
        *,
        intent_hash: str,
        agent_id: str,
        token_id: str,
        risk_score: float,
        extra: dict[str, Any] | None = None,
        ttl_seconds: int | None = None,
    ) -> SignedReceipt:
        now = int(time.time())
        ttl = ttl_seconds or self._ttl
        receipt = {
            "v": RECEIPT_VERSION,
            "intent_hash": intent_hash,
            "agent_id": agent_id,
            "policy_version": self._policy_version,
            "risk_score": round(float(risk_score), 4),
            "token_id": token_id,
            "kid": self._keyring.signing_kid,
            "issued_at": now,
            "expires_at": now + ttl,
        }
        if extra:
            receipt["extra"] = extra

        canonical = _canonical_json(receipt)
        sig = self._keyring.signing_key.sign(canonical)
        return SignedReceipt(
            receipt=receipt,
            signature_b64=base64.b64encode(sig).decode("ascii"),
            kid=self._keyring.signing_kid,
        )

    # ── Verify ──────────────────────────────────────────────────────────
    def verify(self, signed: SignedReceipt) -> tuple[bool, str]:
        receipt = signed.receipt
        if receipt.get("v") != RECEIPT_VERSION:
            return False, "unsupported_receipt_version"

        pub = self._keyring.verify_key_for(signed.kid)
        if pub is None:
            return False, "unknown_kid"

        try:
            sig = base64.b64decode(signed.signature_b64)
        except Exception:
            return False, "malformed_signature"

        canonical = _canonical_json(receipt)
        try:
            pub.verify(sig, canonical)
        except InvalidSignature:
            return False, "invalid_signature"

        if int(receipt.get("expires_at", 0)) < int(time.time()):
            return False, "expired"

        return True, "valid"


def _canonical_json(obj: dict[str, Any]) -> bytes:
    """Deterministic JSON encoding used for both signing and verification."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
