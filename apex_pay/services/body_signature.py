"""Request-body Ed25519 signature verification.

Blueprint §5.1: agents authenticate with mTLS AND a per-request body
signature. mTLS is terminated at the edge and belongs to ingress config;
the body signature lives in the app so every downstream handler can rely
on the invariant "if this handler ran, the agent proved ownership of the
body".

Wire format:

    POST /execute
    Content-Type: application/json
    X-APEX-Agent-ID: <uuid>
    X-APEX-Signature: ed25519:<base64(signature_over_raw_body)>

The signature is computed over the exact bytes of the request body with
the agent's Ed25519 private key; the gateway verifies against the public
key stored in `agents.public_key`.

Public key encoding:

* `agents.public_key` is TEXT and stores the raw 32-byte Ed25519 public
  key as URL-safe base64 (no padding). This is the same encoding the JWKS
  endpoint emits, so operators can copy a kid's "x" field straight in.

Failure modes are explicit and metricized (see metrics.SIGNATURE_REJECTIONS).
"""

from __future__ import annotations

import base64
import logging
import uuid
from dataclasses import dataclass
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

logger = logging.getLogger("apex_pay.body_signature")

SignatureVerdict = Literal["ok", "missing", "malformed", "invalid", "unknown_agent"]


@dataclass
class BodySignatureResult:
    verdict: SignatureVerdict
    reason: str


def _b64url_decode(data: str) -> bytes:
    """Decode URL-safe base64 with optional padding stripped."""
    padded = data + "=" * (-len(data) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        return base64.b64decode(padded.encode("ascii"))


def parse_signature_header(header: str | None) -> bytes | None:
    """Parse `ed25519:<b64>` → raw signature bytes. Returns None on malformed."""
    if not header:
        return None
    try:
        scheme, _, payload = header.partition(":")
        if scheme.lower() != "ed25519" or not payload:
            return None
        return _b64url_decode(payload)
    except Exception:
        return None


def load_public_key(encoded: str) -> Ed25519PublicKey | None:
    """Parse the `agents.public_key` text into an Ed25519PublicKey."""
    try:
        raw = _b64url_decode(encoded.strip())
        if len(raw) != 32:
            return None
        return Ed25519PublicKey.from_public_bytes(raw)
    except Exception:
        return None


def verify_body(
    *,
    public_key_encoded: str | None,
    body: bytes,
    signature_header: str | None,
) -> BodySignatureResult:
    """Pure function: given the stored public key and the raw request body,
    return a verdict. No DB / network here so the verifier is unit-testable.
    """
    sig = parse_signature_header(signature_header)
    if sig is None:
        if signature_header is None:
            return BodySignatureResult("missing", "missing_signature_header")
        return BodySignatureResult("malformed", "malformed_signature_header")

    if not public_key_encoded:
        return BodySignatureResult("unknown_agent", "no_public_key_on_record")

    pub = load_public_key(public_key_encoded)
    if pub is None:
        return BodySignatureResult("malformed", "agent_public_key_unparseable")

    try:
        pub.verify(sig, body)
    except InvalidSignature:
        return BodySignatureResult("invalid", "signature_mismatch")
    except Exception as exc:
        logger.warning("Unexpected verify error (%s) — treating as invalid.", exc)
        return BodySignatureResult("invalid", "signature_verify_error")

    return BodySignatureResult("ok", "valid")
