"""Build a ShieldPipeline from `settings.shield`.

Keeping the factory separate from the pipeline class makes tests simple:
tests construct the pipeline directly with in-memory backends, production
constructs it through `build_shield_pipeline()` which respects env config.
"""

from __future__ import annotations

import base64
import json
import logging

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from apex_pay.core.config import settings
from apex_pay.shield.credential_manager import (
    CredentialManager,
    DevCredentialBackend,
    VaultCredentialBackend,
)
from apex_pay.shield.opa_client import OPAClient
from apex_pay.shield.pipeline import ShieldPipeline, ShieldThresholds
from apex_pay.shield.receipt_service import Ed25519KeyRing, ReceiptService
from apex_pay.shield.risk_filter import HeuristicClassifier, LlamaGuardAdapter

logger = logging.getLogger("apex_pay.shield.factory")


def _build_keyring() -> Ed25519KeyRing:
    s = settings.shield
    if s.ed25519_private_b64:
        priv = Ed25519PrivateKey.from_private_bytes(
            base64.b64decode(s.ed25519_private_b64),
        )
        kr = Ed25519KeyRing(
            signing_kid=s.ed25519_kid,
            signing_key=priv,
            public_keys={s.ed25519_kid: priv.public_key()},
        )
    else:
        logger.warning(
            "shield.ed25519_private_b64 is empty — generating an ephemeral key. "
            "Receipts will not verify across process restarts.",
        )
        kr = Ed25519KeyRing.generate(kid=s.ed25519_kid)

    # Extend verification map with any additional public keys (rotation support).
    if s.ed25519_public_keys_json:
        try:
            extra = json.loads(s.ed25519_public_keys_json)
        except json.JSONDecodeError:
            logger.warning("shield.ed25519_public_keys_json is not valid JSON; ignoring.")
            extra = {}
        for kid, b64 in extra.items():
            raw = base64.b64decode(b64)
            kr.public_keys[kid] = Ed25519PublicKey.from_public_bytes(raw)

    return kr


def _build_credential_manager() -> CredentialManager:
    s = settings.shield
    if s.credential_backend == "vault":
        return VaultCredentialBackend(
            vault_addr=s.vault_addr,
            role_id=s.vault_role_id,
            secret_id=s.vault_secret_id,
            secrets_path=s.vault_secrets_path,
            wrap_ttl=s.vault_wrap_ttl,
        )
    # Default: dev backend, reusing the HMAC key.
    return DevCredentialBackend(secret_key=settings.security.hmac_secret_key)


def _build_risk_classifier():
    s = settings.shield
    # Accept both "llama-guard" and "llama_guard" — env files commonly
    # normalise to one style or the other and a silent mismatch would
    # fall through to the heuristic with no indication the SLM isn't
    # actually being consulted.
    backend = (s.risk_backend or "").lower().replace("_", "-")
    if backend == "llama-guard" and s.llama_guard_url:
        logger.info("Shield risk backend: llama-guard at %s", s.llama_guard_url)
        return LlamaGuardAdapter(url=s.llama_guard_url, timeout=30.0)
    logger.info("Shield risk backend: heuristic (no SLM configured)")
    return HeuristicClassifier()


def build_shield_pipeline() -> ShieldPipeline:
    s = settings.shield
    keyring = _build_keyring()
    return ShieldPipeline(
        opa_client=OPAClient(
            opa_url=s.opa_url or None,
            timeout=s.opa_timeout_seconds,
        ),
        risk_classifier=_build_risk_classifier(),
        credential_manager=_build_credential_manager(),
        receipt_service=ReceiptService(
            keyring=keyring,
            policy_version=s.policy_version,
            default_ttl_seconds=s.ephemeral_ttl_seconds,
        ),
        thresholds=ShieldThresholds(
            risk_block=s.risk_block_threshold,
            risk_escalate=s.risk_escalate_threshold,
            entropy_escalate=s.entropy_escalate_threshold,
        ),
        ephemeral_ttl_seconds=s.ephemeral_ttl_seconds,
    )
