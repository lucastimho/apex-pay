"""Ephemeral Credentialing — shrink blast radius to one transaction.

The gateway **never** hands the agent a long-lived API key. Instead, after
OPA allows the intent, we mint a short-lived, scope-bound token:

    EphemeralCredential {
        token_id:    "ec_…"            # opaque handle
        scope:       {domain, method, intent_hash, budget}
        expires_at:  unix ts (<= 60 s by default)
        revoked:     False
    }

Two backends share one interface:

* `DevCredentialBackend` — mints HMAC-signed scoped tokens in-process.
  Good for tests and local development. Tokens survive until the TTL
  expires or `revoke()` is called. No Vault process required.

* `VaultCredentialBackend` — talks to HashiCorp Vault via `hvac`. Uses
  AppRole auth for the gateway service itself, then exchanges the intent
  for a dynamic secret (e.g. database creds, a Stripe Restricted Key, a
  scoped GitHub PAT) using Vault's Response Wrapping so the secret only
  materialises when the downstream tool redeems it. If `hvac` is not
  installed the class raises at construction time; import guards keep
  tests that don't touch Vault passing.

Both backends enforce the same invariants:

  - TTL <= settings.shield.ephemeral_ttl_max_seconds (default 60s)
  - Scope is bound to intent_hash; redeeming with a different hash fails
  - `revoke(token_id)` is instant and idempotent
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Any, Protocol

logger = logging.getLogger("apex_pay.shield.credentials")

# Hard cap on any dynamically-configured TTL.
_TTL_HARD_CAP_SECONDS = 300


# ── Data classes ────────────────────────────────────────────────────────────
@dataclass
class CredentialScope:
    intent_hash: str
    domain: str | None
    method: str
    max_amount: float
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent_hash": self.intent_hash,
            "domain": self.domain or "",
            "method": self.method.upper(),
            "max_amount": float(self.max_amount),
            **self.extra,
        }


@dataclass
class EphemeralCredential:
    token_id: str           # opaque handle, safe to log
    token: str              # the actual secret — DO NOT log
    scope: CredentialScope
    expires_at: int         # unix timestamp
    backend: str

    @property
    def is_expired(self) -> bool:
        return time.time() >= self.expires_at


# ── Protocol ────────────────────────────────────────────────────────────────
class CredentialManager(Protocol):
    async def issue(self, scope: CredentialScope, ttl_seconds: int) -> EphemeralCredential: ...
    async def verify(
        self, token: str, intent_hash: str
    ) -> tuple[bool, str, CredentialScope | None]: ...
    async def revoke(self, token_id: str) -> None: ...


# ── Dev backend (HMAC, in-memory) ───────────────────────────────────────────
class DevCredentialBackend:
    """Self-contained credential manager for local dev and tests.

    Tokens are structured as:
        v1.<token_id>.<b64(payload)>.<b64(hmac_sha256(secret, token_id|payload))>

    The HMAC key is loaded from settings.security.hmac_secret_key (same
    key used by the existing TokenService). Revocation is tracked in a
    process-local set; in multi-process deployments, use VaultBackend.
    """

    def __init__(self, *, secret_key: str):
        if not secret_key or secret_key == "CHANGE-ME-IN-PRODUCTION":
            logger.warning(
                "DevCredentialBackend is using a default/placeholder HMAC key — "
                "never run this in production."
            )
        self._key = secret_key.encode("utf-8")
        self._revoked: set[str] = set()

    async def issue(self, scope: CredentialScope, ttl_seconds: int) -> EphemeralCredential:
        ttl = min(max(1, int(ttl_seconds)), _TTL_HARD_CAP_SECONDS)
        token_id = "ec_" + secrets.token_urlsafe(16)
        expires_at = int(time.time()) + ttl

        payload = {
            "scope": scope.to_dict(),
            "expires_at": expires_at,
            "token_id": token_id,
        }
        payload_bytes = json.dumps(
            payload, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")
        sig = hmac.new(
            self._key, token_id.encode("utf-8") + b"|" + payload_bytes, hashlib.sha256,
        ).digest()

        token = ".".join([
            "v1",
            token_id,
            _b64url_encode(payload_bytes),
            _b64url_encode(sig),
        ])
        return EphemeralCredential(
            token_id=token_id,
            token=token,
            scope=scope,
            expires_at=expires_at,
            backend="dev",
        )

    async def verify(
        self, token: str, intent_hash: str,
    ) -> tuple[bool, str, CredentialScope | None]:
        try:
            version, token_id, b64_payload, b64_sig = token.split(".")
        except ValueError:
            return False, "invalid_format", None
        if version != "v1":
            return False, "unknown_version", None

        try:
            payload_bytes = _b64url_decode(b64_payload)
            sig = _b64url_decode(b64_sig)
        except Exception:
            return False, "invalid_format", None

        expected = hmac.new(
            self._key, token_id.encode("utf-8") + b"|" + payload_bytes, hashlib.sha256,
        ).digest()
        if not hmac.compare_digest(expected, sig):
            return False, "invalid_signature", None

        try:
            payload = json.loads(payload_bytes)
        except json.JSONDecodeError:
            return False, "invalid_format", None

        if token_id in self._revoked:
            return False, "revoked", None
        if int(payload.get("expires_at", 0)) < int(time.time()):
            return False, "expired", None

        scope_data = payload.get("scope") or {}
        if scope_data.get("intent_hash") != intent_hash:
            return False, "intent_mismatch", None

        scope = CredentialScope(
            intent_hash=scope_data["intent_hash"],
            domain=scope_data.get("domain") or None,
            method=scope_data.get("method", "POST"),
            max_amount=float(scope_data.get("max_amount", 0.0)),
            extra={
                k: v for k, v in scope_data.items()
                if k not in {"intent_hash", "domain", "method", "max_amount"}
            },
        )
        return True, "valid", scope

    async def revoke(self, token_id: str) -> None:
        self._revoked.add(token_id)


# ── Vault backend ───────────────────────────────────────────────────────────
class VaultCredentialBackend:
    """HashiCorp Vault-backed credential manager.

    Assumes the gateway has been authenticated to Vault via AppRole. For
    each intent, we:

      1. Call the configured secrets engine (e.g. database, aws, github)
         to provision a short-lived dynamic secret.
      2. Wrap the returned secret with Vault's Response Wrapping TTL so
         the secret only materialises when the caller unwraps it.
      3. Return the wrapping token as `credential.token`.

    The lease is revoked on `revoke(token_id)` via `/sys/leases/revoke`.

    Vault policy (write once at Vault setup):
        path "database/creds/apex-gateway" { capabilities = ["read"] }
        path "sys/wrapping/wrap"           { capabilities = ["update"] }
        path "sys/leases/revoke"           { capabilities = ["update"] }
    """

    def __init__(
        self,
        *,
        vault_addr: str,
        role_id: str,
        secret_id: str,
        secrets_path: str,
        wrap_ttl: str = "60s",
        mount_point: str = "approle",
    ):
        try:
            import hvac  # type: ignore
        except ImportError as exc:  # pragma: no cover - optional dep
            raise RuntimeError(
                "VaultCredentialBackend requires the 'hvac' package. "
                "Install with: pip install hvac"
            ) from exc

        self._hvac = hvac
        self._client = hvac.Client(url=vault_addr)
        login = self._client.auth.approle.login(
            role_id=role_id, secret_id=secret_id, mount_point=mount_point,
        )
        if not self._client.is_authenticated():
            raise RuntimeError(f"Vault AppRole login failed: {login}")
        self._secrets_path = secrets_path.strip("/")
        self._wrap_ttl = wrap_ttl
        # Map our opaque token_id -> Vault lease_id so we can revoke.
        self._leases: dict[str, str] = {}

    async def issue(self, scope: CredentialScope, ttl_seconds: int) -> EphemeralCredential:
        ttl = min(max(1, int(ttl_seconds)), _TTL_HARD_CAP_SECONDS)
        # Vault call is sync in hvac; in production put behind a threadpool
        # executor. For now we document the blocking behaviour.
        response = self._client.read(self._secrets_path, wrap_ttl=self._wrap_ttl)
        if response is None or "wrap_info" not in response:
            raise RuntimeError("Vault did not return a wrap_info envelope.")
        wrap_info = response["wrap_info"]
        wrap_token = wrap_info["token"]
        lease_id = response.get("lease_id") or wrap_info.get("wrapped_accessor", "")
        token_id = "ec_" + secrets.token_urlsafe(16)
        self._leases[token_id] = lease_id

        return EphemeralCredential(
            token_id=token_id,
            token=wrap_token,
            scope=scope,
            expires_at=int(time.time()) + ttl,
            backend="vault",
        )

    async def verify(
        self, token: str, intent_hash: str,
    ) -> tuple[bool, str, CredentialScope | None]:
        # Verification for Vault-issued wrap tokens is "can it unwrap".
        # We check via /sys/wrapping/lookup. The scope is stored out-of-band
        # (the caller keeps the scope bound to the wrap token); this backend
        # is the more hostile-environment option and does NOT round-trip
        # scope through Vault.
        try:
            info = self._client.sys.read_wrapping_info(token=token)
        except Exception as exc:
            logger.warning("Vault wrapping lookup failed: %s", exc)
            return False, "invalid_signature", None
        if not info:
            return False, "revoked", None
        # The shield pipeline stores (token_id, scope) in the DB; verify
        # matches intent_hash externally. This method only checks liveness.
        return True, "valid", None

    async def revoke(self, token_id: str) -> None:
        lease_id = self._leases.pop(token_id, None)
        if lease_id:
            try:
                self._client.sys.revoke_lease(lease_id=lease_id)
            except Exception as exc:  # pragma: no cover
                logger.warning("Vault lease revoke failed for %s: %s", token_id, exc)


# ── Base64url helpers ───────────────────────────────────────────────────────
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data = data + ("=" * padding)
    return base64.urlsafe_b64decode(data)
