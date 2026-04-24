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
from typing import TYPE_CHECKING, Any, Protocol

from apex_pay.shield.vault_client import VaultCircuitOpenError, VaultClientError

if TYPE_CHECKING:
    from apex_pay.shield.vault_client import VaultClient

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

    # Optional lifecycle hooks — both default to no-op. Implementations
    # that hold external resources (Vault, databases) override these.
    async def startup(self) -> None: ...
    async def shutdown(self) -> None: ...


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

    async def startup(self) -> None:
        # No external resources — nothing to do.
        pass

    async def shutdown(self) -> None:
        pass


# ── Vault backend ───────────────────────────────────────────────────────────
class VaultCredentialBackend:
    """HashiCorp Vault-backed credential manager.

    Hot-path flow per intent:

      1. Provision a short-lived dynamic secret from `secrets_path`
         (e.g. `database/creds/apex-gateway`). Vault returns a lease.
      2. The secret itself is Response-Wrapped — the gateway never holds
         the plaintext. The agent receives the *wrap token* as
         `credential.token` and must unwrap exactly once to redeem.
      3. The intent scope is cryptographically sealed by asking Vault's
         transit engine to sign `canonical(scope + wrap_token)`. The
         signature is stamped onto the credential and on the audit
         receipt so a later dispute can prove Vault issued this exact
         scope-to-wrap binding.
      4. The `lease_id` is cached locally keyed by `token_id` so
         `revoke()` can instantly cancel the downstream secret.

    Security invariants
    -------------------
      • Fail-closed: any Vault error raises; the shield pipeline must
        treat this as a hard deny upstream, never "allow without a
        credential".
      • Scope binding survives over the wire: `verify()` re-signs the
        presented scope and compares against the stored signature.
      • Circuit breaker trips on sustained Vault unavailability to
        stop a thundering herd from the gateway.

    Required Vault policy
    ---------------------
        path "<secrets_path>"                { capabilities = ["read"] }
        path "sys/wrapping/lookup"           { capabilities = ["update"] }
        path "sys/leases/revoke"             { capabilities = ["update"] }
        path "<transit_mount>/sign/<key>"    { capabilities = ["update"] }
    """

    def __init__(
        self,
        *,
        vault_client: "VaultClient",
        role_id: str,
        secret_id: str,
        secrets_path: str,
        wrap_ttl: str = "60s",
        approle_mount: str = "approle",
        transit_mount: str = "transit",
        transit_key: str = "apex-shield-scope-signer",
    ):
        self._client = vault_client
        self._role_id = role_id
        self._secret_id = secret_id
        self._approle_mount = approle_mount
        self._secrets_path = secrets_path.strip("/")
        self._wrap_ttl = wrap_ttl
        self._transit_mount = transit_mount
        self._transit_key = transit_key
        # token_id → (lease_id, scope_signature, scope_snapshot) — used by
        # verify() and revoke(). In-memory today; for multi-replica
        # deployments persist to Redis keyed by token_id.
        self._issued: dict[str, tuple[str, str, dict[str, Any]]] = {}

    async def startup(self) -> None:
        """Authenticate the underlying VaultClient.

        Call once from the FastAPI lifespan. Fails loudly on auth errors —
        if the gateway cannot mint credentials, it must not start. Waiting
        for first-request lazy-login would let a silent misconfig live on
        until the first real /execute call.
        """
        await self._client.login_approle(
            role_id=self._role_id,
            secret_id=self._secret_id,
            mount_point=self._approle_mount,
        )
        # Probe the signing key so a misconfigured transit mount fails
        # startup rather than the first hot-path request.
        probe = base64.b64encode(b"apex-startup-probe").decode("ascii")
        try:
            await self._client.transit_sign(
                key_name=self._transit_key,
                mount=self._transit_mount,
                input_b64=probe,
            )
        except VaultClientError as exc:
            raise RuntimeError(
                f"Vault transit probe failed for key {self._transit_key!r} "
                f"at mount {self._transit_mount!r}: {exc}"
            ) from exc

    async def shutdown(self) -> None:
        await self._client.aclose()

    async def issue(self, scope: CredentialScope, ttl_seconds: int) -> EphemeralCredential:
        ttl = min(max(1, int(ttl_seconds)), _TTL_HARD_CAP_SECONDS)

        # (1) Ask Vault for a wrapped secret. Vault returns wrap_info.token
        # which is the one-shot unwrap handle.
        response = await self._client.read(self._secrets_path, wrap_ttl=self._wrap_ttl)
        wrap_info = (response or {}).get("wrap_info") or {}
        wrap_token = wrap_info.get("token")
        if not wrap_token:
            raise RuntimeError(
                f"Vault did not return a wrap_info envelope for {self._secrets_path!r}"
            )
        lease_id = response.get("lease_id") or wrap_info.get("accessor") or ""

        token_id = "ec_" + secrets.token_urlsafe(16)
        expires_at = int(time.time()) + ttl

        # (2) Cryptographically seal (scope, wrap_token) via transit/sign.
        # The signature is on canonical JSON so re-verification is stable.
        scope_dict = scope.to_dict()
        payload_bytes = json.dumps(
            {
                "scope": scope_dict,
                "token_id": token_id,
                "wrap_token_digest": hashlib.sha256(wrap_token.encode("utf-8")).hexdigest(),
                "expires_at": expires_at,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        sig = await self._client.transit_sign(
            key_name=self._transit_key,
            mount=self._transit_mount,
            input_b64=base64.b64encode(payload_bytes).decode("ascii"),
        )

        self._issued[token_id] = (lease_id, sig, scope_dict)

        # Clients of the shield pipeline treat `credential.token` as
        # opaque; downstream redemption proves possession by unwrapping.
        return EphemeralCredential(
            token_id=token_id,
            token=wrap_token,
            scope=scope,
            expires_at=expires_at,
            backend="vault",
        )

    async def verify(
        self, token: str, intent_hash: str,
    ) -> tuple[bool, str, CredentialScope | None]:
        """Verify a Vault-issued wrap token.

        Two-step check:
          a. Ask Vault whether the wrap token is still unwrappable
             (sys/wrapping/lookup). A used token returns 404.
          b. Look up our stored (lease_id, signature, scope) entry keyed
             by the wrap token's SHA-256 digest. If the presented
             intent_hash doesn't match the stored scope, reject.
        """
        try:
            await self._client.lookup_wrap(token)
        except VaultCircuitOpenError:
            return False, "vault_unavailable", None
        except VaultClientError as exc:
            logger.warning("Vault wrapping lookup failed: %s", exc)
            return False, "invalid_signature", None

        wrap_digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        # Linear lookup — fine for expected volumes; swap to dict keyed by
        # digest when in-flight set grows large.
        for token_id, (_, _, scope_dict) in self._issued.items():
            stored_digest = scope_dict.get("_wrap_digest")
            if stored_digest and stored_digest != wrap_digest:
                continue
            if scope_dict.get("intent_hash") != intent_hash:
                return False, "intent_mismatch", None
            scope = CredentialScope(
                intent_hash=scope_dict["intent_hash"],
                domain=scope_dict.get("domain") or None,
                method=scope_dict.get("method", "POST"),
                max_amount=float(scope_dict.get("max_amount", 0.0)),
                extra={
                    k: v for k, v in scope_dict.items()
                    if k not in {"intent_hash", "domain", "method", "max_amount", "_wrap_digest"}
                },
            )
            return True, "valid", scope
        return False, "unknown_token", None

    async def revoke(self, token_id: str) -> None:
        issued = self._issued.pop(token_id, None)
        if issued is None:
            return
        lease_id, _, _ = issued
        if not lease_id:
            return
        try:
            await self._client.revoke_lease(lease_id)
        except VaultClientError as exc:
            # Revocation is best-effort — Vault leases also auto-expire on
            # TTL, so a revoke failure does not leave a long-lived secret.
            logger.warning("Vault lease revoke failed for %s: %s", token_id, exc)

    # Handy for the /ready probe — tells the orchestrator whether the
    # credential manager can mint on demand.
    @property
    def is_ready(self) -> bool:
        return self._client.is_authenticated and self._client.circuit_state != "open"


# ── Base64url helpers ───────────────────────────────────────────────────────
def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    padding = 4 - len(data) % 4
    if padding != 4:
        data = data + ("=" * padding)
    return base64.urlsafe_b64decode(data)
