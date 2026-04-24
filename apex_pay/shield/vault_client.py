"""Async HashiCorp Vault client for APEX-Shield.

Why write our own instead of using hvac
---------------------------------------
`hvac` is synchronous and would block the asyncio event loop on every call.
The gateway sees Vault on the hot path of every APPROVED intent, so blocking
I/O there would cap throughput at one-in-flight-per-worker. We use `httpx`
AsyncClient directly and pay the price of a thinner API.

Threat model for this client
----------------------------
  • Vault MUST be fail-closed: if we cannot authenticate or mint a token,
    the gateway must deny (not allow) the downstream intent.
  • AppRole secret_id is a long-lived secret on disk; it's scoped to the
    one `role_id` it was issued for and to a specific CIDR set at Vault.
  • The service token returned by AppRole login is short-lived. We refresh
    at 80% of TTL with a +/-10% jitter so a fleet doesn't stampede Vault
    at the same moment.
  • On repeated failure we trip a circuit breaker to avoid amplifying a
    Vault outage into a connection storm. Half-open probe after cooldown.

Public surface
--------------
  • `VaultClient(addr, verify=...)` — construct
  • `await client.login_approle(role_id, secret_id)` — bootstrap
  • `await client.read(path, wrap_ttl=None)` — KV / secret read, optionally
    with response wrapping
  • `await client.write(path, payload, wrap_ttl=None)` — e.g. DB creds
  • `await client.revoke_lease(lease_id)` — explicit revocation
  • `await client.lookup_wrap(token)` — check wrapped token liveness
  • `await client.transit_sign(key, payload_b64)` — Ed25519 or HMAC signing
    via transit engine so the gateway never holds the signing key
  • `await client.health()` — GET /v1/sys/health, for /ready

All methods raise `VaultClientError` on failure. Callers decide whether
that means HTTP 503 (infrastructure) or HTTP 401 (auth).
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Any, Literal

import httpx

logger = logging.getLogger("apex_pay.shield.vault")

# ── Exceptions ──────────────────────────────────────────────────────────────


class VaultClientError(RuntimeError):
    """Base class for Vault client failures."""


class VaultAuthError(VaultClientError):
    """Authentication to Vault failed (wrong role_id/secret_id, CIDR block)."""


class VaultCircuitOpenError(VaultClientError):
    """Circuit breaker is currently open; request refused fast."""


# ── Circuit breaker ─────────────────────────────────────────────────────────


@dataclass
class _CircuitBreaker:
    """Three-state circuit breaker — closed/open/half_open.

    Closed: requests flow normally. N consecutive failures → open.
    Open:   requests refused immediately for `cooldown_seconds`.
    Half-open: one probe allowed; success closes, failure re-opens.
    """

    failure_threshold: int = 3
    cooldown_seconds: float = 10.0

    _state: Literal["closed", "open", "half_open"] = field(default="closed")
    _consecutive_failures: int = field(default=0)
    _opened_at: float = field(default=0.0)

    @property
    def state(self) -> str:
        return self._state

    def allow(self) -> bool:
        if self._state == "open":
            if time.monotonic() - self._opened_at >= self.cooldown_seconds:
                self._state = "half_open"
                return True
            return False
        return True

    def record_success(self) -> None:
        self._state = "closed"
        self._consecutive_failures = 0

    def record_failure(self) -> None:
        self._consecutive_failures += 1
        if self._state == "half_open" or self._consecutive_failures >= self.failure_threshold:
            self._state = "open"
            self._opened_at = time.monotonic()


# ── Token lease ─────────────────────────────────────────────────────────────


@dataclass
class _ServiceToken:
    """Vault service token granted after AppRole login."""

    token: str
    expires_at: float           # monotonic seconds
    renewable: bool
    policies: list[str]

    @property
    def ttl_remaining(self) -> float:
        return max(0.0, self.expires_at - time.monotonic())

    def should_renew(self, threshold_fraction: float = 0.2) -> bool:
        """Renew when <20% of the original TTL remains (with jitter).

        Jitter prevents a fleet of gateways from all renewing at the exact
        same moment after a coordinated restart.
        """
        jitter = random.uniform(-0.05, 0.05)
        return self.ttl_remaining / max(self.ttl_remaining + 1, 1) < (threshold_fraction + jitter)


# ── The client ──────────────────────────────────────────────────────────────


class VaultClient:
    """Thin async httpx client for Vault's HTTP API.

    Intentionally narrow — only the endpoints APEX-Shield needs. Add new
    endpoint methods as you add new Vault integrations; don't reach for
    the raw `_request` helper from outside this module.
    """

    def __init__(
        self,
        *,
        addr: str,
        verify: bool | str = True,
        request_timeout: float = 5.0,
        failure_threshold: int = 3,
        cooldown_seconds: float = 10.0,
    ) -> None:
        if not addr:
            raise ValueError("Vault address is required")
        self._addr = addr.rstrip("/")
        self._timeout = httpx.Timeout(request_timeout)
        self._verify = verify
        self._client: httpx.AsyncClient | None = None
        self._token: _ServiceToken | None = None
        self._approle: tuple[str, str, str] | None = None  # (role_id, secret_id, mount)
        self._breaker = _CircuitBreaker(
            failure_threshold=failure_threshold,
            cooldown_seconds=cooldown_seconds,
        )
        self._token_lock = asyncio.Lock()

    # ── Lifecycle ───────────────────────────────────────────────────────
    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self._addr,
                timeout=self._timeout,
                verify=self._verify,
            )
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # ── Auth ─────────────────────────────────────────────────────────────
    async def login_approle(
        self,
        *,
        role_id: str,
        secret_id: str,
        mount_point: str = "approle",
    ) -> None:
        """Authenticate with AppRole. Stores the service token internally.

        Fail-closed: on auth error raises VaultAuthError; caller must treat
        this as a hard failure and not proceed with hot-path work.
        """
        self._approle = (role_id, secret_id, mount_point)
        data = await self._request(
            "POST",
            f"/v1/auth/{mount_point}/login",
            json={"role_id": role_id, "secret_id": secret_id},
            skip_auth=True,
        )
        auth = data.get("auth") or {}
        token = auth.get("client_token")
        if not token:
            raise VaultAuthError(f"AppRole login returned no client_token: {data}")
        self._token = _ServiceToken(
            token=token,
            expires_at=time.monotonic() + int(auth.get("lease_duration", 3600)),
            renewable=bool(auth.get("renewable", False)),
            policies=list(auth.get("policies", [])),
        )
        logger.info(
            "Vault AppRole auth succeeded, policies=%s, ttl=%ds",
            self._token.policies,
            int(self._token.ttl_remaining),
        )

    async def _renew_if_needed(self) -> None:
        if self._token is None:
            raise VaultAuthError("Not authenticated — call login_approle() first")
        async with self._token_lock:
            if not self._token.should_renew():
                return
            # If the token is non-renewable, re-login with the cached AppRole.
            if not self._token.renewable:
                if self._approle is None:
                    raise VaultAuthError("Token expired and no AppRole cached")
                role_id, secret_id, mount = self._approle
                # Drop the token so _request won't try to use the dying one.
                self._token = None
                await self.login_approle(role_id=role_id, secret_id=secret_id, mount_point=mount)
                return
            # Renewable token — refresh via /v1/auth/token/renew-self.
            try:
                data = await self._request("POST", "/v1/auth/token/renew-self", json={})
                auth = data.get("auth") or {}
                self._token.expires_at = time.monotonic() + int(auth.get("lease_duration", 3600))
                logger.debug("Vault token renewed, new ttl=%ds", int(self._token.ttl_remaining))
            except VaultClientError as exc:
                logger.warning("Vault token renew failed (%s); falling back to re-login", exc)
                if self._approle is None:
                    raise
                role_id, secret_id, mount = self._approle
                self._token = None
                await self.login_approle(role_id=role_id, secret_id=secret_id, mount_point=mount)

    # ── Core request ─────────────────────────────────────────────────────
    async def _request(
        self,
        method: str,
        path: str,
        *,
        json: dict[str, Any] | None = None,
        wrap_ttl: str | None = None,
        skip_auth: bool = False,
    ) -> dict[str, Any]:
        if not self._breaker.allow():
            raise VaultCircuitOpenError(
                f"Vault circuit breaker open (state={self._breaker.state})"
            )

        if not skip_auth:
            await self._renew_if_needed()

        client = await self._ensure_client()
        headers: dict[str, str] = {}
        if not skip_auth and self._token is not None:
            headers["X-Vault-Token"] = self._token.token
        if wrap_ttl:
            headers["X-Vault-Wrap-TTL"] = wrap_ttl

        try:
            resp = await client.request(method, path, json=json, headers=headers)
        except httpx.HTTPError as exc:
            self._breaker.record_failure()
            raise VaultClientError(f"Vault request {method} {path} failed: {exc}") from exc

        if resp.status_code >= 500:
            self._breaker.record_failure()
            raise VaultClientError(
                f"Vault {method} {path} returned {resp.status_code}: {resp.text[:200]}"
            )
        if resp.status_code in (401, 403):
            self._breaker.record_failure()
            raise VaultAuthError(f"Vault rejected request: {resp.status_code} {resp.text[:200]}")
        if resp.status_code >= 400:
            # 4xx other than auth is a caller error, NOT a circuit-breaker signal.
            raise VaultClientError(
                f"Vault {method} {path} client error {resp.status_code}: {resp.text[:200]}"
            )

        self._breaker.record_success()

        if resp.status_code == 204:
            return {}
        try:
            return resp.json()
        except ValueError as exc:
            raise VaultClientError(f"Vault returned non-JSON body: {exc}") from exc

    # ── Public endpoints ────────────────────────────────────────────────

    async def health(self) -> dict[str, Any]:
        """GET /v1/sys/health — returns {initialized, sealed, standby, ...}.

        Vault returns non-200 for a sealed/standby instance; we remap to a
        normal dict for easier use in /ready probes.
        """
        client = await self._ensure_client()
        try:
            resp = await client.get("/v1/sys/health")
            return resp.json() if resp.content else {"status_code": resp.status_code}
        except httpx.HTTPError as exc:
            raise VaultClientError(f"Vault health check failed: {exc}") from exc

    async def read(self, path: str, *, wrap_ttl: str | None = None) -> dict[str, Any]:
        """GET /v1/<path>, optionally response-wrapped."""
        return await self._request("GET", f"/v1/{path.lstrip('/')}", wrap_ttl=wrap_ttl)

    async def write(
        self,
        path: str,
        payload: dict[str, Any],
        *,
        wrap_ttl: str | None = None,
    ) -> dict[str, Any]:
        """POST /v1/<path>."""
        return await self._request(
            "POST", f"/v1/{path.lstrip('/')}", json=payload, wrap_ttl=wrap_ttl,
        )

    async def revoke_lease(self, lease_id: str) -> None:
        """PUT /v1/sys/leases/revoke."""
        await self._request("POST", "/v1/sys/leases/revoke", json={"lease_id": lease_id})

    async def lookup_wrap(self, wrap_token: str) -> dict[str, Any]:
        """POST /v1/sys/wrapping/lookup — returns {creation_ttl, ...} if live."""
        return await self._request(
            "POST", "/v1/sys/wrapping/lookup", json={"token": wrap_token},
        )

    async def transit_sign(
        self,
        *,
        key_name: str,
        input_b64: str,
        mount: str = "transit",
        signature_algorithm: str | None = None,
    ) -> str:
        """POST /v1/<mount>/sign/<key> — returns the `signature` string.

        Vault owns the signing key; the gateway sends base64-encoded input
        and receives an opaque signature. The `signature_algorithm` param
        is only used for RSA/PSS keys; Ed25519 ignores it.
        """
        payload: dict[str, Any] = {"input": input_b64}
        if signature_algorithm:
            payload["signature_algorithm"] = signature_algorithm
        data = await self._request(
            "POST", f"/v1/{mount}/sign/{key_name}", json=payload,
        )
        sig = (data.get("data") or {}).get("signature")
        if not sig:
            raise VaultClientError(f"Vault transit/sign returned no signature: {data}")
        return sig

    # ── Introspection (for /ready, metrics) ─────────────────────────────
    @property
    def circuit_state(self) -> str:
        return self._breaker.state

    @property
    def is_authenticated(self) -> bool:
        return self._token is not None and self._token.ttl_remaining > 0
