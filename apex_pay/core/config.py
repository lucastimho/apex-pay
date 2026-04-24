"""
Centralised configuration loaded from environment variables.

Uses pydantic-settings so every value can be overridden via an .env file
or container environment without touching code.
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class _DatabaseDSN(BaseSettings):
    """Scoped DSNs following Principle of Least Privilege.

    apex_gateway  — read agents/policies, read/write transactions
    apex_auditor  — INSERT-only on audit_logs
    apex_readonly — SELECT-only for dashboards
    """

    model_config = SettingsConfigDict(env_prefix="DB_", env_file=".env", extra="ignore")

    gateway_dsn: str = (
        "postgresql+asyncpg://apex_gateway:change_me_gateway"
        "@localhost:5432/apex_pay"
    )
    auditor_dsn: str = (
        "postgresql+asyncpg://apex_auditor:change_me_auditor"
        "@localhost:5432/apex_pay"
    )
    readonly_dsn: str = (
        "postgresql+asyncpg://apex_readonly:change_me_readonly"
        "@localhost:5432/apex_pay"
    )
    pool_size: int = 10
    pool_overflow: int = 5


class _RedisSettings(BaseSettings):
    """Redis connection for the async audit queue."""

    model_config = SettingsConfigDict(env_prefix="REDIS_", env_file=".env", extra="ignore")

    url: str = "redis://localhost:6379/0"
    audit_queue_name: str = "apex:audit_queue"
    max_queue_depth: int = 5_000  # back-pressure threshold


class _SecuritySettings(BaseSettings):
    """Cryptographic and token lifecycle settings."""

    model_config = SettingsConfigDict(env_prefix="SECURITY_", env_file=".env", extra="ignore")

    hmac_secret_key: str = "CHANGE-ME-IN-PRODUCTION"  # HMAC-SHA256 signing key
    token_ttl_seconds: int = 300                       # 5-minute token validity
    jwt_algorithm: str = "HS256"

    # ── Request-envelope hardening (blueprint §5.1) ─────────────────────
    # Flags default OFF so existing callers keep working. Flip each one
    # on per environment when the agent SDKs are ready.
    require_nonce: bool = False               # reject requests missing nonce/issued_at
    nonce_ttl_seconds: int = 300              # replay window (also the timestamp skew)
    require_body_signature: bool = False      # reject requests without Ed25519 body sig
    # When ON, any monetary tool_call MUST parse as a FinancialAction. When
    # OFF (default), the sanitizer still attempts parsing on best-effort
    # so the validated object + content_hash are available downstream, but
    # a parse failure is downgraded to a warning log and the legacy policy
    # path continues.
    require_financial_validation: bool = False


class _RateLimitSettings(BaseSettings):
    """SlowAPI rate-limit defaults, plus the semantic ($$) limiter."""

    model_config = SettingsConfigDict(env_prefix="RATELIMIT_", env_file=".env", extra="ignore")

    default: str = "60/minute"
    per_agent: str = "30/minute"

    # Semantic (dollar-spend) limiter — blueprint §2.C. Defaults aim for a
    # comfortable envelope on a well-behaved agent: $100 per rolling hour.
    # Flip `semantic_enabled` on in prod after confirming Redis availability.
    semantic_enabled: bool = False
    semantic_window_seconds: int = 3600
    semantic_default_limit_cents: int = 10_000    # $100.00


class _LogfireSettings(BaseSettings):
    """Pydantic Logfire configuration."""

    model_config = SettingsConfigDict(env_prefix="LOGFIRE_", env_file=".env", extra="ignore")

    token: str = ""             # Logfire API token (empty → local console)
    service_name: str = "apex-pay"
    environment: str = "development"


class _ShieldSettings(BaseSettings):
    """APEX-Shield zero-trust layer configuration.

    Every field has a safe default so the shield is active out-of-the-box:
    embedded OPA evaluator, dev credential backend, heuristic risk filter,
    and an ephemeral Ed25519 key. Override in production.
    """

    model_config = SettingsConfigDict(env_prefix="SHIELD_", env_file=".env", extra="ignore")

    enabled: bool = True
    policy_version: str = "2026.04.17"

    # OPA sidecar. Empty = embedded Python evaluator only.
    opa_url: str = ""
    opa_timeout_seconds: float = 2.0

    # Risk filter. "heuristic" (default) or "llama-guard".
    risk_backend: str = "heuristic"
    llama_guard_url: str = ""

    # Decision thresholds.
    risk_block_threshold: float = 0.80
    risk_escalate_threshold: float = 0.40
    entropy_escalate_threshold: float = 0.65

    # Credential backend: "dev" or "vault".
    credential_backend: str = "dev"
    ephemeral_ttl_seconds: int = 60
    ephemeral_ttl_max_seconds: int = 300

    # Vault (only read when credential_backend == "vault").
    vault_addr: str = ""
    vault_role_id: str = ""
    vault_secret_id: str = ""
    vault_secrets_path: str = "database/creds/apex-gateway"
    vault_wrap_ttl: str = "60s"
    # Mount points for AppRole and Transit engines (override for non-default setups).
    vault_approle_mount: str = "approle"
    vault_transit_mount: str = "transit"
    vault_transit_key: str = "apex-shield-scope-signer"
    # Resilience knobs.
    vault_request_timeout_seconds: float = 5.0
    vault_circuit_failure_threshold: int = 3
    vault_circuit_cooldown_seconds: float = 10.0

    # Ed25519 signing keys.
    ed25519_kid: str = "key-ephemeral"
    ed25519_private_b64: str = ""
    # Map of kid -> base64 Raw public key, for multi-key verification.
    ed25519_public_keys_json: str = ""


class Settings(BaseSettings):
    """Root settings object — compose all sub-configs."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "APEX-Pay"
    debug: bool = False

    db: _DatabaseDSN = _DatabaseDSN()
    redis: _RedisSettings = _RedisSettings()
    security: _SecuritySettings = _SecuritySettings()
    rate_limit: _RateLimitSettings = _RateLimitSettings()
    logfire: _LogfireSettings = _LogfireSettings()
    shield: _ShieldSettings = _ShieldSettings()


# Singleton – import `settings` everywhere.
settings = Settings()
