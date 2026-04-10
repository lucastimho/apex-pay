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


class _RateLimitSettings(BaseSettings):
    """SlowAPI rate-limit defaults."""

    model_config = SettingsConfigDict(env_prefix="RATELIMIT_", env_file=".env", extra="ignore")

    default: str = "60/minute"
    per_agent: str = "30/minute"


class _LogfireSettings(BaseSettings):
    """Pydantic Logfire configuration."""

    model_config = SettingsConfigDict(env_prefix="LOGFIRE_", env_file=".env", extra="ignore")

    token: str = ""             # Logfire API token (empty → local console)
    service_name: str = "apex-pay"
    environment: str = "development"


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


# Singleton – import `settings` everywhere.
settings = Settings()
