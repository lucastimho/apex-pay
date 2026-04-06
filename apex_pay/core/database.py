"""
Database engine factory — one engine per privilege scope.

Follows the Principle of Least Privilege: each component connects via a
role that has *only* the grants it needs (see schema.sql ROLES section).
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from apex_pay.core.config import settings

# ---------------------------------------------------------------------------
# Engine: apex_gateway (reads agents/policies, writes transactions)
# ---------------------------------------------------------------------------
_gateway_engine = create_async_engine(
    settings.db.gateway_dsn,
    pool_size=settings.db.pool_size,
    max_overflow=settings.db.pool_overflow,
    echo=settings.debug,
)
GatewaySession = async_sessionmaker(
    _gateway_engine, class_=AsyncSession, expire_on_commit=False
)

# ---------------------------------------------------------------------------
# Engine: apex_auditor (INSERT-only on audit_logs)
# ---------------------------------------------------------------------------
_auditor_engine = create_async_engine(
    settings.db.auditor_dsn,
    pool_size=max(3, settings.db.pool_size // 2),
    max_overflow=2,
    echo=False,
)
AuditorSession = async_sessionmaker(
    _auditor_engine, class_=AsyncSession, expire_on_commit=False
)

# ---------------------------------------------------------------------------
# Engine: apex_readonly (SELECT-only for dashboards / observability)
# ---------------------------------------------------------------------------
_readonly_engine = create_async_engine(
    settings.db.readonly_dsn,
    pool_size=max(2, settings.db.pool_size // 3),
    max_overflow=1,
    echo=False,
)
ReadonlySession = async_sessionmaker(
    _readonly_engine, class_=AsyncSession, expire_on_commit=False
)


async def dispose_engines() -> None:
    """Graceful shutdown — drain all connection pools."""
    await _gateway_engine.dispose()
    await _auditor_engine.dispose()
    await _readonly_engine.dispose()
