"""
SQLAlchemy ORM models — mirrors the Supabase SQL schema.

Each model maps 1-to-1 with a table defined in schema.sql.
"""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    Text,
    UniqueConstraint,
    Uuid,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Shared declarative base for all APEX-Pay models."""


# ── agents ──────────────────────────────────────────────────────────────────
class Agent(Base):
    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    current_balance: Mapped[float] = mapped_column(
        Numeric(18, 4), nullable=False, default=0.0
    )
    status: Mapped[str] = mapped_column(
        Text, nullable=False, default="active"
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # Relationships
    policies: Mapped[list[Policy]] = relationship(back_populates="agent", lazy="selectin")

    __table_args__ = (
        CheckConstraint("current_balance >= 0", name="ck_agents_balance_positive"),
        CheckConstraint(
            "status IN ('active', 'suspended', 'revoked')",
            name="ck_agents_status_enum",
        ),
        Index("idx_agents_status", "status"),
    )


# ── policies ────────────────────────────────────────────────────────────────
class Policy(Base):
    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("agents.id", ondelete="CASCADE"), nullable=False
    )
    max_per_transaction: Mapped[float] = mapped_column(
        Numeric(18, 4), nullable=False, default=10.0
    )
    daily_limit: Mapped[float] = mapped_column(
        Numeric(18, 4), nullable=False, default=100.0
    )
    allowed_domains: Mapped[dict] = mapped_column(JSON, nullable=False, default=list)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    agent: Mapped[Agent] = relationship(back_populates="policies")

    __table_args__ = (
        CheckConstraint("max_per_transaction > 0", name="ck_policy_max_txn"),
        CheckConstraint("daily_limit > 0", name="ck_policy_daily"),
        UniqueConstraint("agent_id", "is_active", name="uq_active_policy_per_agent"),
        Index("idx_policies_agent_active", "agent_id", postgresql_where="is_active = TRUE"),
    )


# ── audit_logs ──────────────────────────────────────────────────────────────
class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("agents.id", ondelete="SET NULL"), nullable=False
    )
    raw_intent: Mapped[dict] = mapped_column(JSON, nullable=False)
    projected_cost: Mapped[float | None] = mapped_column(Numeric(18, 4))
    action_domain: Mapped[str | None] = mapped_column(Text)
    risk_score: Mapped[float] = mapped_column(Numeric(5, 4), default=0.0)
    status: Mapped[str] = mapped_column(Text, nullable=False)
    denial_reason: Mapped[str | None] = mapped_column(Text)
    transaction_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    policy_snapshot: Mapped[dict | None] = mapped_column(JSON)
    latency_ms: Mapped[float | None] = mapped_column(Numeric(10, 2))
    intent_hash: Mapped[str | None] = mapped_column(Text)
    financial_action_hash: Mapped[str | None] = mapped_column(Text)
    receipt: Mapped[dict | None] = mapped_column(JSON)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )

    __table_args__ = (
        CheckConstraint(
            "status IN ('APPROVED', 'DENIED', 'ERROR')", name="ck_audit_status"
        ),
        CheckConstraint("risk_score >= 0 AND risk_score <= 1", name="ck_audit_risk"),
        Index("idx_audit_agent", "agent_id"),
        Index("idx_audit_status", "status"),
        Index("idx_audit_created", "created_at"),
    )


# ── transactions ────────────────────────────────────────────────────────────
class Transaction(Base):
    __tablename__ = "transactions"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid, primary_key=True, default=uuid.uuid4
    )
    agent_id: Mapped[uuid.UUID] = mapped_column(
        Uuid, ForeignKey("agents.id"), nullable=False
    )
    ref_id: Mapped[str] = mapped_column(Text, unique=True, nullable=False)
    amount: Mapped[float] = mapped_column(Numeric(18, 4), nullable=False)
    state: Mapped[str] = mapped_column(Text, nullable=False, default="CHALLENGED")
    token: Mapped[str | None] = mapped_column(Text)
    token_expiry: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    idempotency_key: Mapped[str | None] = mapped_column(Text)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow
    )

    __table_args__ = (
        CheckConstraint("amount > 0", name="ck_txn_amount_positive"),
        CheckConstraint(
            "state IN ('CHALLENGED', 'INITIATED', 'SETTLED', 'CONSUMED')",
            name="ck_txn_state_enum",
        ),
        Index("idx_txn_state", "state"),
        Index("idx_txn_agent", "agent_id"),
    )
