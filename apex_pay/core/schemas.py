"""
Pydantic v2 schemas — request validation and response serialisation.

These are the data contracts at the API boundary. They enforce structural
correctness before any business logic executes.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ── Tool-Call Intercept ─────────────────────────────────────────────────────
class ToolCallPayload(BaseModel):
    """Incoming agent tool-call that APEX-Pay intercepts.

    Example:
        {
            "agent_id": "...",
            "tool_call": {
                "function": "book_flight",
                "target_url": "https://api.stripe.com/v1/charges",
                "parameters": { "amount": 49.99, ... }
            }
        }
    """

    model_config = ConfigDict(str_strip_whitespace=True)

    agent_id: uuid.UUID
    tool_call: dict[str, Any] = Field(
        ..., description="Raw tool_call payload from the LLM agent."
    )
    idempotency_key: str | None = Field(
        default=None,
        max_length=128,
        description="Client-supplied key for idempotent settlement.",
    )

    @field_validator("tool_call")
    @classmethod
    def must_contain_target(cls, v: dict) -> dict:
        if "target_url" not in v and "function" not in v:
            raise ValueError(
                "tool_call must contain at least 'target_url' or 'function'."
            )
        return v


# ── Policy Decision Response ────────────────────────────────────────────────
class PolicyDecision(BaseModel):
    """Result returned by the Policy Enforcement Engine."""

    allowed: bool
    reason: str
    projected_cost: float | None = None
    action_domain: str | None = None
    risk_score: float = 0.0
    policy_snapshot: dict[str, Any] | None = None


# ── Gateway Response ────────────────────────────────────────────────────────
class GatewayResponse(BaseModel):
    """Top-level response envelope for the /execute endpoint."""

    model_config = ConfigDict(ser_json_timedelta="float")

    request_id: uuid.UUID
    allowed: bool
    status: str  # "APPROVED" | "DENIED" | "ERROR" | "ESCALATED"
    reason: str
    transaction_id: uuid.UUID | None = None
    token: str | None = None
    token_expiry: datetime | None = None
    latency_ms: float | None = None

    # ── APEX-Shield additions ──────────────────────────────────────────
    intent_hash: str | None = None
    ephemeral_credential: str | None = None   # scoped, short-lived token
    credential_token_id: str | None = None    # opaque handle, safe to log
    receipt: dict[str, Any] | None = None     # signed execution receipt
    risk_score: float | None = None
    risk_entropy: float | None = None
    violations: list[str] = Field(default_factory=list)
    hitl_request_id: uuid.UUID | None = None  # set when status == ESCALATED


# ── Challenge (HTTP 402) ────────────────────────────────────────────────────
class ChallengeResponse(BaseModel):
    """Returned when payment is required (HTTP 402)."""

    detail: dict[str, Any] = Field(
        ...,
        examples=[
            {
                "amount": 10.0,
                "ref_id": "abc-123",
                "baseline": "payment_with_policy",
                "message": "Payment Required",
            }
        ],
    )


# ── Settlement Request ──────────────────────────────────────────────────────
class SettlementRequest(BaseModel):
    """Agent's payment attempt after receiving a 402 challenge."""

    ref_id: str = Field(..., max_length=256)
    amount: float = Field(..., gt=0)
    baseline: str = Field(default="payment_with_policy")
    idempotency_key: str | None = Field(default=None, max_length=128)


class SettlementResponse(BaseModel):
    """Returned after successful payment settlement."""

    status: str  # "success" | "blocked"
    ref_id: str
    amount: float
    token: str | None = None
    token_expiry: int | None = None  # Unix timestamp
    state: str | None = None
    allowed: bool | None = None
    reason: str | None = None


# ── Health / Info ───────────────────────────────────────────────────────────
class HealthResponse(BaseModel):
    status: str = "ok"
    version: str
    uptime_seconds: float


# ── Agent Registration (admin) ──────────────────────────────────────────────
class AgentCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    public_key: str
    initial_balance: float = Field(default=0.0, ge=0)


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    status: str
    current_balance: float
    created_at: datetime


# ── Policy Management (admin) ───────────────────────────────────────────────
class PolicyCreate(BaseModel):
    agent_id: uuid.UUID
    max_per_transaction: float = Field(default=10.0, gt=0)
    daily_limit: float = Field(default=100.0, gt=0)
    allowed_domains: list[str] = Field(default_factory=list)


class PolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent_id: uuid.UUID
    max_per_transaction: float
    daily_limit: float
    allowed_domains: list[str]
    is_active: bool
