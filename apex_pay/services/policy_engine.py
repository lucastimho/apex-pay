"""
Policy Enforcement Engine
=========================
The core decision-making layer of APEX-Pay. Intercepts every tool_call and
performs three sequential checks:

    1. **Domain Allowlist** — Is the target URL in `allowed_domains`?
    2. **Per-Transaction Cap** — Does the projected cost ≤ `max_per_transaction`?
    3. **Daily Budget** — Would approval push cumulative spend > `daily_limit`?

Design is aligned with the APEX paper's "Constraint Check" step (§IV.4)
and budget constraint formulation (§VII.A):  Σ c_i ≤ B_d
"""

from __future__ import annotations

import time
import uuid
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any
from urllib.parse import urlparse

from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from apex_pay.core.models import Agent, AuditLog, Policy, Transaction
from apex_pay.core.schemas import PolicyDecision, ToolCallPayload
from apex_pay.services.policy_cache import default_cache


class PolicyEngine:
    """Stateless policy evaluator — instantiate per-request."""

    # ── Public API ──────────────────────────────────────────────────────
    async def evaluate(
        self,
        payload: ToolCallPayload,
        session: AsyncSession,
    ) -> PolicyDecision:
        """Run the full pre-flight policy check pipeline.

        Returns a PolicyDecision indicating APPROVED or DENIED with reason.
        """
        start = time.perf_counter()

        # 1. Load agent + active policy ──────────────────────────────────
        agent = await self._load_agent(payload.agent_id, session)
        if agent is None:
            return self._deny("agent_not_found", "No registered agent with this ID.")

        if agent.status != "active":
            return self._deny("agent_suspended", f"Agent status is '{agent.status}'.")

        policy_snap = await self._load_snapshot(payload.agent_id, session)
        if policy_snap is None:
            return self._deny("no_active_policy", "No active spending policy found.")

        # 2. Extract intent fields ───────────────────────────────────────
        projected_cost = self._extract_cost(payload.tool_call)
        action_domain = self._extract_domain(payload.tool_call)

        # 3. Domain allowlist check ──────────────────────────────────────
        if not self._domain_allowed(action_domain, policy_snap.get("allowed_domains")):
            return self._deny(
                "domain_not_allowed",
                f"Domain '{action_domain}' is not in the agent's allowed list.",
                projected_cost=projected_cost,
                action_domain=action_domain,
                policy_snapshot=policy_snap,
            )

        # 4. Per-transaction cap  (paper: a ≤ M) ────────────────────────
        max_per_txn = float(policy_snap["max_per_transaction"])
        if projected_cost is not None and projected_cost > max_per_txn:
            return self._deny(
                "exceeds_per_transaction_limit",
                f"Projected cost ${projected_cost:.2f} exceeds per-txn cap "
                f"${max_per_txn:.2f}.",
                projected_cost=projected_cost,
                action_domain=action_domain,
                policy_snapshot=policy_snap,
            )

        # 5. Daily budget check  (paper: Σ c_i ≤ B_d) ───────────────────
        spent_today = await self._daily_spend(payload.agent_id, session)
        pending_total = spent_today + (projected_cost or 0.0)
        daily_cap = float(policy_snap["daily_limit"])

        if pending_total > daily_cap:
            return self._deny(
                "daily_budget_exceeded",
                f"Today's spend ${spent_today:.2f} + ${projected_cost or 0:.2f} "
                f"= ${pending_total:.2f} exceeds daily limit ${daily_cap:.2f}.",
                projected_cost=projected_cost,
                action_domain=action_domain,
                policy_snapshot=policy_snap,
            )

        # 6. Passed all gates ────────────────────────────────────────────
        elapsed = (time.perf_counter() - start) * 1000
        return PolicyDecision(
            allowed=True,
            reason="policy_passed",
            projected_cost=projected_cost,
            action_domain=action_domain,
            risk_score=0.0,
            policy_snapshot=policy_snap,
        )

    # ── Internals ───────────────────────────────────────────────────────

    @staticmethod
    async def _load_agent(
        agent_id: uuid.UUID, session: AsyncSession
    ) -> Agent | None:
        result = await session.execute(
            select(Agent).where(Agent.id == agent_id)
        )
        return result.scalar_one_or_none()

    @staticmethod
    async def _load_active_policy(
        agent_id: uuid.UUID, session: AsyncSession
    ) -> Policy | None:
        result = await session.execute(
            select(Policy).where(
                Policy.agent_id == agent_id, Policy.is_active.is_(True)
            )
        )
        return result.scalar_one_or_none()

    @classmethod
    async def _load_snapshot(
        cls, agent_id: uuid.UUID, session: AsyncSession
    ) -> dict[str, Any] | None:
        """Cache-aside read of the active policy snapshot.

        Cache hit → return the memoized dict (no DB roundtrip).
        Miss → load the row, cache the snapshot, return it.
        Missing policy is NOT cached: a missing row is fail-closed in the
        caller, and we want admins to see the fix as soon as they create
        the policy, not after a TTL expiry.
        """
        cache = default_cache()
        hit = cache.get(agent_id)
        if hit is not None:
            return hit
        policy = await cls._load_active_policy(agent_id, session)
        if policy is None:
            return None
        snap = cls._snapshot(policy)
        cache.put(agent_id, snap)
        return snap

    @staticmethod
    async def _daily_spend(
        agent_id: uuid.UUID, session: AsyncSession
    ) -> float:
        """Sum of approved projected_cost for `agent_id` since midnight UTC.

        Uses both audit_logs (APPROVED) and transactions (SETTLED/CONSUMED)
        to get the most accurate picture.
        """
        today_start = datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0
        )
        result = await session.execute(
            select(func.coalesce(func.sum(AuditLog.projected_cost), 0)).where(
                AuditLog.agent_id == agent_id,
                AuditLog.status == "APPROVED",
                AuditLog.created_at >= today_start,
            )
        )
        return float(result.scalar_one())

    # ── Intent Extraction ───────────────────────────────────────────────

    @staticmethod
    def _extract_cost(tool_call: dict[str, Any]) -> float | None:
        """Best-effort extraction of projected cost from the tool_call payload.

        Looks for common fields: amount, cost, price, projected_cost.
        """
        params = tool_call.get("parameters", tool_call)
        for key in ("amount", "cost", "price", "projected_cost"):
            if key in params:
                try:
                    return float(params[key])
                except (TypeError, ValueError):
                    continue
        return None

    @staticmethod
    def _extract_domain(tool_call: dict[str, Any]) -> str | None:
        """Extract domain from `target_url` if present."""
        url = tool_call.get("target_url")
        if url:
            try:
                return urlparse(url).netloc.lower()
            except Exception:
                return url
        return None

    @staticmethod
    def _domain_allowed(
        domain: str | None, allowed: list | dict | Any
    ) -> bool:
        """Check domain against allowlist. Empty list = allow all."""
        if isinstance(allowed, dict):
            allowed = allowed.get("domains", [])
        if not allowed:
            return True  # empty allowlist → unrestricted
        if domain is None:
            return True  # no domain in payload → internal call, allow
        return domain in allowed

    @staticmethod
    def _snapshot(policy: Policy) -> dict[str, Any]:
        return {
            "policy_id": str(policy.id),
            "max_per_transaction": float(policy.max_per_transaction),
            "daily_limit": float(policy.daily_limit),
            "allowed_domains": (
                policy.allowed_domains
                if isinstance(policy.allowed_domains, list)
                else []
            ),
        }

    @staticmethod
    def _deny(
        reason: str,
        message: str,
        *,
        projected_cost: float | None = None,
        action_domain: str | None = None,
        risk_score: float = 0.0,
        policy_snapshot: dict | None = None,
    ) -> PolicyDecision:
        return PolicyDecision(
            allowed=False,
            reason=reason,
            projected_cost=projected_cost,
            action_domain=action_domain,
            risk_score=risk_score,
            policy_snapshot=policy_snapshot,
        )
