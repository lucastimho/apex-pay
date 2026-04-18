"""Zero-Trust pipeline: risk filter → OPA → credential → receipt.

Call path from `routers/gateway.py::execute_tool_call`:

    intent  = canonicalize_intent(agent_id, tool_call)
    risk    = await risk_filter.classify(intent_text, context)
    opa     = await opa_client.evaluate(intent.to_opa_input() + policy + risk + thresholds)
    if not opa.allow and opa.escalate:  → HITL pending state, no credential issued
    if not opa.allow and not opa.escalate: → hard deny
    credential = await credential_manager.issue(scope, ttl=60)
    receipt    = receipt_service.sign(intent_hash, agent_id, token_id, risk.score)

The pipeline is deliberately stateless wrt DB — the caller hands it the
agent's policy and the daily spend figure. This keeps the existing
`PolicyEngine` free to do the DB lookups and lets the shield be unit-tested
without a database.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from apex_pay.shield.credential_manager import (
    CredentialManager,
    CredentialScope,
    EphemeralCredential,
)
from apex_pay.shield.intent import ShieldIntent, SpeechAct
from apex_pay.shield.opa_client import OPAClient, OPADecision
from apex_pay.shield.receipt_service import ReceiptService, SignedReceipt
from apex_pay.shield.risk_filter import (
    HeuristicClassifier,
    RiskAssessment,
    RiskClassifier,
    intent_to_text,
)

logger = logging.getLogger("apex_pay.shield.pipeline")


@dataclass
class PolicySnapshot:
    max_per_transaction: float
    daily_limit: float
    allowed_domains: list[str]
    spent_today: float = 0.0

    def to_opa(self) -> dict[str, Any]:
        return {
            "max_per_transaction": float(self.max_per_transaction),
            "daily_limit": float(self.daily_limit),
            "allowed_domains": list(self.allowed_domains),
            "spent_today": float(self.spent_today),
        }


@dataclass
class ShieldThresholds:
    risk_block: float = 0.80
    risk_escalate: float = 0.40
    entropy_escalate: float = 0.65

    def to_opa(self) -> dict[str, Any]:
        return {
            "risk_block": self.risk_block,
            "risk_escalate": self.risk_escalate,
            "entropy_escalate": self.entropy_escalate,
        }


@dataclass
class ShieldDecision:
    """Aggregate decision returned by `ShieldPipeline.evaluate`.

    Exactly one of {credential, hitl_reason} is set:
      * `credential` is populated on allow
      * `hitl_reason` is populated on escalate (soft deny)
      * neither is set on hard deny
    """

    allow: bool
    escalate: bool
    reason: str
    violations: list[str]
    intent: ShieldIntent
    risk: RiskAssessment
    opa: OPADecision
    credential: EphemeralCredential | None = None
    receipt: SignedReceipt | None = None
    hitl_reason: str | None = None
    policy_snapshot: dict[str, Any] = field(default_factory=dict)


class ShieldPipeline:
    def __init__(
        self,
        *,
        opa_client: OPAClient,
        risk_classifier: RiskClassifier | None = None,
        credential_manager: CredentialManager,
        receipt_service: ReceiptService,
        thresholds: ShieldThresholds | None = None,
        ephemeral_ttl_seconds: int = 60,
    ):
        self.opa = opa_client
        self.risk = risk_classifier or HeuristicClassifier()
        self.credentials = credential_manager
        self.receipts = receipt_service
        self.thresholds = thresholds or ShieldThresholds()
        self.ttl = ephemeral_ttl_seconds

    async def evaluate(
        self,
        *,
        intent: ShieldIntent,
        policy: PolicySnapshot,
        channel: str = "agent",
    ) -> ShieldDecision:
        # ── 1. Semantic risk filter ────────────────────────────────────
        text = intent_to_text({
            "function": intent.function,
            "target_url": intent.target_url,
            "parameters": intent.parameters,
        })
        risk = await self.risk.classify(text, {"channel": channel})

        # ── 2. OPA policy evaluation ───────────────────────────────────
        opa_input = {
            "intent": intent.to_opa_input(),
            "policy": policy.to_opa(),
            "risk": {
                "score": risk.score,
                "entropy": risk.entropy,
                "labels": risk.labels,
            },
            "thresholds": self.thresholds.to_opa(),
            "policy_version": self.receipts._policy_version,  # noqa: SLF001
        }
        opa = await self.opa.evaluate(opa_input)

        decision = ShieldDecision(
            allow=opa.allow,
            escalate=opa.escalate,
            reason=opa.reason,
            violations=list(opa.violations),
            intent=intent,
            risk=risk,
            opa=opa,
            policy_snapshot=policy.to_opa(),
        )

        if not opa.allow and opa.escalate:
            decision.hitl_reason = opa.reason
            return decision

        if not opa.allow:
            return decision

        # ── 3. Ephemeral credential ────────────────────────────────────
        scope = CredentialScope(
            intent_hash=intent.intent_hash,
            domain=intent.action_domain,
            method=(intent.parameters.get("method") or "POST") if isinstance(intent.parameters, dict) else "POST",
            max_amount=float(intent.projected_cost),
            extra={"function": intent.function or ""},
        )
        credential = await self.credentials.issue(scope, ttl_seconds=self.ttl)

        # ── 4. Signed receipt (non-repudiation) ────────────────────────
        receipt = self.receipts.sign(
            intent_hash=intent.intent_hash,
            agent_id=str(intent.agent_id),
            token_id=credential.token_id,
            risk_score=risk.score,
            extra={
                "action_domain": intent.action_domain or "",
                "projected_cost": intent.projected_cost,
                "speech_act": intent.speech_act.value,
            },
            ttl_seconds=self.ttl,
        )

        decision.credential = credential
        decision.receipt = receipt
        return decision
