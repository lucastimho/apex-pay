"""OPA evaluator — two backends behind one interface.

1. `OPAClient` (httpx)  — POSTs to a running OPA sidecar at the Data API
    (`/v1/data/apex/shield/decision`). This is the production path.

2. `EmbeddedOPAEvaluator` — re-implements apex.shield in Python. It exists
    for two reasons:
      * local tests must run without spinning up an OPA process
      * if the sidecar is unreachable, the gateway can fail closed to
        embedded evaluation and keep the deny path intact

Both return the same `OPADecision` dataclass so callers don't care which
backend fired. The dev tooling uses both: the Rego unit tests (apex_test.rego)
and the Python tests (test_opa_client.py) share the same fixtures, so drift
between Rego and Python evaluators is caught at CI time.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Protocol

import httpx

logger = logging.getLogger("apex_pay.shield.opa")


# ── Decision dataclass ──────────────────────────────────────────────────────
@dataclass
class OPADecision:
    allow: bool
    reason: str
    escalate: bool
    violations: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)


class _Evaluator(Protocol):
    async def evaluate(self, opa_input: dict[str, Any]) -> OPADecision: ...


# ── Embedded Python evaluator (no OPA process needed) ───────────────────────
class EmbeddedOPAEvaluator:
    """Mirrors policies/apex.rego in Python.

    Keep this in lock-step with the Rego file. Any change to one must be
    reflected in the other; the shared test fixtures catch drift.
    """

    # Sets mirror the Rego `credential_keys` / `destructive_functions` sets.
    _CREDENTIAL_KEYS = frozenset({
        "api_key", "apikey", "secret", "private_key", "bearer_token",
        "session_token", "refresh_token", "oauth_token", "ssh_key",
        "vault_token", "aws_secret_access_key",
    })
    _DESTRUCTIVE_FUNCTIONS = frozenset({
        "delete_file", "drop_table", "rm_rf", "wipe_disk",
        "revoke_all_keys", "delete_account", "terminate_instance",
        "force_delete", "purge_backups",
    })
    _CREDENTIAL_VALUE_PATTERN = re.compile(
        r"(?i)(api[_-]?key|secret|bearer\s+[A-Za-z0-9._-]{20,})",
    )

    async def evaluate(self, opa_input: dict[str, Any]) -> OPADecision:
        intent = opa_input.get("intent", {})
        policy = opa_input.get("policy", {})
        risk = opa_input.get("risk", {})
        thresholds = opa_input.get("thresholds", {})

        violations: list[str] = []
        escalations: list[str] = []

        # ── Hard violations ──────────────────────────────────────────────
        if self._is_credential_forwarding(intent):
            violations.append("credential_forwarding_blocked")

        if self._is_destructive_action(intent):
            violations.append("destructive_action_blocked")

        if not self._domain_allowed(intent, policy):
            violations.append("domain_not_allowed")

        projected = float(intent.get("projected_cost", 0.0))
        max_txn = float(policy.get("max_per_transaction", 0.0))
        if projected > max_txn:
            violations.append("exceeds_per_transaction_limit")

        spent = float(policy.get("spent_today", 0.0))
        daily_cap = float(policy.get("daily_limit", 0.0))
        if (spent + projected) > daily_cap:
            violations.append("daily_budget_exceeded")

        risk_score = float(risk.get("score", 0.0))
        risk_block = float(thresholds.get("risk_block", 0.8))
        if risk_score >= risk_block:
            violations.append("risk_above_hard_block")

        # ── Escalations ──────────────────────────────────────────────────
        entropy = float(risk.get("entropy", 0.0))
        entropy_gate = float(thresholds.get("entropy_escalate", 0.65))
        if entropy >= entropy_gate:
            escalations.append("risk_uncertainty_escalation")

        risk_escalate = float(thresholds.get("risk_escalate", 0.4))
        if risk_escalate <= risk_score < risk_block:
            escalations.append("risk_moderate_escalation")

        if (
            intent.get("speech_act") == "declarative"
            and projected > 0
        ):
            escalations.append("declarative_framing_escalation")

        # ── Fold into final decision ─────────────────────────────────────
        if violations:
            return OPADecision(
                allow=False,
                reason=violations[0],
                escalate=False,
                violations=violations,
                raw={"violations": violations, "escalations": escalations},
            )
        if escalations:
            return OPADecision(
                allow=False,
                reason=escalations[0],
                escalate=True,
                violations=escalations,
                raw={"violations": [], "escalations": escalations},
            )
        return OPADecision(
            allow=True,
            reason="policy_passed",
            escalate=False,
            violations=[],
            raw={"violations": [], "escalations": []},
        )

    # ── helpers ─────────────────────────────────────────────────────────
    @classmethod
    def _is_credential_forwarding(cls, intent: dict[str, Any]) -> bool:
        params = intent.get("parameters") or {}
        if not isinstance(params, dict):
            return False
        for k, v in params.items():
            if isinstance(k, str) and k.lower() in cls._CREDENTIAL_KEYS:
                return True
            if isinstance(v, str) and cls._CREDENTIAL_VALUE_PATTERN.search(v):
                return True
        return False

    @classmethod
    def _is_destructive_action(cls, intent: dict[str, Any]) -> bool:
        fn = (intent.get("function") or "").lower()
        if fn in cls._DESTRUCTIVE_FUNCTIONS:
            return True
        params = intent.get("parameters") or {}
        if isinstance(params, dict):
            method = str(params.get("method", "")).upper()
            url = str(intent.get("target_url") or "").lower()
            if method == "DELETE" and "/admin/" in url:
                return True
        return False

    @staticmethod
    def _domain_allowed(intent: dict[str, Any], policy: dict[str, Any]) -> bool:
        allowed = policy.get("allowed_domains") or []
        if not allowed:
            return True
        domain = intent.get("action_domain") or ""
        if not domain:
            return True  # internal call, no URL
        return domain in allowed


# ── HTTP evaluator against an OPA sidecar ───────────────────────────────────
class _HTTPOPAEvaluator:
    def __init__(self, url: str, timeout: float = 2.0):
        self._url = url.rstrip("/")
        self._timeout = timeout

    async def evaluate(self, opa_input: dict[str, Any]) -> OPADecision:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(
                f"{self._url}/v1/data/apex/shield/decision",
                json={"input": opa_input},
            )
            resp.raise_for_status()
            body = resp.json()
        result = body.get("result", {}) or {}
        return OPADecision(
            allow=bool(result.get("allow", False)),
            reason=str(result.get("reason", "default_deny")),
            escalate=bool(result.get("escalate", False)),
            violations=list(result.get("violations", [])),
            raw=result,
        )


# ── Facade used by the pipeline ─────────────────────────────────────────────
class OPAClient:
    """Wraps an evaluator with a fail-closed-to-embedded fallback.

    If `opa_url` is set and reachable, HTTP eval is used. On any error
    (connection refused, 5xx, timeout) we fall back to the embedded
    evaluator so the deny path is never bypassed.
    """

    def __init__(
        self,
        *,
        opa_url: str | None = None,
        timeout: float = 2.0,
        embedded: EmbeddedOPAEvaluator | None = None,
    ):
        self._embedded = embedded or EmbeddedOPAEvaluator()
        self._http: _Evaluator | None = (
            _HTTPOPAEvaluator(opa_url, timeout=timeout) if opa_url else None
        )

    async def evaluate(self, opa_input: dict[str, Any]) -> OPADecision:
        if self._http is None:
            return await self._embedded.evaluate(opa_input)

        try:
            return await self._http.evaluate(opa_input)
        except Exception as exc:  # connection refused, timeout, 5xx, etc.
            logger.warning(
                "OPA sidecar unreachable (%s); falling back to embedded evaluator.",
                exc,
            )
            # Bump the fallback counter so SRE can alert on sidecar flapping.
            # Import lazily to keep this module free of the metrics dep.
            try:
                from apex_pay.services import metrics as _m
                _m.OPA_FALLBACK.inc()
            except Exception:  # pragma: no cover
                pass
            # Fail-closed-to-embedded: we still run the policy, just locally.
            return await self._embedded.evaluate(opa_input)
