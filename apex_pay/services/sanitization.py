"""Sanitization middleware glue — turn a raw tool_call into a validated
`FinancialAction` (when monetary) and surface RFC-7807 errors without
leaking payload content to logs.

Why a dedicated module
----------------------
The gateway's `/execute` handler is already busy. Putting the
monetary-intent detection + strict-validation plumbing here keeps the
router short and makes the sanitization logic independently testable.
The contract is narrow:

    sanitize_financial_intent(tool_call) -> SanitizationResult

    SanitizationResult.action           # FinancialAction | None (None = not monetary)
    SanitizationResult.problem          # RFC-7807 problem+json dict | None

On a non-monetary `tool_call` (balance lookup, search, etc.) both are
`None` and the gateway falls through to the legacy pre-shield path.

On a monetary call with a valid payload, `.action` is a validated
`FinancialAction` and `.problem` is `None`.

On a monetary call with an INVALID payload, `.action` is `None` and
`.problem` is the RFC-7807 body to return as the response.

Logging policy
--------------
We NEVER log the payload. We log:
  • The tool_call's function name (already in the audit log anyway)
  • The list of ValidationError field paths that failed
  • The ValidationError error-type identifiers (e.g. "string_pattern_mismatch")

We do NOT log:
  • Field VALUES (could leak injected SQL/prompts/PII)
  • Stack traces that include variable dumps
  • Raw request bodies

This is important for operations where the dashboards ship to third
parties (compliance, SRE), who shouldn't see raw payment intents even
when they fail validation.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from apex_pay.services.correlation import current_correlation_id
from apex_pay.shield.financial_action import FinancialAction

logger = logging.getLogger("apex_pay.sanitization")

# Keywords in a tool_call's function name that identify a monetary call.
# Intentionally broad — `FinancialAction.from_tool_call` does the strict
# check. This is the "should we even try" heuristic.
_MONETARY_KEYWORDS: frozenset[str] = frozenset({
    "charge",
    "refund",
    "transfer",
    "payout",
    "preauth",
    "capture",
    "pay",
    "payment",
    "settle",
    "withdraw",
    "deposit",
})


@dataclass
class SanitizationResult:
    action: FinancialAction | None = None
    problem: dict[str, Any] | None = None     # RFC-7807 body
    status_code: int = 200

    @property
    def is_problem(self) -> bool:
        return self.problem is not None


def looks_monetary(tool_call: dict[str, Any]) -> bool:
    """Return True if the tool_call smells like a money action.

    Heuristics, OR'd — broad on purpose; `FinancialAction.from_tool_call`
    does the strict check. Catches the four shapes we've seen in the wild:

      (a) legacy: `function` name contains a monetary keyword
      (b) legacy: `parameters.amount` field present
      (c) flat:   top-level `action_type` on the monetary allowlist
      (d) flat:   top-level `amount` field present
    """
    function = str(tool_call.get("function") or "").lower()
    if any(k in function for k in _MONETARY_KEYWORDS):
        return True
    action_type = str(tool_call.get("action_type") or "").lower()
    if action_type in _MONETARY_KEYWORDS:
        return True
    if "amount" in tool_call:
        return True
    params = tool_call.get("parameters") or {}
    if isinstance(params, dict) and "amount" in params:
        return True
    return False


def sanitize_financial_intent(tool_call: dict[str, Any]) -> SanitizationResult:
    """Run FinancialAction validation if the tool_call is monetary.

    Callers:
      • Non-monetary → `SanitizationResult(action=None, problem=None)`. Proceed.
      • Monetary + valid → `.action = FinancialAction(...)`. Proceed; use
        `.action.content_hash()` for the audit row.
      • Monetary + invalid → `.problem` is the RFC-7807 body to return
        verbatim to the client with `.status_code`.
    """
    if not looks_monetary(tool_call):
        return SanitizationResult()

    try:
        action = FinancialAction.from_tool_call(tool_call)
        return SanitizationResult(action=action)
    except ValidationError as exc:
        # Redact payload content. Only field paths and error types leak
        # to logs — everything else stays in the response body which the
        # agent receives anyway.
        redacted_errors = [
            {"loc": ".".join(str(p) for p in err["loc"]), "type": err["type"]}
            for err in exc.errors()
        ]
        logger.warning(
            "Financial-intent validation failed (request_id=%s, "
            "function=%s, violations=%s)",
            current_correlation_id(),
            str(tool_call.get("function") or "")[:64],
            [e["type"] for e in redacted_errors],
        )
        body = _rfc7807(
            type_=_PROBLEM_BASE + "/invalid-financial-intent",
            title="The submitted tool_call failed strict financial validation.",
            status=422,
            detail=(
                "The payload did not match the FinancialAction schema. See "
                "the `violations` field for per-field error codes. Payload "
                "content is not echoed back — resubmit a corrected request."
            ),
            extensions={
                "violations": redacted_errors,
                "request_id": current_correlation_id() or None,
            },
        )
        return SanitizationResult(problem=body, status_code=422)
    except (ValueError, KeyError) as exc:
        # from_tool_call raises these for shape mismatches outside
        # Pydantic's reach (e.g. legacy-nested dict missing a key).
        logger.warning(
            "Financial-intent shape error (request_id=%s): %s",
            current_correlation_id(),
            type(exc).__name__,
        )
        body = _rfc7807(
            type_=_PROBLEM_BASE + "/malformed-financial-intent",
            title="The submitted tool_call could not be parsed as a FinancialAction.",
            status=400,
            detail=(
                "The tool_call appears to be a monetary action but is "
                "missing required fields or uses an unexpected shape."
            ),
            extensions={
                "error_class": type(exc).__name__,
                "request_id": current_correlation_id() or None,
            },
        )
        return SanitizationResult(problem=body, status_code=400)


# ── RFC-7807 builder ────────────────────────────────────────────────────────

_PROBLEM_BASE = "https://apex-pay.example/problems"


def _rfc7807(
    *,
    type_: str,
    title: str,
    status: int,
    detail: str,
    extensions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    body = {
        "type": type_,
        "title": title,
        "status": status,
        "detail": detail,
    }
    if extensions:
        for k, v in extensions.items():
            if v is not None:
                body[k] = v
    return body
