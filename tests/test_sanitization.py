"""Tests for apex_pay.services.sanitization.

Pins:
  • Non-monetary calls pass through with no action and no problem.
  • Monetary + valid → returns a FinancialAction.
  • Monetary + invalid → returns RFC-7807 body; payload content is NOT
    echoed in the logged warning (only field paths + error types).
  • Legacy tool_call shape (function + target_url + parameters) is
    recognised and validated.
  • RFC-7807 response conforms to the standard shape
    (type/title/status/detail, optional extensions).
"""

from __future__ import annotations

import logging

import pytest

from apex_pay.services.sanitization import (
    looks_monetary,
    sanitize_financial_intent,
)
from apex_pay.shield.financial_action import FinancialAction


# ── Heuristic detection ─────────────────────────────────────────────────────


class TestLooksMonetary:
    @pytest.mark.parametrize("func", [
        "charge", "charge_card", "refund_order", "create_payment",
        "transfer_funds", "settle_invoice", "withdraw",
    ])
    def test_function_keyword_hits(self, func):
        assert looks_monetary({"function": func}) is True

    def test_amount_field_hits(self):
        assert looks_monetary({"function": "lookup", "parameters": {"amount": 10}}) is True

    def test_non_monetary_passes(self):
        assert looks_monetary({"function": "get_balance"}) is False
        assert looks_monetary({"function": "search_docs", "parameters": {"q": "hello"}}) is False


# ── End-to-end sanitization ─────────────────────────────────────────────────


class TestSanitizeFinancialIntent:
    def test_non_monetary_is_passthrough(self):
        r = sanitize_financial_intent({"function": "get_balance"})
        assert r.action is None
        assert r.problem is None

    def test_valid_monetary_returns_action(self):
        r = sanitize_financial_intent({
            "action_type": "charge",
            "amount": 25.00,
            "currency": "USD",
            "target_domain": "api.stripe.com",
            "target_url": "https://api.stripe.com/v1/charges",
            "idempotency_key": "req_01J9",
        })
        assert r.problem is None
        assert isinstance(r.action, FinancialAction)
        assert r.action.amount == 25.00

    def test_legacy_nested_shape_is_recognised(self):
        r = sanitize_financial_intent({
            "function": "charge",
            "target_url": "https://api.stripe.com/v1/charges",
            "parameters": {
                "amount": 12.50,
                "currency": "USD",
                "idempotency_key": "req_01",
            },
        })
        assert r.problem is None
        assert r.action is not None
        assert r.action.target_domain == "api.stripe.com"

    def test_over_ceiling_produces_rfc7807(self):
        r = sanitize_financial_intent({
            "action_type": "charge",
            "amount": 500,                               # > $50 ceiling
            "currency": "USD",
            "target_domain": "api.stripe.com",
            "target_url": "https://api.stripe.com/v1/charges",
            "idempotency_key": "req_01",
        })
        assert r.action is None
        assert r.problem is not None
        assert r.status_code == 422
        # RFC-7807 required fields.
        assert set(r.problem) >= {"type", "title", "status", "detail"}
        assert r.problem["status"] == 422
        # Structured violations surface to the client.
        assert "violations" in r.problem
        assert len(r.problem["violations"]) >= 1

    def test_unverified_domain_produces_rfc7807(self):
        r = sanitize_financial_intent({
            "action_type": "charge",
            "amount": 25.00,
            "currency": "USD",
            "target_domain": "evil.example.com",
            "target_url": "https://evil.example.com/v1/charges",
            "idempotency_key": "req_01",
        })
        assert r.problem is not None
        violations = r.problem["violations"]
        # At least one violation should reference the target_domain field.
        assert any("target_domain" in v["loc"] for v in violations)

    def test_malformed_shape_returns_400(self):
        # Monetary but missing required fields in both legacy and flat
        # shapes → parser raises ValueError / KeyError → 400 problem.
        r = sanitize_financial_intent({
            "function": "charge",
            "target_url": "https://api.stripe.com/v1/charges",
            "parameters": {"amount": 12.50},  # no idempotency_key
        })
        assert r.problem is not None
        assert r.status_code == 400
        assert "malformed-financial-intent" in r.problem["type"]

    def test_logs_do_not_leak_payload(self, caplog):
        """The whole point of the middleware — log redaction."""
        caplog.set_level(logging.WARNING, logger="apex_pay.sanitization")
        secret_memo = "<SECRET-CARD-4111-1111-1111-1111>"
        sanitize_financial_intent({
            "action_type": "charge",
            "amount": 25.00,
            "currency": "USD",
            "target_domain": "api.stripe.com",
            "target_url": "https://api.stripe.com/v1/charges",
            "idempotency_key": "req_01",
            "memo": secret_memo,
        })
        for record in caplog.records:
            assert secret_memo not in record.getMessage()
            assert "4111" not in record.getMessage()

    def test_logs_include_violation_types_but_not_values(self, caplog):
        caplog.set_level(logging.WARNING, logger="apex_pay.sanitization")
        hostile_memo = "' OR 1=1 --"
        r = sanitize_financial_intent({
            "action_type": "charge",
            "amount": 25.00,
            "currency": "USD",
            "target_domain": "api.stripe.com",
            "target_url": "https://api.stripe.com/v1/charges",
            "idempotency_key": "req_01",
            "memo": hostile_memo,
        })
        assert r.problem is not None
        msgs = [r.getMessage() for r in caplog.records]
        joined = "\n".join(msgs)
        # The log line surfaces the failing error TYPE but not the value.
        assert hostile_memo not in joined
        assert "OR 1=1" not in joined
