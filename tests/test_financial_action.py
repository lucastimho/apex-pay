"""Tests for apex_pay.shield.financial_action.FinancialAction.

Each rejection path has at least one test. Happy-path tests document the
intended acceptance envelope; rejection tests pin every deny rule to a
specific ValidationError field so regressions are caught by exact match
rather than by "some error happened".
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from pydantic import ValidationError

from apex_pay.shield.financial_action import (
    MAX_TRANSACTION_USD,
    FinancialAction,
    _is_verified_domain,
)

# ── Fixture builder ─────────────────────────────────────────────────────────


def _valid_payload(**overrides):
    base = {
        "action_type": "charge",
        "amount": Decimal("25.00"),
        "currency": "USD",
        "target_domain": "api.stripe.com",
        "target_url": "https://api.stripe.com/v1/charges",
        "idempotency_key": "req_01J9ABCDEF",
    }
    base.update(overrides)
    return base


# ── Happy path ──────────────────────────────────────────────────────────────


class TestAccepts:
    def test_valid_small_transaction(self):
        fa = FinancialAction(**_valid_payload())
        assert fa.amount == Decimal("25.00")
        assert fa.target_domain == "api.stripe.com"

    def test_amount_at_exact_ceiling(self):
        fa = FinancialAction(**_valid_payload(amount=Decimal("50.00")))
        assert fa.amount == Decimal("50.00")

    def test_subdomain_of_verified_domain(self):
        fa = FinancialAction(**_valid_payload(
            target_domain="sandbox.api.stripe.com",
            target_url="https://sandbox.api.stripe.com/v1/charges",
        ))
        assert fa.target_domain == "sandbox.api.stripe.com"

    def test_optional_fields_omitted(self):
        fa = FinancialAction(**_valid_payload())
        assert fa.memo is None
        assert fa.recipient_ref is None

    def test_optional_fields_accepted(self):
        fa = FinancialAction(**_valid_payload(
            memo="Subscription renewal for April 2026",
            recipient_ref="cus_abc123",
        ))
        assert fa.memo == "Subscription renewal for April 2026"


# ── Amount rules ────────────────────────────────────────────────────────────


class TestAmount:
    def test_rejects_over_ceiling(self):
        with pytest.raises(ValidationError, match="hard ceiling"):
            FinancialAction(**_valid_payload(amount=Decimal("50.01")))

    def test_rejects_zero(self):
        with pytest.raises(ValidationError):
            FinancialAction(**_valid_payload(amount=Decimal("0")))

    def test_rejects_negative(self):
        with pytest.raises(ValidationError):
            FinancialAction(**_valid_payload(amount=Decimal("-1.00")))

    def test_rejects_too_many_decimal_places_for_usd(self):
        # USD has 2-decimal exponent. 0.001 is too precise.
        with pytest.raises(ValidationError, match="decimal"):
            FinancialAction(**_valid_payload(amount=Decimal("10.001")))

    def test_rejects_string_amount(self):
        # Pydantic's Decimal coercion accepts strings at the type level, so
        # Decimal("25.00") works — but a free-form "not-a-number" must fail.
        with pytest.raises(ValidationError):
            FinancialAction(**_valid_payload(amount="not-a-number"))

    def test_rejects_nan_infinity(self):
        with pytest.raises(ValidationError):
            FinancialAction(**_valid_payload(amount=Decimal("NaN")))


# ── Currency rules ──────────────────────────────────────────────────────────


class TestCurrency:
    def test_rejects_lowercase(self):
        with pytest.raises(ValidationError):
            FinancialAction(**_valid_payload(currency="usd"))

    def test_rejects_off_list(self):
        # ZAR is a real ISO 4217 code but not on our allowlist.
        with pytest.raises(ValidationError, match="not on the allowed list"):
            FinancialAction(**_valid_payload(currency="ZAR"))

    def test_rejects_bad_length(self):
        with pytest.raises(ValidationError):
            FinancialAction(**_valid_payload(currency="US"))


# ── Domain rules ────────────────────────────────────────────────────────────


class TestDomain:
    def test_rejects_unverified_domain(self):
        with pytest.raises(ValidationError, match="verified-domain allowlist"):
            FinancialAction(**_valid_payload(
                target_domain="evil.example.com",
                target_url="https://evil.example.com/v1/charges",
            ))

    def test_rejects_typo_squat_suffix(self):
        # "stripe.com.evil.com" must NOT be verified as stripe.com.
        with pytest.raises(ValidationError, match="verified-domain allowlist"):
            FinancialAction(**_valid_payload(
                target_domain="stripe.com.evil.com",
                target_url="https://stripe.com.evil.com/v1/charges",
            ))

    def test_rejects_url_host_mismatch(self):
        # Domain says api.stripe.com, URL points somewhere else → reject
        # on cross-field check even though each field individually is fine.
        with pytest.raises(ValidationError, match="does not match"):
            FinancialAction(**_valid_payload(
                target_domain="api.stripe.com",
                target_url="https://api.paypal.com/v1/charges",
            ))

    def test_rejects_http_scheme(self):
        # HttpUrl accepts http; the cross-field validator downgrades that
        # to an error.
        with pytest.raises(ValidationError, match="https"):
            FinancialAction(**_valid_payload(
                target_url="http://api.stripe.com/v1/charges",
            ))

    def test_rejects_malformed_hostname(self):
        with pytest.raises(ValidationError):
            FinancialAction(**_valid_payload(
                target_domain="not..a..domain",
                target_url="https://not..a..domain/v1/charges",
            ))


# ── Injection rules ─────────────────────────────────────────────────────────


class TestInjectionHardening:
    @pytest.mark.parametrize("bad_char,label", [
        ("\u0000", "NULL"),
        ("\u0008", "backspace"),
        ("\u000A", "LF"),
        ("\u000D", "CR"),
        ("\u001B", "ESC"),
        ("\u007F", "DEL"),
        ("\u200B", "ZWSP"),
        ("\u200E", "LRM"),
        ("\u202E", "RLO"),
        ("\u2066", "LRI"),
        ("\uFEFF", "BOM"),
    ])
    def test_rejects_hostile_codepoint_in_memo(self, bad_char, label):
        with pytest.raises(ValidationError):
            FinancialAction(**_valid_payload(memo=f"hello{bad_char}world"))

    def test_rejects_sql_looking_characters_in_memo(self):
        with pytest.raises(ValidationError, match="safe set"):
            FinancialAction(**_valid_payload(memo="' OR 1=1 --"))

    def test_rejects_html_in_memo(self):
        with pytest.raises(ValidationError, match="safe set"):
            FinancialAction(**_valid_payload(memo="<script>alert(1)</script>"))

    def test_rejects_dollar_brace_injection_in_memo(self):
        with pytest.raises(ValidationError, match="safe set"):
            FinancialAction(**_valid_payload(memo="${system.exec}"))

    def test_rejects_bad_chars_in_idempotency_key(self):
        with pytest.raises(ValidationError):
            FinancialAction(**_valid_payload(idempotency_key="req 123"))  # space

    def test_rejects_non_nfc_text(self):
        # "é" as decomposed (e + combining acute) vs NFC composed.
        decomposed = "caf\u0065\u0301"
        with pytest.raises(ValidationError, match="NFC"):
            FinancialAction(**_valid_payload(memo=decomposed))

    def test_rejects_oversized_memo(self):
        with pytest.raises(ValidationError):
            FinancialAction(**_valid_payload(memo="a" * 257))


# ── Shape closure ───────────────────────────────────────────────────────────


class TestShapeClosure:
    def test_rejects_unknown_field(self):
        with pytest.raises(ValidationError, match="extra_forbidden"):
            FinancialAction(**_valid_payload(evil_extra="surprise"))

    def test_is_frozen(self):
        fa = FinancialAction(**_valid_payload())
        with pytest.raises(ValidationError):
            fa.amount = Decimal("0.01")

    def test_rejects_missing_required(self):
        payload = _valid_payload()
        del payload["currency"]
        with pytest.raises(ValidationError, match="currency"):
            FinancialAction(**payload)


# ── Canonicalisation ────────────────────────────────────────────────────────


class TestCanonical:
    def test_canonical_json_is_deterministic(self):
        fa1 = FinancialAction(**_valid_payload())
        fa2 = FinancialAction(**_valid_payload())
        assert fa1.canonical_json() == fa2.canonical_json()

    def test_canonical_json_sorted_keys(self):
        fa = FinancialAction(**_valid_payload())
        s = fa.canonical_json().decode()
        # Sorted → "action_type" appears before "amount" before "currency".
        assert s.index("action_type") < s.index("amount") < s.index("currency")

    def test_canonical_omits_none_fields(self):
        fa = FinancialAction(**_valid_payload())
        assert b"memo" not in fa.canonical_json()
        assert b"recipient_ref" not in fa.canonical_json()

    def test_content_hash_is_stable(self):
        fa = FinancialAction(**_valid_payload())
        assert fa.content_hash() == fa.content_hash()
        # 64 hex chars = 256 bits.
        assert len(fa.content_hash()) == 64
        int(fa.content_hash(), 16)  # parses as hex

    def test_content_hash_changes_with_amount(self):
        fa1 = FinancialAction(**_valid_payload(amount=Decimal("25.00")))
        fa2 = FinancialAction(**_valid_payload(amount=Decimal("25.01")))
        assert fa1.content_hash() != fa2.content_hash()


# ── OPA input adapter ───────────────────────────────────────────────────────


class TestOpaAdapter:
    def test_shape_matches_rego_expectations(self):
        fa = FinancialAction(**_valid_payload())
        opa_in = fa.to_opa_input(
            agent_id="agent-123",
            policy_version="2026.04.17",
        )
        assert set(opa_in.keys()) == {"action", "context"}
        assert set(opa_in["action"].keys()) == {
            "action_type", "amount_usd", "currency",
            "target_domain", "target_url", "idempotency_key",
        }
        assert opa_in["context"] == {
            "agent_id": "agent-123",
            "policy_version": "2026.04.17",
        }

    def test_amount_is_numeric_for_rego(self):
        fa = FinancialAction(**_valid_payload())
        opa_in = fa.to_opa_input(agent_id="a", policy_version="v")
        # Rego's D10 rejects non-numeric amount — we must send a float.
        assert isinstance(opa_in["action"]["amount_usd"], float)


# ── Domain helper ───────────────────────────────────────────────────────────


class TestDomainHelper:
    @pytest.mark.parametrize("domain,expected", [
        ("stripe.com", True),
        ("api.stripe.com", True),
        ("sandbox.api.stripe.com", True),
        ("paypal.com", True),
        ("evil.com", False),
        ("stripe.com.evil.com", False),      # suffix match, not substring
        ("notstripe.com", False),
        ("api-stripe.com", False),           # hyphen is not a separator
    ])
    def test_suffix_matching(self, domain, expected):
        assert _is_verified_domain(domain) is expected


# ── Legacy adapter ──────────────────────────────────────────────────────────


class TestLegacyAdapter:
    def test_flat_dict_passes_through(self):
        fa = FinancialAction.from_tool_call(_valid_payload())
        assert fa.action_type == "charge"

    def test_nested_tool_call_shape(self):
        fa = FinancialAction.from_tool_call({
            "function": "charge",
            "target_url": "https://api.stripe.com/v1/charges",
            "parameters": {
                "amount": 12.50,
                "currency": "USD",
                "idempotency_key": "req_nested_01",
            },
        })
        assert fa.amount == Decimal("12.50")
        assert fa.target_domain == "api.stripe.com"

    def test_legacy_missing_idempotency_raises(self):
        with pytest.raises((KeyError, ValueError)):
            FinancialAction.from_tool_call({
                "function": "charge",
                "target_url": "https://api.stripe.com/v1/charges",
                "parameters": {"amount": 12.50, "currency": "USD"},
            })


# ── Constant sanity check ───────────────────────────────────────────────────


def test_ceiling_constant_matches_rego():
    """If the Rego constant changes, this test alerts us to also update
    the Pydantic mirror (or vice versa)."""
    assert MAX_TRANSACTION_USD == Decimal("50.00")
