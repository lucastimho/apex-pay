# =============================================================================
# Rego unit tests for apex.financial
# =============================================================================
# Run: opa test policies/financial_actions.rego policies/financial_actions_test.rego
#
# Coverage:
#   • Happy path (small amount, verified domain)
#   • Each deny rule D1..D10 fires exactly when expected
#   • Boundary behaviour at $50.00 exact (allowed) and $50.01 (denied)
#   • URL/domain mismatch doesn't pass on a typo-squat suffix
#   • Fields are required even when surrounding ones look valid
# =============================================================================

package apex.financial_test

import rego.v1
import data.apex.financial

# ---- Fixtures --------------------------------------------------------------

_valid_input := {
    "action": {
        "action_type":     "charge",
        "amount_usd":      25.00,
        "currency":        "USD",
        "target_domain":   "api.stripe.com",
        "target_url":      "https://api.stripe.com/v1/charges",
        "idempotency_key": "req_01J9...",
    },
    "context": {
        "agent_id":       "00000000-0000-0000-0000-000000000000",
        "policy_version": "2026.04.17",
    },
}

# ---- Happy path ------------------------------------------------------------

test_allow_valid_small_transaction if {
    financial.allow with input as _valid_input
    financial.decision.reason == "policy_passed" with input as _valid_input
}

test_allow_at_exact_ceiling if {
    # $50.00 is allowed; strictly greater-than on D1.
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {"amount_usd": 50.00})})
    financial.allow with input as i
}

# ---- D1: amount ceiling ----------------------------------------------------

test_deny_over_fifty_dollars if {
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {"amount_usd": 50.01})})
    not financial.allow with input as i
    "amount_exceeds_ceiling" in financial.decision.violations with input as i
}

test_deny_large_amount if {
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {"amount_usd": 9999.99})})
    not financial.allow with input as i
}

# ---- D2: non-positive amount -----------------------------------------------

test_deny_zero_amount if {
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {"amount_usd": 0})})
    not financial.allow with input as i
    "amount_must_be_positive" in financial.decision.violations with input as i
}

test_deny_negative_amount if {
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {"amount_usd": -5.00})})
    not financial.allow with input as i
}

# ---- D3: missing fields ----------------------------------------------------

test_deny_missing_amount if {
    action := object.remove(_valid_input.action, ["amount_usd"])
    i := object.union(_valid_input, {"action": action})
    not financial.allow with input as i
    "missing_field:amount_usd" in financial.decision.violations with input as i
}

test_deny_missing_target_domain if {
    action := object.remove(_valid_input.action, ["target_domain"])
    i := object.union(_valid_input, {"action": action})
    not financial.allow with input as i
    "missing_field:target_domain" in financial.decision.violations with input as i
}

# ---- D4/D5: action_type validation -----------------------------------------

test_deny_unknown_action_type if {
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {"action_type": "exfiltrate"})})
    not financial.allow with input as i
    "action_type_not_allowed" in financial.decision.violations with input as i
}

test_deny_malformed_action_type if {
    # Uppercase / contains digits — both should trip the regex.
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {"action_type": "Charge99"})})
    not financial.allow with input as i
    "action_type_malformed" in financial.decision.violations with input as i
}

# ---- D6: unverified domain -------------------------------------------------

test_deny_unverified_domain if {
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {
        "target_domain": "evil.example.com",
        "target_url":    "https://evil.example.com/v1/charges",
    })})
    not financial.allow with input as i
    "unverified_domain" in financial.decision.violations with input as i
}

test_deny_typo_squat_suffix if {
    # "stripe.com.evil.com" MUST NOT match the stripe.com suffix rule.
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {
        "target_domain": "stripe.com.evil.com",
        "target_url":    "https://stripe.com.evil.com/v1/charges",
    })})
    not financial.allow with input as i
    "unverified_domain" in financial.decision.violations with input as i
}

test_allow_subdomain_of_verified if {
    # Sandbox subdomain is fine — suffix match.
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {
        "target_domain": "sandbox.api.stripe.com",
        "target_url":    "https://sandbox.api.stripe.com/v1/charges",
    })})
    financial.allow with input as i
}

# ---- D7: scheme downgrade --------------------------------------------------

test_deny_insecure_scheme if {
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {
        "target_url": "http://api.stripe.com/v1/charges",
    })})
    not financial.allow with input as i
    "insecure_url_scheme" in financial.decision.violations with input as i
}

# ---- D8: URL/domain splitting ----------------------------------------------

test_deny_url_domain_mismatch if {
    # Claim stripe.com as domain but post to a different host.
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {
        "target_domain": "api.stripe.com",
        "target_url":    "https://evil.example.com/v1/charges",
    })})
    not financial.allow with input as i
    "url_domain_mismatch" in financial.decision.violations with input as i
}

# ---- D9: currency ----------------------------------------------------------

test_deny_unsupported_currency if {
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {"currency": "XYZ"})})
    not financial.allow with input as i
    "currency_not_allowed" in financial.decision.violations with input as i
}

# ---- D10: type confusion ---------------------------------------------------

test_deny_stringy_amount if {
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {"amount_usd": "25.00"})})
    not financial.allow with input as i
    "amount_not_numeric" in financial.decision.violations with input as i
}

# ---- Determinism of reason -------------------------------------------------

test_reason_is_deterministic if {
    # Two violations at once — reason must be the lexicographically first.
    i := object.union(_valid_input, {"action": object.union(_valid_input.action, {
        "amount_usd":    500,            # ceiling
        "target_domain": "evil.com",     # unverified
        "target_url":    "https://evil.com/x",
    })})
    sorted_expected := sort(["amount_exceeds_ceiling", "unverified_domain", "url_domain_mismatch"])
    financial.decision.reason == sorted_expected[0] with input as i
}
