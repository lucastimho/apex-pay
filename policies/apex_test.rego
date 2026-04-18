# OPA conformance tests for apex.shield — runs with `opa test policies/`.
# Mirrors the Python unit tests in tests/test_opa_client.py so the two layers
# stay in sync.

package apex.shield

# ── Helpers ─────────────────────────────────────────────────────────────────
base_input := {
    "intent": {
        "agent_id": "aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb",
        "function": "charge_card",
        "target_url": "https://api.stripe.com/v1/charges",
        "action_domain": "api.stripe.com",
        "parameters": {"amount": 25.0, "currency": "USD"},
        "projected_cost": 25.0,
        "intent_hash": "deadbeef",
        "speech_act": "imperative",
    },
    "policy": {
        "max_per_transaction": 50.0,
        "daily_limit": 200.0,
        "allowed_domains": ["api.stripe.com", "api.openai.com"],
        "spent_today": 47.50,
    },
    "risk": {"score": 0.1, "entropy": 0.2, "labels": ["benign"]},
    "thresholds": {"risk_block": 0.8, "risk_escalate": 0.4, "entropy_escalate": 0.65},
    "policy_version": "2026.04.17",
}

# ── Allow path ──────────────────────────────────────────────────────────────
test_allows_benign_request if {
    decision.allow with input as base_input
    decision.reason == "policy_passed" with input as base_input
}

# ── Hard denies ─────────────────────────────────────────────────────────────
test_denies_domain_not_allowed if {
    inp := object.union(base_input, {
        "intent": object.union(base_input.intent, {
            "target_url": "https://evil.example.com/exfil",
            "action_domain": "evil.example.com",
        }),
    })
    not decision.allow with input as inp
    decision.reason == "domain_not_allowed" with input as inp
}

test_denies_over_per_transaction_cap if {
    inp := object.union(base_input, {
        "intent": object.union(base_input.intent, {"projected_cost": 100.0}),
    })
    not decision.allow with input as inp
    "exceeds_per_transaction_limit" in decision.violations with input as inp
}

test_denies_over_daily_limit if {
    inp := object.union(base_input, {
        "policy": object.union(base_input.policy, {"spent_today": 190.0}),
        "intent": object.union(base_input.intent, {"projected_cost": 20.0}),
    })
    not decision.allow with input as inp
    "daily_budget_exceeded" in decision.violations with input as inp
}

test_denies_credential_forwarding if {
    inp := object.union(base_input, {
        "intent": object.union(base_input.intent, {
            "parameters": {"amount": 1.0, "api_key": "sk_live_abc123"},
        }),
    })
    not decision.allow with input as inp
    decision.reason == "credential_forwarding_blocked" with input as inp
}

test_denies_destructive_action if {
    inp := object.union(base_input, {
        "intent": object.union(base_input.intent, {"function": "delete_account"}),
    })
    not decision.allow with input as inp
    decision.reason == "destructive_action_blocked" with input as inp
}

test_denies_risk_above_hard_block if {
    inp := object.union(base_input, {
        "risk": object.union(base_input.risk, {"score": 0.95}),
    })
    not decision.allow with input as inp
    "risk_above_hard_block" in decision.violations with input as inp
}

# ── Escalations ─────────────────────────────────────────────────────────────
test_escalates_on_high_entropy if {
    inp := object.union(base_input, {
        "risk": object.union(base_input.risk, {"entropy": 0.8}),
    })
    not decision.allow with input as inp
    decision.escalate with input as inp
    "risk_uncertainty_escalation" in decision.violations with input as inp
}

test_escalates_on_moderate_risk if {
    inp := object.union(base_input, {
        "risk": object.union(base_input.risk, {"score": 0.55}),
    })
    not decision.allow with input as inp
    decision.escalate with input as inp
    "risk_moderate_escalation" in decision.violations with input as inp
}

test_escalates_on_declarative_framing if {
    inp := object.union(base_input, {
        "intent": object.union(base_input.intent, {"speech_act": "declarative"}),
    })
    not decision.allow with input as inp
    decision.escalate with input as inp
    "declarative_framing_escalation" in decision.violations with input as inp
}

# Hard violations must take precedence over escalations
test_hard_deny_beats_escalation if {
    inp := object.union(base_input, {
        "intent": object.union(base_input.intent, {
            "target_url": "https://evil.example.com/x",
            "action_domain": "evil.example.com",
            "speech_act": "declarative",
        }),
        "risk": object.union(base_input.risk, {"entropy": 0.9}),
    })
    not decision.allow with input as inp
    not decision.escalate with input as inp
    decision.reason == "domain_not_allowed" with input as inp
}
