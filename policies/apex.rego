# =============================================================================
# APEX-Shield: Zero-Trust Agent Gateway — Master Policy
# =============================================================================
# Entry point for OPA evaluation. Composes sub-policies and emits a single
# decision:
#
#     data.apex.shield.decision = {
#         "allow":   bool,
#         "reason":  string,           # machine-readable reason code
#         "escalate": bool,            # true => route to Human-in-the-Loop
#         "violations": [string],      # list of failed sub-policies
#     }
#
# Input contract (constructed in apex_pay/shield/opa_client.py):
#     input = {
#         "intent": {
#             "agent_id":      "uuid",
#             "function":      "charge_card",
#             "target_url":    "https://api.stripe.com/v1/charges",
#             "action_domain": "api.stripe.com",
#             "parameters":    { "amount": 25.0, "currency": "USD", ... },
#             "projected_cost": 25.0,
#             "intent_hash":   "sha256-hex",
#             "speech_act":    "imperative" | "declarative",
#         },
#         "policy": {
#             "max_per_transaction": 50.0,
#             "daily_limit": 200.0,
#             "allowed_domains": ["api.stripe.com", "api.openai.com"],
#             "spent_today": 47.50,
#         },
#         "risk": {
#             "score":   0.12,
#             "entropy": 0.34,
#             "labels":  ["benign"],
#         },
#         "thresholds": {
#             "risk_block":   0.80,      # >= triggers hard deny
#             "risk_escalate": 0.40,     # [risk_escalate, risk_block) -> HITL
#             "entropy_escalate": 0.65,  # ambiguous classification -> HITL
#         },
#         "policy_version": "2026.04.17"
#     }
# =============================================================================

package apex.shield

import future.keywords.if
import future.keywords.in

default decision := {
    "allow": false,
    "reason": "default_deny",
    "escalate": false,
    "violations": ["default_deny"],
}

# ── The aggregate decision ──────────────────────────────────────────────────
decision := result if {
    vs := violations
    esc := escalations
    count(vs) == 0
    count(esc) == 0
    result := {
        "allow": true,
        "reason": "policy_passed",
        "escalate": false,
        "violations": [],
    }
}

decision := result if {
    vs := violations
    count(vs) > 0
    result := {
        "allow": false,
        "reason": vs[0],
        "escalate": false,
        "violations": vs,
    }
}

decision := result if {
    vs := violations
    count(vs) == 0
    esc := escalations
    count(esc) > 0
    result := {
        "allow": false,
        "reason": esc[0],
        "escalate": true,
        "violations": esc,
    }
}

# ── Violations (hard-deny) ──────────────────────────────────────────────────
violations contains "credential_forwarding_blocked" if {
    is_credential_forwarding
}

violations contains "destructive_action_blocked" if {
    is_destructive_action
}

violations contains "domain_not_allowed" if {
    not domain_allowed
}

violations contains "exceeds_per_transaction_limit" if {
    input.intent.projected_cost > input.policy.max_per_transaction
}

violations contains "daily_budget_exceeded" if {
    (input.policy.spent_today + input.intent.projected_cost) > input.policy.daily_limit
}

violations contains "risk_above_hard_block" if {
    input.risk.score >= input.thresholds.risk_block
}

# ── Escalations (soft-deny, route to HITL) ──────────────────────────────────
# Uncertainty-gated execution: high entropy in the risk classifier means the
# SLM is uncertain — don't trust it, ask a human.
escalations contains "risk_uncertainty_escalation" if {
    input.risk.entropy >= input.thresholds.entropy_escalate
}

escalations contains "risk_moderate_escalation" if {
    input.risk.score >= input.thresholds.risk_escalate
    input.risk.score < input.thresholds.risk_block
}

# Declarative framing escalation (ClawSafety §4.6 defense boundary lesson):
# defenses fire on imperative verbs ("update X") but miss declarative ones
# ("X does not match Y"). Treat declarative financial intents as suspect.
escalations contains "declarative_framing_escalation" if {
    input.intent.speech_act == "declarative"
    input.intent.projected_cost > 0
}

# ── Rule helpers ────────────────────────────────────────────────────────────
domain_allowed if {
    count(input.policy.allowed_domains) == 0  # empty list = unrestricted
}

domain_allowed if {
    input.intent.action_domain in input.policy.allowed_domains
}

domain_allowed if {
    not input.intent.action_domain  # internal call, no URL
}

# Credential-forwarding detection (ClawSafety showed this as a hard boundary
# Sonnet 4.6 enforces at 0% ASR — we enforce it deterministically).
credential_keys := {
    "api_key", "apikey", "secret", "private_key", "bearer_token",
    "session_token", "refresh_token", "oauth_token", "ssh_key",
    "vault_token", "aws_secret_access_key",
}

is_credential_forwarding if {
    some k
    input.intent.parameters[k]
    lower(k) in credential_keys
}

is_credential_forwarding if {
    some k, v
    input.intent.parameters[k] = v
    is_string(v)
    regex.match(`(?i)(api[_-]?key|secret|bearer\s+[A-Za-z0-9._-]{20,})`, v)
}

# Destructive-action detection (also 0% ASR for Sonnet 4.6 — hard block here).
destructive_functions := {
    "delete_file", "drop_table", "rm_rf", "wipe_disk",
    "revoke_all_keys", "delete_account", "terminate_instance",
    "force_delete", "purge_backups",
}

is_destructive_action if {
    lower(input.intent.function) in destructive_functions
}

is_destructive_action if {
    m := input.intent.parameters.method
    upper(m) == "DELETE"
    contains(lower(input.intent.target_url), "/admin/")
}
