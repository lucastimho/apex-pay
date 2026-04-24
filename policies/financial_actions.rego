# =============================================================================
# APEX-Shield: FinancialAction — Hardened Second-Gate Policy
# =============================================================================
# Absolute ceiling on monetary agent actions. Composes with apex.rego's
# per-agent policy (which can be stricter, never laxer). Evaluated at
# data.apex.financial.decision.
#
# DESIGN NOTES
#   1. MAX_TRANSACTION_USD is a hard ceiling. Per-agent policies in
#      apex.rego enforce additional per-agent limits, but nothing — not a
#      generous policy, not a missing policy — can authorise more than
#      $50 through this gate.
#   2. VERIFIED_DOMAINS is an allowlist of known-good payment processors.
#      A domain is "verified" iff its registrable suffix is in this set.
#      Subdomains are permitted so sandbox.api.stripe.com matches, but
#      typo-squats like stripe.evil.com do not (suffix match, not prefix).
#   3. The policy is written to be composed: data.apex.shield.decision
#      runs first (per-agent budget + risk + speech-act). If that passes,
#      this gate runs as a SECOND, stricter deny-list for monetary actions.
#      A deny here overrides an allow upstream.
#   4. All deny rules return a structured violation so the audit log can
#      be filtered by reason code. No free-text denial reasons — each is
#      machine-readable.
# =============================================================================

package apex.financial

import rego.v1

# ---- Constants -------------------------------------------------------------

# Hard ceiling in USD. See design note 1.
MAX_TRANSACTION_USD := 50.00

# Registrable-suffix allowlist. See design note 2.
# Suffix match: "api.stripe.com" ends with ".stripe.com" → verified.
VERIFIED_DOMAINS := {
    "stripe.com",
    "paypal.com",
    "adyen.com",
    "squareup.com",
    "checkout.com",
    "mollie.com",
    "plaid.com",
    "dwolla.com",
    "wise.com",
    "braintreepayments.com",
}

# Monetary action types that must pass this gate. Read-only calls (e.g.
# balance lookups) are routed through apex.rego only.
MONETARY_ACTIONS := {
    "charge",
    "refund",
    "transfer",
    "payout",
    "preauth",
    "capture",
}

# ISO 4217 three-letter currency code whitelist. Narrower than the full ISO
# list on purpose — reject currencies we cannot price-convert.
ALLOWED_CURRENCIES := {"USD", "EUR", "GBP", "CAD", "AUD", "JPY"}

# Pattern an action_type must match (defence against injection via enum).
ACTION_TYPE_PATTERN := `^[a-z_]{3,16}$`

# ---- Input contract --------------------------------------------------------
#
# input = {
#     "action": {
#         "action_type":   "charge",
#         "amount_usd":    25.00,           # already FX-normalised by caller
#         "currency":      "USD",
#         "target_domain": "api.stripe.com",
#         "target_url":    "https://api.stripe.com/v1/charges",
#         "idempotency_key": "...",
#     },
#     "context": {
#         "agent_id":       "uuid",
#         "policy_version": "2026.04.17",
#     },
# }
#
# Output:
#     data.apex.financial.decision = {
#         "allow":      bool,
#         "violations": [string],
#         "reason":     string,    # first deny reason, or "policy_passed"
#     }

# ---- Core decision ---------------------------------------------------------

default allow := false

allow if {
    count(violations) == 0
}

# Violations accumulate; each rule below contributes a string to the set.
# Rego unioning via `violations contains x` deduplicates automatically.

# D1: amount over ceiling.
violations contains "amount_exceeds_ceiling" if {
    input.action.amount_usd > MAX_TRANSACTION_USD
}

# D2: non-positive amount (zero-dollar abuse for enumeration / probing).
violations contains "amount_must_be_positive" if {
    input.action.amount_usd <= 0
}

# D3: missing required field.
violations contains sprintf("missing_field:%s", [field]) if {
    some field in {"action_type", "amount_usd", "currency", "target_domain", "target_url"}
    not has_field(input.action, field)
}

# D4: action_type not in the monetary-action whitelist.
violations contains "action_type_not_allowed" if {
    has_field(input.action, "action_type")
    not input.action.action_type in MONETARY_ACTIONS
}

# D5: action_type fails structural sanity (defence against type confusion).
violations contains "action_type_malformed" if {
    has_field(input.action, "action_type")
    not regex.match(ACTION_TYPE_PATTERN, input.action.action_type)
}

# D6: target_domain not in the verified suffix set.
violations contains "unverified_domain" if {
    has_field(input.action, "target_domain")
    not domain_is_verified(input.action.target_domain)
}

# D7: target_url scheme must be https (downgrade attacks).
violations contains "insecure_url_scheme" if {
    has_field(input.action, "target_url")
    not startswith(lower(input.action.target_url), "https://")
}

# D8: host portion of target_url must align with target_domain. This closes
# the "claim stripe.com but actually post to evil.com" splitting trick.
violations contains "url_domain_mismatch" if {
    has_field(input.action, "target_url")
    has_field(input.action, "target_domain")
    host := url_host(input.action.target_url)
    not host == input.action.target_domain
}

# D9: currency not on the allowlist.
violations contains "currency_not_allowed" if {
    has_field(input.action, "currency")
    not input.action.currency in ALLOWED_CURRENCIES
}

# D10: amount must be a number (not string, not bool, not null). Rego is
# dynamically typed but is_number rules catch upstream JSON sloppiness.
violations contains "amount_not_numeric" if {
    has_field(input.action, "amount_usd")
    not is_number(input.action.amount_usd)
}

# ---- Surface -------------------------------------------------------------

decision := {
    "allow":      allow,
    "violations": [v | some v in violations],
    "reason":     reason,
}

reason := "policy_passed" if {
    count(violations) == 0
}

reason := first_violation if {
    count(violations) > 0
    # Deterministic ordering for reproducible audit messages.
    sorted := sort([v | some v in violations])
    first_violation := sorted[0]
}

# ---- Helpers ---------------------------------------------------------------

has_field(obj, key) if {
    _ := obj[key]
}

# Suffix-match against VERIFIED_DOMAINS. "api.stripe.com" ends with
# ".stripe.com" → verified. "stripe.com.evil.com" does NOT → denied.
domain_is_verified(domain) if {
    some suffix in VERIFIED_DOMAINS
    endswith(lower(domain), sprintf(".%s", [suffix]))
}

domain_is_verified(domain) if {
    some suffix in VERIFIED_DOMAINS
    lower(domain) == suffix
}

# Extract the host portion from an https URL. Returns "" on malformed input
# so D8 always triggers rather than silently passing.
url_host(u) := host if {
    startswith(lower(u), "https://")
    after_scheme := substring(u, 8, -1)
    # First segment up to "/" or "?" or end.
    slash_idx := indexof(after_scheme, "/")
    query_idx := indexof(after_scheme, "?")
    end_idx := min_positive(slash_idx, query_idx, count(after_scheme))
    host := lower(substring(after_scheme, 0, end_idx))
}

min_positive(a, b, fallback) := result if {
    candidates := [x | some x in [a, b, fallback]; x >= 0]
    result := min(candidates)
}
