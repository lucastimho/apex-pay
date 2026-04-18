# APEX-Shield Security Architecture

APEX-Shield is the Zero-Trust hardening layer that wraps the APEX-Pay gateway
described in the original APEX paper (arXiv:2604.02023). It extends the
baseline per-transaction / daily-budget policy engine with four new
guarantees:

1. **Cryptographic non-repudiation** — every approved intent is bound to a
   content-addressable hash and signed with an Ed25519 execution receipt.
2. **Uncertainty-gated execution** — requests whose risk classifier output
   has high Shannon entropy are routed to human review instead of being
   silently allowed or denied.
3. **Transient tool sandboxing** — approved intents do not hand the agent a
   long-lived API key; they mint a short-lived scope-bound credential whose
   blast radius is exactly one tool-call.
4. **Fail-closed policy evaluation** — OPA is the single source of truth.
   If the sidecar is unreachable the gateway falls back to an embedded
   Python mirror of the same Rego rules; the deny path is never bypassed.

The design draws its threat model from the ClawSafety paper
(arXiv:2604.01438), specifically its finding that skill-injection is the
highest-ASR attack vector (69.4%) and that declarative framing ("the
fingerprint does not match…") routinely bypasses model-level defenses.

## The pipeline

```
┌──────────┐   ┌───────────────┐   ┌──────────────┐   ┌──────────────┐   ┌───────────────┐
│ tool_call│ → │ canonicalize  │ → │ risk filter  │ → │  OPA (Rego)  │ → │ credential +  │
│          │   │ + intent_hash │   │  score +     │   │  policy gate │   │ signed receipt│
└──────────┘   └───────────────┘   │  entropy     │   └──────┬───────┘   └───────────────┘
                                   └──────────────┘          │
                                                             ▼
                                                   deny | allow | escalate
                                                             │
                                                             ▼
                                                  HITL queue (if escalate)
```

`canonicalize_intent` produces a `ShieldIntent` with a stable SHA-256 hash
over `(agent_id, function, target_url, parameters)`. Every downstream
artefact — the ephemeral credential scope, the Ed25519 receipt body, the
audit log entry — is bound to that hash. Mutate any field and every
artefact becomes invalid.

The `HeuristicClassifier` is the default pluggable risk filter. It emits a
score in `[0, 1]`, a Shannon entropy in `[0, 1]`, and a set of labels
(prompt injection, destination substitution, credential forwarding, channel
bias, declarative framing). The `LlamaGuardAdapter` swaps it for a model
served over HTTP with automatic fallback to the heuristic if the model
endpoint fails.

OPA is evaluated via the Data API (`/v1/data/apex/shield/decision`) against
`policies/apex.rego`. On any HTTP failure the `OPAClient` facade falls
through to `EmbeddedOPAEvaluator`, a Python mirror of the same rules.
Drift between the two is caught at CI time: `policies/apex_test.rego` and
`tests/test_shield_opa.py` use the same fixtures, so a change in one that
is not reflected in the other breaks the build.

A decision is one of:

| Decision | Rego output | Gateway status | Credential issued | Receipt issued |
|---|---|---|---|---|
| allow | `allow=true` | `APPROVED` | yes | yes |
| hard deny | `allow=false, escalate=false` | `DENIED` | no | no |
| escalate | `allow=false, escalate=true` | `ESCALATED` | no | no |

Hard violations (bad domain, over budget, credential forwarding,
destructive verb, risk score ≥ 0.80) take precedence over escalations, so
a request that would both escalate on entropy AND fail the domain
allowlist hard-denies with `domain_not_allowed`.

## Threat model

| Vector | Defense |
|---|---|
| Prompt injection in tool params | Risk filter labels `prompt_injection_imperative` and raises score; OPA hard-blocks at ≥ 0.80 and escalates at ≥ 0.40 |
| Declarative framing ("does not match…") | Speech-act classifier flags `declarative`; OPA escalates any declarative intent with a projected cost |
| Credential forwarding (`api_key`, bearer token in params) | Hard deny via `credential_forwarding_blocked` — both by parameter-key match and by value pattern |
| Destructive verbs (`delete_account`, `DELETE /admin/…`) | Hard deny via `destructive_action_blocked` |
| Domain exfiltration | Hard deny if the request URL's host is not in the agent's `allowed_domains` |
| Long-lived key leakage | Every approval mints a 60-s HMAC-scoped token tied to the intent_hash; no raw API key ever reaches the agent |
| Audit log tampering | `audit_logs` UPDATE/DELETE/TRUNCATE revoked from all roles except `apex_admin`; write-once trigger `reject_audit_mutation` enforces the invariant at the DB layer |
| Replay of a stale approval | Receipts embed `expires_at` and `intent_hash`; the verifier rejects expired or tampered receipts |
| Gateway compromise | Least-privilege DB roles (`apex_gateway` has no DELETE on anything; `apex_auditor` is INSERT-only on `audit_logs`) keep the blast radius small |
| OPA sidecar unavailable | Fail closed to `EmbeddedOPAEvaluator` — the deny path never degrades to allow |

## Ed25519 key rotation

Keys live in the `Ed25519KeyRing`. The ring holds one `signing_key` and a
map `kid → public_key` used for verification. Rotation is three steps:

1. Generate a new key pair. Add the public key to `SHIELD_ED25519_PUBLIC_KEYS_JSON`
   alongside the old one. Deploy.
2. Switch `SHIELD_ED25519_KID` and `SHIELD_ED25519_PRIVATE_B64` to the new
   key. Deploy. All new receipts are signed with the new `kid`.
3. Wait until all previously-issued receipts have expired
   (`expires_at < now`). Only then remove the old public key from the
   verification map.

During step 2 the gateway accepts receipts with either `kid`, so there is
no flag day. `test_kid_rotation_allows_verification_of_old_receipts` pins
this property.

In production the `Ed25519KeyRing` should be built from Vault's transit
engine; the current `from_env` loader exists for dev and CI. The factory
`apex_pay.shield.factory._build_keyring` is the single switch point.

## Dev → Vault switch for credentials

`CredentialManager` is a Protocol with two shipped backends:

- `DevCredentialBackend` — self-contained, HMAC-signed tokens of the form
  `v1.<token_id>.<b64(payload)>.<b64(hmac_sha256(...))>`. TTL is hard-capped at
  300 seconds; revocation is tracked in a process-local set.
- `VaultCredentialBackend` — logs in via AppRole, calls the configured
  secrets engine (e.g. `database/creds/apex-gateway`) with Response
  Wrapping so the secret only materialises when the downstream tool
  unwraps it. Revocation hits `/sys/leases/revoke`.

Flipping backends is a single env var: `SHIELD_CREDENTIAL_BACKEND=vault`.
The gateway never sees the plaintext secret for a Vault-issued credential;
the agent receives a wrap token and the actual downstream credential is
materialised by the outbound tool.

Vault policy for this setup:

```
path "database/creds/apex-gateway" { capabilities = ["read"] }
path "sys/wrapping/wrap"           { capabilities = ["update"] }
path "sys/leases/revoke"           { capabilities = ["update"] }
```

## OPA authoring workflow

1. Edit `policies/apex.rego`. Every hard violation lives under `violations`
   and every escalation under `escalations`.
2. Mirror the change in `EmbeddedOPAEvaluator` in
   `apex_pay/shield/opa_client.py`. The Python class exists only as a
   fail-closed fallback — its rules must stay in lock-step with the Rego.
3. Add or update the matching fixture in `tests/test_shield_opa.py` and a
   mirror test in `policies/apex_test.rego`. The two share the same
   `base_input` shape; a change in one that breaks the other is a drift
   bug.
4. Bump `settings.shield.policy_version`. The version ends up in every
   signed receipt so an auditor can tell which policy evaluated which
   intent.
5. Run `opa test policies/ -v` and `pytest tests/test_shield_opa.py -q`.
   Both must pass.

## Hardened audit log

`migrations/001_shield_hardening.sql` adds:

- `intent_hash` and `receipt` columns to `audit_logs`
- `shield_hitl_requests` table for the HITL queue
- A write-once trigger `reject_audit_mutation()` that raises on UPDATE /
  DELETE / TRUNCATE against `audit_logs`
- Explicit `REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM PUBLIC`
  and `GRANT INSERT ON audit_logs TO apex_auditor`

The audit worker uses the INSERT-only `apex_auditor` role. Even with a
full gateway compromise, an attacker cannot rewrite history — at most
they can append to it, and each append carries the intent hash and signed
receipt for cryptographic reconciliation.

## HITL flow

When OPA returns `escalate=true`, the gateway writes a row into the
`hitl_store` with the intent hash, violations, risk score and entropy.
The `/hitl/pending`, `/hitl/{id}/approve` and `/hitl/{id}/deny` endpoints
let operators drain the queue. Approving a HITL request re-runs the
pipeline with a human-review override; denying it pushes a permanent
`DENIED` row into the audit log.

The current `HITLStore` is an in-memory implementation with an `asyncio.Lock`
and TTL purge; the interface is deliberately small so it can be ported to
Postgres (`shield_hitl_requests`) or Redis without touching the router.

## Environment surface

All shield settings carry the `SHIELD_` prefix:

| Variable | Purpose |
|---|---|
| `SHIELD_ENABLED` | Master on/off switch. If false the gateway runs the legacy policy engine only |
| `SHIELD_POLICY_VERSION` | Embedded into every signed receipt |
| `SHIELD_OPA_URL` | OPA sidecar base URL. Unset → embedded evaluator |
| `SHIELD_RISK_BACKEND` | `heuristic` (default) or `llama_guard` |
| `SHIELD_LLAMA_GUARD_URL` | Required if `SHIELD_RISK_BACKEND=llama_guard` |
| `SHIELD_RISK_BLOCK_THRESHOLD` | Hard-deny above this score. Default 0.80 |
| `SHIELD_RISK_ESCALATE_THRESHOLD` | Escalate between this and `RISK_BLOCK`. Default 0.40 |
| `SHIELD_ENTROPY_ESCALATE_THRESHOLD` | Escalate on classifier uncertainty. Default 0.65 |
| `SHIELD_CREDENTIAL_BACKEND` | `dev` (default) or `vault` |
| `SHIELD_EPHEMERAL_TTL_SECONDS` | Default credential TTL. Capped at 300s |
| `SHIELD_VAULT_*` | AppRole credentials + secrets path for Vault backend |
| `SHIELD_ED25519_KID` | Current signing `kid` |
| `SHIELD_ED25519_PRIVATE_B64` | Base64 Ed25519 private key |
| `SHIELD_ED25519_PUBLIC_KEYS_JSON` | `{"kid": "b64-pub", …}` — verification map |

## Running the test suite

```
pytest -q
```

138 tests in total covering the six shield components (intent, OPA, risk
filter, credential manager, receipt service, pipeline) plus the existing
gateway, policy-engine and admin-endpoint suites. The shield suite runs
without a database or Redis and pins the contract between the Python
evaluator and the Rego policy.
