# APEX-Pay + APEX-Shield

> **A policy-gated execution layer for AI agents.** Every tool-call passes through a zero-trust pipeline — semantic risk classifier, OPA policy gate, scoped credential issuance, and an Ed25519-signed execution receipt — before the agent is allowed to act. Non-compliant intents are denied, escalated, or fall through to human review.

---

## Why this exists

Large language model agents are rapidly being given the authority to spend money, call APIs, and move data. The canonical failure mode is simple and catastrophic: a prompt-injected agent calls a legitimate tool with malicious parameters, and downstream systems have no mechanism to say *no*.

APEX-Pay is the gateway that sits between the agent and its tools. APEX-Shield is the zero-trust hardening layer on top. Together they answer four questions for every tool-call, on the hot path, in under 200ms:

1. **Does this intent match what the agent was provisioned to do?** — OPA-evaluated per-transaction and daily budget, plus an allowed-domains check.
2. **Is the semantic framing suspicious?** — a pluggable risk filter scores declarative injections ("the fingerprint does not match…") before they ever reach a policy rule.
3. **If approved, what's the minimum authority required?** — a short-lived, scope-bound credential is minted; no long-lived API key is ever handed to the agent.
4. **Can a third party later prove this execution was sanctioned?** — every approved intent is hashed and signed with an Ed25519 receipt, verifiable offline.

The threat model is taken directly from the **ClawSafety paper (arXiv:2604.01438)**, which established skill-injection as the highest-ASR attack vector (69.4%) against modern agents. The execution semantics are derived from the **APEX paper (arXiv:2604.02023)**.

---

## Highlights

- **Zero-trust pipeline** — canonicalize → risk filter → OPA → credential → receipt, fail-closed at every stage.
- **Least-privilege Postgres roles** — three separate database connections (`apex_gateway`, `apex_auditor`, `apex_readonly`) so the write path can't read and the read path can't write.
- **Append-only audit log, exactly-once** — role-enforced INSERT-only access, write-once trigger, and a `(intent_hash, agent_id, minute-bucket)` dedup index that collapses at-least-once delivery retries into one row.
- **Atomic balance debit on `/pay`** — `SELECT ... FOR UPDATE` locks the agent row, verifies balance, decrements, and flips the transaction state in one DB transaction so a mid-flight crash can never double-spend or issue an unpaid token.
- **Live Nerve Center dashboard** — a React single-page app with a Server-Sent Events feed backed by a shared `LISTEN` broker; sub-100ms tail latency from decision to pixel.
- **Cryptographically non-repudiable** — Ed25519 signed receipts bound to content-addressable intent hashes, with a public **JWKS endpoint** (`/.well-known/apex-jwks`) so third parties can verify offline without a shared secret.
- **HITL escalation** — high-entropy risk classifier outputs route to a human-review queue instead of guessing.
- **OPA + Python fallback** — Rego as the source of truth, with an embedded Python mirror of the same rules so the sidecar being unreachable can never open the deny path. Fallback rate is exported as a Prometheus counter for alerting.
- **Production-grade observability** — Prometheus `/metrics` (decision/latency/queue/risk/OPA-fallback/HITL gauges), split `/health` vs `/ready` probes, and a correlation-id middleware that stamps `X-Request-ID` across every log, span, and audit row.
- **Per-agent rate limiting** — request keys resolve header → cert CN → IP, so one runaway agent can't starve its neighbours behind a shared egress NAT.
- **Policy cache with pub/sub invalidation** — in-process TTL cache keeps the hot path off Postgres; admin edits publish on `apex.policies.invalidate` so peer replicas evict within milliseconds. SQLAlchemy ORM events catch direct-DB edits as a safety net.
- **Opt-in replay protection + body signing** — nonce/timestamp guard backed by Redis `SET NX`, plus Ed25519 signature verification against each agent's registered public key. Both feature-flagged so agent SDKs can adopt at their own pace.
- **Monthly partitioning playbook** — migration 004 ships an opt-in `audit_logs_partitioned` table plus `apex_create_audit_partition(year, month)` helper and a documented swap procedure for v3 scale.
- **138 tests, all green.** Unit + integration coverage across every Shield component, with OPA/Python parity fixtures that catch Rego drift in CI.

---

## Architecture

```
                            Agent (LLM + tools)
                                    │
                                    ▼  POST /execute  (optionally Ed25519-signed body)
                        ┌───────────────────────────────┐
                        │  FastAPI + CorrelationID MW   │
                        │  SlowAPI (per-agent key)      │
                        │  ReplayGuard  (Redis SET NX)  │  ← feature-flagged
                        │  BodySignature verifier       │  ← feature-flagged
                        └──────────────┬────────────────┘
                                       │
                                       ▼
                        ┌───────────────────────────────┐
                        │   Legacy policy engine        │   per-tx + daily
                        │   PolicyCache (TTL + pub/sub) │   limits + domains
                        └──────────────┬────────────────┘
                                       │
                                       ▼
                ┌──────────────────────────────────────────┐
                │            APEX-Shield pipeline          │
                │  ┌────────────────────────────────────┐  │
                │  │ 1. canonicalize_intent → SHA-256   │  │
                │  │ 2. risk_filter (pluggable)         │  │
                │  │ 3. OPA gate (sidecar + fallback)   │  │
                │  │ 4. credential_manager (scoped)     │  │
                │  │ 5. receipt_service (Ed25519)       │  │
                │  └────────────────────────────────────┘  │
                └──────────────┬───────────────────────────┘
                               │
             allowed ──────────┤────────── denied / escalated
                               │                │
                               ▼                ▼
                        GatewayResponse   HITLStore  (human review)
                               │
                               │  (on /pay only) agent row SELECT FOR UPDATE
                               │  → verify balance → decrement → SETTLED
                               │
                               ▼
                      AuditQueue (Redis RPUSH, back-pressure → 503)
                               │
                  ┌────────────┘
                  ▼
           AuditWorker (async drain, IntegrityError-tolerant for dedup)
                  │
                  ▼  INSERT audit_logs  (apex_auditor role, INSERT-only)
           Postgres ───────────────────► AFTER INSERT TRIGGER
                                              │ pg_notify('audit_feed', id)
                                              ▼
                                    AuditFeedBroker (single LISTEN conn)
                                              │ fanout via asyncio.Queue
                                              ▼
                                    SSE clients (React dashboard)

    Side channels:
      • /metrics  → Prometheus scrape (decisions, latency, queue depth, risk hist)
      • /ready    → deep readiness (DB + Redis + OPA + broker)
      • /.well-known/apex-jwks → Ed25519 public keys for third-party verification
```

---

## Tech stack

| Layer                 | Technology                                    |
| --------------------- | --------------------------------------------- |
| API framework         | FastAPI 0.115, Pydantic 2.10                  |
| Async runtime         | uvicorn + asyncio + asyncpg                   |
| ORM                   | SQLAlchemy 2.0 async                          |
| Database              | PostgreSQL (Supabase-compatible)              |
| Cache / queue         | Redis 7 (async, hiredis) — audit queue, policy pub/sub, replay-nonce store |
| Policy engine         | Open Policy Agent + embedded Python fallback  |
| Cryptography          | Ed25519 (cryptography), HMAC-SHA256           |
| Observability         | Pydantic Logfire (OTel) + Prometheus client   |
| Rate limiting         | SlowAPI (per-agent key-func)                  |
| Real-time stream      | PostgreSQL LISTEN/NOTIFY + SSE                |
| Frontend              | React 19, Vite 8, Tailwind, Recharts          |
| Tests                 | pytest + pytest-asyncio (138 passing)         |

---

## Installation

### Prerequisites

- **Python 3.11+** (tested on 3.13)
- **Node.js 20+** and **npm** (for the dashboard)
- **Redis 7** — `brew install redis && brew services start redis`
- **PostgreSQL 15+** — local or managed (Supabase works out of the box)
- **psql** CLI — for applying migrations

### 1. Clone and install Python dependencies

```bash
git clone <your-fork-url> apex-pay
cd apex-pay

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment

```bash
cp .env.example .env
# Edit .env with your database DSNs and secrets.
# See the Configuration section below for what each value means.
```

The `.env` file is in `.gitignore`. Never commit real credentials.

### 3. Provision the database

Create three least-privilege roles and load the schema. The `schema.sql` file sets up the role grants; `migrations/` contains the zero-trust hardening and live-stream trigger.

```bash
# Against a fresh Postgres / Supabase project:
psql "$DATABASE_URL" -f schema.sql
psql "$DATABASE_URL" -f migrations/001_shield_hardening.sql
psql "$DATABASE_URL" -f migrations/002_audit_notify.sql
psql "$DATABASE_URL" -f migrations/003_audit_dedup.sql
# migration 004 is OPT-IN for v3 scale — see its header for the cutover procedure.

# Verify all three triggers are present:
psql "$DATABASE_URL" -c "
  SELECT tgname FROM pg_trigger WHERE tgrelid = 'audit_logs'::regclass;
"
# Expect: trg_audit_no_update, trg_audit_notify, plus RI_ConstraintTrigger_* rows
```

### 4. Start Redis

```bash
brew services start redis   # macOS
# or: docker run -d -p 6379:6379 redis:7
redis-cli ping              # expect: PONG
```

### 5. Run the gateway

```bash
uvicorn apex_pay.main:app --reload --port 8000
```

You should see, in order:

```
Redis audit queue connected.
Audit feed broker starting (channel=audit_feed)
Audit feed broker connected; LISTEN audit_feed
Application startup complete.
```

### 6. Run the dashboard

```bash
cd apex-command-app
npm install
# Optional: point the dashboard at a non-local gateway
echo "VITE_API_URL=http://localhost:8000" > .env.local
npm run dev
```

Open `http://localhost:5173`. The header badge should transition amber (connecting) → emerald (live) within a second.

---

## Quickstart — fire a policy-gated tool-call

With the gateway running, seed an agent and a policy, then fire three requests that exercise APPROVE / per-transaction DENY / domain DENY:

```bash
# One-time seed
psql "$DATABASE_URL" <<'SQL'
WITH new_agent AS (
  INSERT INTO agents (id, name, status)
  VALUES (gen_random_uuid(), 'demo-agent', 'active')
  RETURNING id
)
INSERT INTO policies (agent_id, is_active, max_per_transaction, daily_limit, allowed_domains)
SELECT id, true, 50.00, 200.00, ARRAY['api.stripe.com','api.openai.com']
FROM new_agent;
SQL

AGENT_ID=$(psql "$DATABASE_URL" -tA -c "SELECT id FROM agents WHERE name='demo-agent';")

# 1. APPROVED
curl -s -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"$AGENT_ID\",\"tool_call\":{\"function\":\"charge_card\",\"target_url\":\"https://api.stripe.com/v1/charges\",\"parameters\":{\"amount\":12.50}}}" | jq .

# 2. DENIED — per-transaction cap
curl -s -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"$AGENT_ID\",\"tool_call\":{\"function\":\"charge_card\",\"target_url\":\"https://api.stripe.com/v1/charges\",\"parameters\":{\"amount\":9999.00}}}" | jq .

# 3. DENIED — disallowed domain
curl -s -X POST http://localhost:8000/execute \
  -H "Content-Type: application/json" \
  -d "{\"agent_id\":\"$AGENT_ID\",\"tool_call\":{\"function\":\"exfiltrate\",\"target_url\":\"https://evil.example.com/drop\",\"parameters\":{\"amount\":1.00}}}" | jq .
```

All three will appear in the dashboard's Live Nerve Center feed within ~100ms.

---

## API surface

### Gateway

| Method | Path                          | Purpose                                                           |
| ------ | ----------------------------- | ----------------------------------------------------------------- |
| POST   | `/execute`                    | Main entry point. Intent → policy → decision + receipt.           |
| GET    | `/data`                       | Protected data endpoint — 402 challenge / bearer-token flow.      |
| POST   | `/pay`                        | Settle a 402 challenge, atomic balance debit, signed token.       |
| POST   | `/shield/verify-receipt`      | Offline verification of an Ed25519 execution receipt (JSON body). |
| GET    | `/shield/verify-receipt`      | Same verification via `?receipt=<b64url>` — cache/CDN-friendly.   |
| GET    | `/.well-known/apex-jwks`      | RFC 7517 JWKS for the current & rotating Ed25519 public keys.     |
| GET    | `/health`                     | Liveness.                                                         |
| GET    | `/ready`                      | Readiness — deep-checks DB, Redis, OPA, audit-feed broker.        |
| GET    | `/metrics`                    | Prometheus scrape target.                                         |
| POST   | `/reset`                      | Clear ledger (dev only).                                          |

### Dashboard

| Method | Path                              | Purpose                                        |
| ------ | --------------------------------- | ---------------------------------------------- |
| GET    | `/dashboard/agents`               | Registered agents and their policies.          |
| PATCH  | `/dashboard/agents/{id}/status`   | Freeze / unfreeze an agent.                    |
| GET    | `/dashboard/audit-logs`           | Paginated decision history.                    |
| GET    | `/dashboard/audit-logs/stream`    | Server-Sent Events live tail.                  |
| POST   | `/dashboard/policies`             | Create or update a policy.                     |
| GET    | `/dashboard/stats`                | Aggregate decision counts.                     |
| GET    | `/dashboard/throughput`           | Requests-per-minute time series.               |

### HITL

| Method | Path                              | Purpose                                        |
| ------ | --------------------------------- | ---------------------------------------------- |
| GET    | `/hitl/pending`                   | Escalated requests awaiting review.            |
| POST   | `/hitl/{id}/decision`             | Approve or reject a pending escalation.        |

---

## Configuration

All configuration is environment-driven via `pydantic-settings`. The `.env.example` is checked in with safe placeholders; copy it to `.env` before running anything.

| Variable                             | Purpose                                                                |
| ------------------------------------ | ---------------------------------------------------------------------- |
| `DB_GATEWAY_DSN`                     | Read/write session. Role: `apex_gateway`.                              |
| `DB_AUDITOR_DSN`                     | INSERT-only, for the audit worker. Role: `apex_auditor`.               |
| `DB_READONLY_DSN`                    | SELECT-only, for dashboards and the LISTEN broker.                     |
| `REDIS_URL`                          | Audit queue, policy pub/sub, and (if enabled) replay-nonce store.      |
| `REDIS_MAX_QUEUE_DEPTH`              | Audit-queue back-pressure threshold — 503 is returned when exceeded.   |
| `SECURITY_HMAC_SECRET_KEY`           | Payment-token signing key. 64-char hex.                                |
| `SECURITY_REQUIRE_NONCE`             | **Feature flag** (default `false`). Enforce nonce + issued_at window.  |
| `SECURITY_NONCE_TTL_SECONDS`         | Replay-protection window. Also bounds clock skew. Default 300 s.       |
| `SECURITY_REQUIRE_BODY_SIGNATURE`    | **Feature flag** (default `false`). Require Ed25519-signed request bodies. |
| `SHIELD_ED25519_PRIVATE_B64`         | Base64 Ed25519 private key for execution receipts. Generate fresh.     |
| `SHIELD_ED25519_PUBLIC_KEYS_JSON`    | `{kid: b64pub}` verification map. Enables zero-downtime key rotation.  |
| `SHIELD_OPA_URL`                     | OPA sidecar HTTP endpoint. Leave empty to use Python fallback.         |
| `SHIELD_RISK_FILTER_URL`             | Optional Llama-Guard-compatible semantic risk classifier.              |
| `RATELIMIT_DEFAULT`                  | Per-IP SlowAPI default (e.g. `60/minute`).                             |
| `RATELIMIT_PER_AGENT`                | Per-agent ceiling when `X-APEX-Agent-ID` is present (e.g. `30/minute`). |
| `LOGFIRE_TOKEN`                      | Pydantic Logfire — empty = console only.                               |

---

## Zero-trust design notes

### Least-privilege roles

Three roles, three DSNs. No role can do everything:

```
apex_gateway  — SELECT/INSERT/UPDATE on agents, policies, transactions
apex_auditor  — INSERT only on audit_logs
apex_readonly — SELECT only on audit_logs, agents, policies
```

A compromised gateway cannot tamper with historical audit rows. A compromised dashboard cannot write anywhere. The audit worker can append, but not modify or delete.

### Append-only audit log

Two layers of enforcement:

1. **Role grants** — `apex_auditor` is granted `INSERT` only; `UPDATE`, `DELETE`, and `TRUNCATE` are not in its ACL.
2. **Trigger defense** — `trg_audit_no_update` raises on any `UPDATE`, in case role privileges are misconfigured.

### Live stream without connection storms

The audit feed uses a **single-connection broker** pattern: one `LISTEN` connection per uvicorn worker, fanning notifications out to many SSE subscribers via per-client `asyncio.Queue`s. This sidesteps Supabase Supavisor's per-pool connection cap and avoids tripping its upstream circuit breaker under load — a lesson learned the hard way.

### Ed25519 signed receipts

Every APPROVED decision produces a receipt:

```json
{
  "receipt": {
    "v": 1,
    "intent_hash": "af23974c28c4a22fb92e572241dd54b6bddba4845f1a2515091791a455fdaad1",
    "agent_id": "...",
    "policy_version": "2026.04.17",
    "risk_score": 0.05,
    "token_id": "ec_9REHxgCZ4JcjeHRk7zhyAA",
    "kid": "key-ephemeral",
    "issued_at": 1776550714,
    "expires_at": 1776550774,
    "extra": { "action_domain": "api.stripe.com", "projected_cost": 12.5 }
  },
  "signature": "8+iOV/8iyd85BJsRtaxaBNwLO77ezbYDYl7XBrSw2XFfZrJSFYd15BaqcKPxzOBtn4uw5ikjCibkYTDY05WRBA==",
  "kid": "key-ephemeral"
}
```

Anyone — including third-party auditors — can verify the receipt against the public key by `POST /shield/verify-receipt` or by using the verification code directly. No database round-trip required.

### Fail-closed OPA

The Rego policy is the source of truth. If the OPA sidecar is unreachable, APEX-Shield evaluates the same rules via an embedded Python mirror of `apex.rego`. The fallback path only ever produces the same or a stricter decision — it cannot accidentally approve what OPA would deny. Every fallback increments `apex_opa_fallback_total`; alert when the rate crosses ~1% to catch sidecar flapping early.

---

## Production hardening

The codebase follows a formal backend blueprint ([`docs/BACKEND_BLUEPRINT.md`](docs/BACKEND_BLUEPRINT.md)) modelled on the donnemartin system-design-primer conventions: use cases → back-of-envelope → high-level → core components → CAP trade-offs → scale → security → observability → deploy. The blueprint calls out which subsystem is CP, which is AP, and where back-pressure propagates; the implementation matches.

### Hot-path correctness

- **Atomic money math** — `/pay` opens a `SELECT ... FOR UPDATE` on the agent row, verifies `current_balance ≥ amount`, decrements, and flips the transaction to `SETTLED` in one DB transaction. Insufficient balance is an explicit `DENIED` reason, not a 500. A mid-flight crash leaves the ledger in a consistent state; there is no window in which a token is issued without the corresponding debit.
- **Exactly-once audit** — at-least-once delivery from the Redis queue is collapsed at the DB with a partial unique index on `(intent_hash, agent_id, date_trunc('minute', created_at))`. The audit worker catches `IntegrityError` (SQLSTATE 23505) and treats it as success, so retries after a worker crash can't pollute dashboards or billing analytics.
- **Idempotent `/pay`** — `(agent_id, idempotency_key)` uniqueness plus a cache of the original receipt means a retried settlement returns the same token and never double-debits.

### Observability

- **Prometheus `/metrics`** exports:
  - `apex_decision_total{status}` — APPROVED / DENIED / ESCALATED / ERROR counts
  - `apex_decision_latency_seconds` histogram, plus per-stage `apex_decision_stage_latency_seconds{stage}`
  - `apex_risk_score` — distribution, for threshold tuning
  - `apex_opa_fallback_total` — sidecar-health proxy
  - `apex_audit_queue_depth` — sampled on scrape, drives back-pressure alerts
  - `apex_audit_backpressure_total`, `apex_replay_rejections_total{reason}`, `apex_signature_rejections_total{reason}`, `apex_hitl_pending`
- **Correlation IDs** — every request is stamped with an `X-Request-ID` (minted or propagated from the edge), stored in a contextvar, echoed on the response, and attached to every Logfire span, unhandled-exception log, and audit row. One trace spans edge → gateway → shield stages → DB → SSE.
- **Deep readiness** — `/ready` runs a trivial query on the gateway DSN, an LLEN on Redis, a no-op OPA evaluation, and a liveness check on the audit-feed broker. Returns 503 when any of them are down, so k8s / ALB pulls the replica out of rotation without killing it.

### Performance & scale

- **Policy cache (cache-aside, TTL + pub/sub)** — the active policy snapshot per `agent_id` is memoized in-process for `~5 s`. Admin policy edits publish on `apex.policies.invalidate` so peer replicas evict synchronously; a SQLAlchemy ORM `after_update` listener covers code paths that bypass the admin router. Redis going down degrades to TTL-only — safe, not fatal.
- **Per-agent rate limit** — SlowAPI's key function resolves `X-APEX-Agent-ID` → `X-Client-Cert-CN` → remote IP. One misbehaving agent burns its own quota, not its neighbours'. Both `RATELIMIT_DEFAULT` and `RATELIMIT_PER_AGENT` apply; the stricter governs.
- **Partitioning playbook** — [`migrations/004_audit_partitioning.sql`](migrations/004_audit_partitioning.sql) ships an opt-in `audit_logs_partitioned` table with the same schema and write-once enforcement, plus an `apex_create_audit_partition(year, month)` helper for pg_cron, and a documented swap procedure that keeps the existing table as a safety net. Fresh installs can adopt partitioning from day one; live systems cut over in a maintenance window.

### Security depth

- **Third-party receipt verification** — `/.well-known/apex-jwks` publishes every active Ed25519 public key in RFC 7517 format with `kty=OKP`, `crv=Ed25519`. Verifiers pin on `kid` and rotate without a flag day: an old key stays in the JWKS map until all receipts signed with it expire. Receipts are also verifiable via `GET /shield/verify-receipt?receipt=<b64url>` for caches, CDNs, and shell-script verifiers.
- **Opt-in request-envelope hardening** (`SECURITY_REQUIRE_NONCE`, `SECURITY_REQUIRE_BODY_SIGNATURE`) — both default OFF so existing callers keep working. When enabled:
  - `ReplayGuard` uses Redis `SET NX` with a TTL equal to the replay window, so the nonce claim is atomic. Requests with reused nonces or out-of-window `issued_at` get a 401 with a structured reason code. Fails CLOSED if Redis is unavailable.
  - `BodySignature` verifies `X-APEX-Signature: ed25519:<b64>` against `agents.public_key` (stored as url-safe base64 of the raw 32-byte key — same encoding as JWKS `x`). Every failure mode maps to a specific metric label (`missing`, `malformed`, `invalid`, `unknown_agent`) so dashboards can tell a misconfigured SDK from an attack.

---

## Testing

```bash
python3 -m pytest -q
# 138 passed, 1 warning in 5.59s
```

Suites:

- `test_gateway_endpoints.py` — full request/response flow for `/execute`, `/data`, `/pay`.
- `test_policy_engine.py` — budget arithmetic, domain matching, edge cases around daily rollovers.
- `test_audit_queue.py` — Redis serialization, back-pressure, graceful degradation when Redis is down.
- `test_shield_pipeline.py` — end-to-end zero-trust path including deny/escalate branches.
- `test_shield_intent.py` — canonicalization stability and SHA-256 determinism.
- `test_shield_risk_filter.py` — pluggable filter interface and entropy calculation.
- `test_shield_opa.py` — sidecar + fallback parity.
- `test_shield_credential_manager.py` — scope-bound token issuance and verification.
- `test_shield_receipt_service.py` — Ed25519 signing, verification, key rotation.
- `test_admin_endpoints.py`, `test_token_service.py`, `test_schemas.py` — supporting coverage.

---

## Observability

Every decision emits a Pydantic Logfire span with `agent_id`, `tool_call`, `status`, `reason`, `latency_ms`, `intent_hash`, `risk_score`, and any policy violations. Logfire is OTel-compatible — pipe to any observability backend you prefer, or run in console-only mode with `LOGFIRE_TOKEN` empty.

For quick local debugging without Logfire:

```bash
tail -f logs.json | jq 'select(.msg | contains("Policy decision"))'
```

---

## Research foundation

- **APEX paper** — *A Policy-Gated Execution Layer for Agentic Commerce*, arXiv:2604.02023. Provided the `/execute`, `/data`, `/pay` contract and the three-baseline evaluation framework.
- **ClawSafety paper** — *Adversarial Probing of Skill-Based Agent Frameworks*, arXiv:2604.01438. Provided the threat model: skill-injection (69.4% ASR), declarative bypass, capability confusion.
- **Open Policy Agent (CNCF)** — policy-as-code substrate. See `policies/apex.rego` for the source rules and `policies/apex_test.rego` for the property tests.

See `docs/SECURITY.md` for the full architecture note tracing each threat-model vector to the component that mitigates it.

---

## Roadmap

The full blueprint — including SLO targets, back-of-envelope capacity for a 10k-agent tenant, a CAP breakdown per subsystem, a multi-region topology, and seven open architectural questions — lives in [`docs/BACKEND_BLUEPRINT.md`](docs/BACKEND_BLUEPRINT.md). Short-term items on the implementation side:

- **Default-on request signing** — nonce + body-signature enforcement is feature-flagged today; flip on per-environment once agent SDKs ship with the client-side signer.
- **OPA bundle server** — serve `apex.rego` from a signed OCI-registry bundle instead of the bundled fallback, so policy updates roll out without redeploying the gateway.
- **Llama Guard co-location** — when the heuristic classifier is superseded, GPU-backed model servers need to sit next to gateway pods; heuristic stays as the low-risk fast path.
- **Multi-tenant HITL UI** — the queue and API are done; the reviewer console is currently a single-agent prototype.
- **Formal Rego ↔ Python parity** — property-based testing today; SMT-backed equivalence checking is a stretch goal tracked in the blueprint's open questions.
- **Execution-proxy mode (OPEN)** — should the gateway itself make the downstream tool call for high-risk targets, or always hand the agent a scoped credential? Blueprint §15 lays out the trade.

---

## License

TBD. Research reference material (`APEX_reference.pdf`) is redistributed under the terms of its original license.

## Acknowledgements

Built on top of the APEX and ClawSafety research, with grateful use of FastAPI, SQLAlchemy, OPA, and the broader Python async ecosystem.
