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
- **Append-only audit log** — role-enforced INSERT-only access, plus a `pg_notify` trigger that streams every decision to subscribed dashboards in real time.
- **Live Nerve Center dashboard** — a React single-page app with a Server-Sent Events feed backed by a shared `LISTEN` broker; sub-100ms tail latency from decision to pixel.
- **Cryptographically non-repudiable** — Ed25519 signed receipts bound to content-addressable intent hashes.
- **HITL escalation** — high-entropy risk classifier outputs route to a human-review queue instead of guessing.
- **OPA + Python fallback** — Rego as the source of truth, with an embedded Python mirror of the same rules so the sidecar being unreachable can never open the deny path.
- **138 tests, all green.** Unit + integration coverage across every Shield component.

---

## Architecture

```
                            Agent (LLM + tools)
                                    │
                                    ▼  POST /execute
                        ┌───────────────────────────┐
                        │   APEX-Pay FastAPI        │
                        │   SlowAPI rate limiter    │
                        └──────────────┬────────────┘
                                       │
                                       ▼
                        ┌───────────────────────────┐
                        │   Legacy policy engine    │   per-tx + daily
                        │   (budget math)           │   limits + domains
                        └──────────────┬────────────┘
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
                               ▼
                      AuditQueue (Redis RPUSH)
                               │
                  ┌────────────┘
                  ▼
           AuditWorker (async drain)
                  │
                  ▼  INSERT audit_logs  (apex_auditor role, INSERT-only)
           Postgres ───────────────────► AFTER INSERT TRIGGER
                                              │ pg_notify('audit_feed', id)
                                              ▼
                                    AuditFeedBroker (single LISTEN conn)
                                              │ fanout via asyncio.Queue
                                              ▼
                                    SSE clients (React dashboard)
```

---

## Tech stack

| Layer                 | Technology                                    |
| --------------------- | --------------------------------------------- |
| API framework         | FastAPI 0.115, Pydantic 2.10                  |
| Async runtime         | uvicorn + asyncio + asyncpg                   |
| ORM                   | SQLAlchemy 2.0 async                          |
| Database              | PostgreSQL (Supabase-compatible)              |
| Cache / queue         | Redis 7 (async, hiredis)                      |
| Policy engine         | Open Policy Agent + embedded Python fallback  |
| Cryptography          | Ed25519 (PyNaCl / cryptography)               |
| Observability         | Pydantic Logfire (OTel-compatible)            |
| Rate limiting         | SlowAPI                                       |
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

| Method | Path                          | Purpose                                                       |
| ------ | ----------------------------- | ------------------------------------------------------------- |
| POST   | `/execute`                    | Main entry point. Intent → policy → decision + receipt.       |
| GET    | `/data`                       | Protected data endpoint — 402 challenge / bearer-token flow.  |
| POST   | `/pay`                        | Settle a 402 challenge and receive a signed token.            |
| POST   | `/shield/verify-receipt`      | Offline verification of an Ed25519 execution receipt.         |
| GET    | `/health`                     | Liveness.                                                     |
| POST   | `/reset`                      | Clear ledger (dev only).                                      |

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

| Variable                          | Purpose                                                            |
| --------------------------------- | ------------------------------------------------------------------ |
| `DB_GATEWAY_DSN`                  | Read/write session. Role: `apex_gateway`.                          |
| `DB_AUDITOR_DSN`                  | INSERT-only, for the audit worker. Role: `apex_auditor`.           |
| `DB_READONLY_DSN`                 | SELECT-only, for dashboards and the LISTEN broker.                 |
| `REDIS_URL`                       | Audit queue backing store.                                         |
| `REDIS_MAX_QUEUE_DEPTH`           | Back-pressure threshold — 503 is returned when exceeded.           |
| `SECURITY_HMAC_SECRET_KEY`        | Payment-token signing key. 64-char hex.                            |
| `SHIELD_ED25519_PRIVATE_B64`      | Base64 Ed25519 private key for execution receipts. Generate fresh. |
| `SHIELD_OPA_URL`                  | OPA sidecar HTTP endpoint. Leave empty to use Python fallback.     |
| `SHIELD_RISK_FILTER_URL`          | Optional Llama-Guard-compatible semantic risk classifier.          |
| `RATELIMIT_DEFAULT`               | Global SlowAPI default (e.g. `60/minute`).                         |
| `LOGFIRE_TOKEN`                   | Pydantic Logfire — empty = console only.                           |

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

The Rego policy is the source of truth. If the OPA sidecar is unreachable, APEX-Shield evaluates the same rules via an embedded Python mirror of `apex.rego`. The fallback path only ever produces the same or a stricter decision — it cannot accidentally approve what OPA would deny.

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

- **Migration 003** — lock down Supabase's default `anon`/`authenticated`/`service_role` grants on `audit_logs`. (Currently the app-level roles are correctly scoped, but PostgREST defaults leave a PostgREST-accessible tampering window.)
- **Persistent Ed25519 key** — ship a key-loading helper so receipts verify across process restarts without hand-rolling base64.
- **OPA bundle server** — serve `apex.rego` from a signed bundle URL instead of the bundled fallback, so policy updates roll out without redeploying the gateway.
- **Multi-tenant HITL UI** — the queue and API are done; the reviewer console is currently a single-agent prototype.
- **Throughput benchmarks at p99** — instrument a load-gen harness and publish numbers against the APEX paper's baselines.

---

## License

TBD. Research reference material (`APEX_reference.pdf`) is redistributed under the terms of its original license.

## Acknowledgements

Built on top of the APEX and ClawSafety research, with grateful use of FastAPI, SQLAlchemy, OPA, and the broader Python async ecosystem.
