# APEX-Pay Backend Blueprint

*Agentic Transaction Gateway — system design reference, modeled on the donnemartin/system-design-primer conventions.*

This blueprint is the authoritative design document for the APEX-Pay backend. It assumes the reader has skimmed `README.md` and `docs/SECURITY.md`. Where an existing component is already implemented, the section cites the file; where a decision is open, it is flagged **OPEN**.

---

## 1. Problem statement

APEX-Pay is a **policy-enforcing transaction gateway** sitting between autonomous LLM agents and the real-world tools/APIs that cost money or touch sensitive data. Every tool call an agent wants to make is intercepted, scored for prompt-injection and declarative-framing risk, matched against a signed per-agent policy, and either approved (with a short-lived scope-bound credential and a signed receipt) or denied/escalated to a human. Every decision is written to an append-only audit log that downstream finance, compliance, and SRE can stream in real time.

The core threat we are defending against is **attacker-controlled natural language** flowing into a capable model — the ClawSafety-style 69.4% attack-success rate on skill injection. We cannot trust the agent's prompt, we cannot trust the agent's reasoning, and we cannot trust the tool the agent is about to call. We can only trust **cryptographically-verified intent** plus **policy**.

---

## 2. Use cases, actors, and constraints

### 2.1 Actors

| Actor | Description |
|---|---|
| **Agent** | An LLM-powered autonomous process registered in `agents` with a public key and balance. Calls `/execute`, `/data`, `/pay`. |
| **Tool / downstream API** | The external target (Stripe, Slack, internal CRUD). Receives a scope-bound credential, never the agent's raw key. |
| **Policy author** | Human who writes Rego + Python policy snapshots for agents. |
| **HITL reviewer** | Human who approves/denies escalated intents through the reviewer console. |
| **SRE / compliance** | Consumes the SSE audit feed and the dashboards. |
| **Platform admin** | Creates agents, rotates keys, manages tenants. |

### 2.2 Use cases

**In scope (v1):**
1. `POST /execute` — agent submits an intent; gateway approves + returns a scope-bound token, denies, or escalates.
2. `POST /data` — read-only variant (no credential mint, just risk + OPA gate).
3. `POST /pay` — monetary-effect variant (strictest policy, mandatory receipt).
4. `GET /shield/verify-receipt` — any party verifies an Ed25519 receipt offline.
5. Real-time SSE feed of audit events for the dashboard.
6. HITL queue for soft-denied intents.
7. Admin CRUD over agents and policies.
8. Self-rotating keys (Ed25519 signer, HMAC token secret).

**Out of scope (v1):**
- Actually executing the downstream tool call. The gateway hands the agent a scoped credential; the agent makes the call. (See §14 for the "execution-proxy" variant.)
- Multi-tenant billing/invoicing for APEX-Pay itself.
- Cross-agent social graph / delegation chains.

### 2.3 Functional constraints

- **Non-repudiation**: every decision must be content-addressable (`intent_hash = SHA-256(canonicalized intent)`) and every approval must carry an Ed25519 signature over `(intent_hash, agent_id, token_id, risk_score, policy_version, issued_at, expires_at)`.
- **Append-only audit**: the audit log must be unforgeable by the gateway itself — the gateway's DB role has **no UPDATE or DELETE** on `audit_logs`. A DB trigger rejects mutation.
- **Fail-closed policy**: if the OPA sidecar is unreachable AND the embedded evaluator errors, the request is denied, not allowed.
- **Idempotency**: `/pay` is idempotent on `idempotency_key` per agent.
- **Short-lived credentials**: tokens expire in ≤60s by default; receipts in ≤5 min.

### 2.4 Non-functional constraints (target SLOs)

| Metric | Target (v1) | Target (v3 / scaled) |
|---|---|---|
| P50 latency `/execute` approve path | 80 ms | 40 ms |
| P99 latency `/execute` approve path | 350 ms | 150 ms |
| P99 latency including LLM risk classifier | 600 ms | 300 ms |
| Availability | 99.9% (≤8.8 h/yr) | 99.95% (≤4.4 h/yr) |
| Durable audit write loss | 0 | 0 |
| Max sustained RPS per region | 500 | 20,000 |
| Audit-log write lag (intent → DB) P99 | 500 ms | 200 ms |
| SSE feed lag (DB → dashboard) P99 | 1 s | 500 ms |

**Fail-closed is non-negotiable.** The gateway prefers a 503 over a wrong allow.

---

## 3. Back-of-the-envelope

Assume a mid-sized customer at v3 scale: 10k registered agents, each firing 1 req/min average, with peak bursts of 10×.

- **Steady-state QPS**: `10,000 × 1/60 ≈ 170 QPS`
- **Peak QPS**: `≈ 1,700 QPS`
- **Daily requests**: `10,000 × 1,440 = 14.4 M/day`
- **Audit log row size**: ~2 KB (raw_intent + policy_snapshot + hashes). `14.4M × 2 KB = 28.8 GB/day` → ~10 TB/year uncompressed. With monthly partitioning + pgroonga/columnar on partitions older than 30d, working set stays ~1 TB.
- **Redis audit queue**: at peak-burst (1,700 QPS × 2 KB) × 60s back-pressure window = ~200 MB in flight. Comfortable on a `cache.m7g.large`.
- **Ed25519 signatures**: ~50 µs/sig on modern x86. 1,700 QPS × 50 µs = 85 ms of aggregate CPU/sec per gateway replica — negligible.
- **LLM risk classifier** (when enabled): ~300 ms/call to an external Llama Guard endpoint. To hit P99 target we need either (a) co-located model servers, (b) async speculative pre-fetch, or (c) heuristic-first + LLM fallback. v1 uses (c).

These numbers drive the sharding/federation decisions in §11.

---

## 4. High-level architecture

```
                     ┌──────────────────────┐
                     │  Agent (LLM runtime) │
                     └──────────┬───────────┘
                                │ HTTPS + mTLS
                                ▼
          ┌────────────────────────────────────────┐
          │  Edge: TLS term, WAF, global rate-limit│
          └──────────────────┬─────────────────────┘
                             │
                             ▼
             ┌────────────────────────────────┐
             │  L7 LB (active-active, 2+ AZ)  │
             └───────┬────────────────┬───────┘
                     │                │
           ┌─────────▼────────┐  ┌────▼──────────┐
           │ Gateway replica  │  │ Gateway replica│  ... (N)
           │  (FastAPI async) │  │ (FastAPI async)│
           └───┬──────┬───┬───┘  └────────────────┘
               │      │   │
       ┌───────┘      │   └───────────────────────┐
       ▼              ▼                           ▼
 ┌──────────┐  ┌────────────────┐        ┌────────────────┐
 │ Policy   │  │  Shield        │        │ Token svc      │
 │ cache    │  │  pipeline      │        │ (HMAC, short)  │
 │ (Redis)  │  │  (in-process)  │        └──────┬─────────┘
 └────┬─────┘  │  ├─canonicalize│               │
      │       │  ├─risk_filter │               │
      │       │  ├─OPA sidecar │               │
      │       │  ├─cred mgr    │               │
      │       │  └─receipt (Ed)│               │
      │       └──────┬─────────┘                │
      │              │                          │
      │              ▼                          ▼
      │       ┌─────────────┐            ┌─────────────┐
      │       │ OPA sidecar │            │ Vault /     │
      │       │  (Rego)     │            │ KMS (keys)  │
      │       └──────┬──────┘            └─────────────┘
      │              │
      │              ▼ (fallback)
      │       ┌──────────────┐
      │       │ Embedded py  │
      │       │ policy eval  │
      │       └──────────────┘
      │
      ▼
┌────────────────────────────────────────┐
│  PostgreSQL (primary + 2 read replicas)│
│  - role apex_gateway  (R/W on agents,  │
│     policies, transactions)            │
│  - role apex_auditor  (INSERT-only on  │
│     audit_logs)                        │
│  - role apex_readonly (dashboards)     │
│  - pg_notify('audit_feed', id)         │
└──────┬────────────────────┬────────────┘
       │                    │
       ▼                    ▼
 ┌──────────┐         ┌────────────────┐
 │ Audit    │         │ LISTEN/NOTIFY  │
 │ queue    │         │ broker (single │
 │ (Redis)  │         │  conn, fan-out)│
 └────┬─────┘         └────────┬───────┘
      │                        │
      ▼                        ▼
 ┌──────────┐          ┌────────────────┐
 │ Audit    │          │ SSE endpoints  │
 │ worker   │          │ (dashboard)    │
 │ (N pods) │          └────────┬───────┘
 └────┬─────┘                   │
      │ INSERT (auditor role)   ▼
      └──────► Postgres    Reviewer UI /
                            HITL console
```

**Request path summary** (approve case):

```
Agent → Edge → LB → Gateway → Shield.canonicalize → Shield.risk_filter
  → Shield.OPA (allow) → Shield.credential_manager (mint 60s token)
  → Shield.receipt (Ed25519 sign) → audit_queue.push
  → return {token, receipt, expires_at} to agent
            ↓ (async)
         Audit worker → Postgres (auditor role)
            ↓ (trigger)
         pg_notify → broker → SSE subscribers
```

---

## 5. API surface

All endpoints are JSON over HTTPS, rate-limited via SlowAPI at the gateway, and globally at the edge. Agent auth is **mTLS + signed request body** (Ed25519, agent's registered public key).

### 5.1 Gateway (agent-facing)

| Method + path | Purpose | Hot-path latency budget |
|---|---|---|
| `POST /execute` | Generic tool-call intent, returns token+receipt or denial | 350 ms P99 |
| `POST /data` | Read-only intent (stricter risk thresholds, no credential) | 250 ms P99 |
| `POST /pay` | Monetary intent (mandatory receipt, idempotency required, strictest OPA) | 400 ms P99 |
| `GET /shield/verify-receipt?receipt=…` | Offline receipt verification | 50 ms P99 |
| `GET /health`, `GET /ready` | Liveness + readiness | 10 ms |

All hot-path POSTs share this envelope:

```jsonc
// Request
{
  "agent_id": "uuid",
  "nonce": "base64",           // replay protection
  "issued_at": "RFC3339",
  "intent": {
    "function": "stripe.charge",
    "target_url": "https://api.stripe.com/v1/charges",
    "parameters": { "amount": 2500, "currency": "USD", "customer": "cus_..." },
    "projected_cost_usd": 25.00
  },
  "idempotency_key": "optional-for-/pay"
}
// Signed by agent private key over canonical JSON; signature in header.
```

```jsonc
// Approve response
{
  "status": "APPROVED",
  "token": "eyJ...",            // HMAC, scope={function,target,params_hash,exp}
  "expires_at": "RFC3339",
  "receipt": {
    "v": 1,
    "intent_hash": "sha256:...",
    "agent_id": "...",
    "token_id": "...",
    "risk_score": 0.12,
    "policy_version": 42,
    "issued_at": "...",
    "expires_at": "...",
    "signature": "ed25519:..."
  }
}
```

```jsonc
// Deny / escalate response
{
  "status": "DENIED" | "ESCALATED",
  "reason": "per_transaction_limit_exceeded",
  "intent_hash": "sha256:...",
  "hitl_request_id": "uuid"     // only when status=ESCALATED
}
```

### 5.2 Admin / dashboard

| Method + path | Purpose |
|---|---|
| `POST /admin/agents` | Register agent (idempotent on name) |
| `POST /admin/policies` | Create / version policy snapshot |
| `GET /dashboard/agents` | Paged list with daily spend |
| `GET /dashboard/audit-logs` | Paged + filterable |
| `GET /dashboard/audit-logs/stream` | SSE subscription |
| `GET /hitl/pending` | Reviewer queue |
| `POST /hitl/{id}/approve` | Reviewer decision (signs a reviewer receipt) |
| `POST /hitl/{id}/deny` | Reviewer decision |

Admin and dashboard endpoints sit behind a separate OIDC ingress and are not co-tenant with the agent hot path.

---

## 6. Data model

The canonical schema lives in `schema.sql`; migrations accumulate in `migrations/`. This section captures the **invariants** the schema enforces and the partitioning plan for scale.

### 6.1 Tables and invariants

**`agents`** — one row per registered agent.

- `id` UUID PK, `name` UNIQUE, `public_key` TEXT, `current_balance` NUMERIC(18,4), `status` ENUM('active','suspended','revoked'), timestamps.
- Invariant: `current_balance ≥ 0`. Debits happen inside a transaction with `SELECT ... FOR UPDATE`.
- Indexes: `idx_agents_status`, `idx_agents_name`.

**`policies`** — versioned per-agent policy snapshots.

- `id` UUID PK, `agent_id` FK, `max_per_transaction` NUMERIC, `daily_limit` NUMERIC, `allowed_domains` JSONB, `is_active` BOOL, `version` INT, `created_at`.
- Invariant: at most one `is_active = true` row per `agent_id` (partial UNIQUE index).
- Policy snapshot is **immutable once written** — updates create a new row with `version+1`.

**`transactions`** — state machine per agent request.

- States: `CHALLENGED` → `INITIATED` → `SETTLED` → `CONSUMED`.
- Unique `(agent_id, idempotency_key)` when idempotency_key is non-null.
- `token` + `token_expiry` populated at SETTLED.
- Indexes: state, agent, token, idempotency_key.

**`audit_logs`** — append-only decision log.

- Columns: `id`, `agent_id`, `raw_intent` JSONB, `intent_hash` BYTEA, `projected_cost`, `action_domain`, `risk_score`, `risk_entropy`, `status`, `denial_reason`, `transaction_id`, `policy_snapshot` JSONB, `receipt` JSONB, `latency_ms`, `created_at`.
- **Append-only enforced two ways:**
  1. Role grants: only `apex_auditor` has `INSERT`; nobody has `UPDATE` or `DELETE`.
  2. A `BEFORE UPDATE OR DELETE` trigger raises an exception.
- Indexes: `agent_id`, `status`, `created_at`, composite `(agent_id, created_at) WHERE status='APPROVED'` for spend queries.
- **Partitioning (v3)**: `PARTITION BY RANGE (created_at)` monthly. Partitions older than 90 days move to columnar (e.g., Citus columnar or Timescale hypertable compression).

**`shield_hitl_requests`** — escalated intents awaiting human review.

- `id`, `intent_hash`, `agent_id`, `reason`, `violations` JSONB, `opa_input` JSONB, `risk_score`, `risk_entropy`, `resolution` ENUM('pending','approved','denied'), `resolver`, `resolved_at`.

**`v_daily_agent_spend`** — materialized view refreshed every minute for dashboard.

### 6.2 Role matrix

| Role | agents | policies | transactions | audit_logs | hitl |
|---|---|---|---|---|---|
| `apex_gateway` | S/I/U | S | S/I/U | — | S/I/U |
| `apex_auditor` | — | — | — | **I only** | — |
| `apex_readonly` | S | S | S | S | S |
| `apex_admin` | S/I/U/D | S/I/U/D | S | S | S |

This is the single most important security control in the system. A compromised gateway replica **cannot** cover its tracks.

### 6.3 Data lifecycle

- `audit_logs` retention: 7 years (compliance). Partitions >90d live on cheaper storage; >1y are optionally archived to S3 Glacier with a manifest indexed in a small `audit_archive` table.
- `transactions` retention: 90 days hot, then archived with its audit row.
- `shield_hitl_requests` retention: 90 days after resolution.

---

## 7. Core components

### 7.1 Edge ingress

- TLS termination at an L7 load balancer (ALB / GCLB / Envoy), with **mTLS** required on agent-facing routes — the client cert CN maps to `agent_id` and is cross-checked against the registered public key.
- A WAF layer (Cloudflare / AWS WAF) with baseline OWASP rules and a bot-scoring layer, but we **do not rely on WAF** for any semantic decision — the Shield pipeline is the source of truth.
- Global rate limit: per source IP, per agent_id, per tenant. Defaults: 10 QPS burst / 60 QPS sustained per agent.
- Health-check routing: `/health` (liveness) and `/ready` (checks DB + Redis + OPA reachability).

### 7.2 Gateway API service

- Stateless FastAPI app (`apex_pay/main.py`), deployed as N replicas behind the LB.
- **Async all the way down**: asyncpg for Postgres, async Redis client, httpx AsyncClient for OPA.
- Per-replica local caches (TTL ~5s) for:
  - Active policy snapshot keyed by `agent_id`.
  - Agent public key keyed by `agent_id`.
- These local caches are write-through-invalidated via Redis pub/sub channel `apex.policies.invalidate` so an admin policy edit propagates in ≤1s without a full cache flush.

The gateway never talks to the DB directly for hot-path reads beyond (a) the agent row with `FOR UPDATE` (for balance debit on `/pay`) and (b) the active policy on a cache miss. Everything else is in-memory after the first request.

### 7.3 Shield zero-trust pipeline

Implemented in `apex_pay/shield/pipeline.py` and already covered in depth in `docs/SECURITY.md`. The pipeline is **five stages, each independently testable, each fail-closed**:

1. **`canonicalize_intent`** — deterministic SHA-256 over (agent_id, function, target_url, sorted parameters). Produces `intent_hash`. This is the content-address used everywhere downstream.
2. **`risk_filter`** — pluggable classifier. v1 default: `HeuristicClassifier` (regex + entropy). v2: `LlamaGuardAdapter` (HTTP POST to a co-located Llama Guard 2 server, with heuristic fallback on timeout). Output: `{score ∈ [0,1], entropy ∈ [0,1], labels: [prompt_injection, declarative_framing, credential_forwarding, destructive_verb, ...]}`.
3. **OPA gate** — packages `{intent, policy_snapshot, risk}` as the OPA input; calls the sidecar at `SHIELD_OPA_URL/v1/data/apex/shield/decision`. Output: `allow | hard_deny | escalate`. If the sidecar times out (configurable, default 50 ms), falls back to `EmbeddedOPAEvaluator` — a Python reimplementation kept in lock-step via shared Rego fixtures in `policies/apex_test.rego`.
4. **`credential_manager`** — on `allow`, mints a scope-bound token. Dev backend: HMAC over `(intent_hash, exp, scope)` with `CRED_HMAC_SECRET`. Prod backend: HashiCorp Vault transit-engine sign + wrap, so the downstream tool validates against a Vault JWKS and the gateway never sees the signing key.
5. **`receipt_service`** — signs the envelope with Ed25519 private key (pulled from KMS/Vault at startup and rotated every 30 days; see `docs/SECURITY.md#key-rotation`). Receipt is verifiable offline by anyone with the rotating public JWKS at `GET /.well-known/apex-jwks`.

Pipeline is pure (no DB writes). The only side effects are (a) the Redis push of an audit record, (b) the balance debit for `/pay` inside a DB transaction. This is what makes it safe to horizontally scale the gateway.

### 7.4 Token service & transaction state machine

- HMAC tokens are compact and self-verifying — no DB lookup on the consumption path if the downstream tool is APEX-aware.
- For legacy downstreams, the `transactions.token` column is the source of truth and the gateway exposes `POST /internal/consume-token` with agent_id auth.
- State transitions are enforced by a CHECK + transition trigger in `transactions`; invalid transitions raise.
- `CHALLENGED` is the "agent got a 402 asking to pay" state, kept for the original APEX paper's two-phase flow. Under the zero-trust pipeline, most requests never enter `CHALLENGED` (the policy pre-approves budget), but the state remains so hitting a `/pay` with idempotency replays correctly.

### 7.5 Audit pipeline

This is the most load-bearing asynchrony in the system; its correctness is what lets us stamp 0 on the "durable audit write loss" SLO.

**Write path:**
1. Gateway, after any decision (allow/deny/escalate), serializes the audit record to Redis via `RPUSH apex.audit.queue`.
2. Before the push, it checks `LLEN apex.audit.queue`; if depth ≥ `REDIS_MAX_QUEUE_DEPTH`, the request returns **503** (back-pressure up to the caller). This is the single place we choose **availability of one request over consistency of the whole system** — we'd rather refuse new work than silently drop audits.
3. The audit worker pool (N pods) does `BLPOP` with a 1s timeout, then `INSERT` into `audit_logs` using the `apex_auditor` DSN. Inserts are batched when the queue is hot (up to 100 per transaction, `COPY`-style).
4. `AFTER INSERT` trigger fires `pg_notify('audit_feed', NEW.id)`.

**Read path (SSE):**
1. A **single** asyncpg connection in each gateway replica `LISTEN`s on `audit_feed`. This is critical — managed Postgres (Supabase, RDS) has connection-count ceilings that a naïve "listen per subscriber" would blow through.
2. The broker (`apex_pay/services/audit_feed_broker.py`) fans each notification to an in-process `asyncio.Queue` per subscriber.
3. SSE endpoints read the queue and serialize.

**Correctness properties:**
- At-least-once audit delivery from gateway to DB (Redis push is durable; worker retries on DB error).
- Exactly-once DB insert by using a unique `(intent_hash, agent_id, created_at_minute)` constraint (belt + suspenders against worker duplicate-processing).
- Audit latency: Redis push <2 ms; worker drain <50 ms; notify fan-out <5 ms.

**Failure modes:**
- Redis down → gateway 503 on new requests (fail-closed). We do not buffer in memory; the process can die and we must not lose audit rows.
- DB primary down → worker blocks, Redis queue fills, gateway back-pressures. SRE alerts fire on `redis_queue_depth > 50%`.
- Worker crash → Redis `BLPOP` is atomic, partial work is re-dequeued by the next worker.

### 7.6 Policy engine (OPA)

- **Source of truth**: `policies/apex.rego`. Committed with tests in `policies/apex_test.rego`.
- **Deployment**: OPA runs as a sidecar container next to each gateway replica. Policies are loaded from a bundle server (OCI registry in v3) with 30s refresh. Rollouts are flagged: `policy_version` is in every audit row.
- **Embedded fallback**: `apex_pay/shield/opa_client.py::EmbeddedOPAEvaluator` mirrors the Rego in Python. Same fixtures drive both test suites, so drift is caught in CI.
- **Policy versioning**: every decision carries `policy_version` in the receipt. Retiring a version triggers a grace window during which both old and new are evaluated and a divergence counter is exported to Prometheus.

---

## 8. Caching strategy

We use caching in four places, each with a different pattern from the primer.

| Where | What | Pattern | TTL / invalidation |
|---|---|---|---|
| Gateway replica in-proc | Active policy per agent | **Cache-aside** with pub/sub invalidation | 5 s TTL + Redis `apex.policies.invalidate` channel |
| Gateway replica in-proc | Agent public key | Cache-aside | 60 s TTL + invalidation on key rotation |
| Redis | Daily spend counter per agent | **Write-through** on `/pay` success | Midnight UTC rollover, recomputed from `audit_logs` |
| CDN / HTTP cache | `GET /.well-known/apex-jwks` | Public, CDN-cacheable | 300 s; receipt validators respect `Cache-Control` |

**What we do NOT cache:**
- OPA decisions. The risk score can vary per invocation (entropy from heuristic, model output from Llama Guard), and decisions are cheap. Caching here would undermine the "every request is evaluated" property.
- Audit log reads on the dashboard. We paginate over the partition, and the SSE stream handles real-time.

The daily-spend counter is the one place we trade a small consistency risk for big throughput. If the counter in Redis and the truth in `audit_logs` diverge (crash mid-increment), the next request recomputes from DB. The counter is an **optimization**, not the authority — `audit_logs` is always reconciled for the actual enforce decision when the counter is within 5% of the limit.

---

## 9. Asynchronism & back-pressure

Three async boundaries, each from the primer's playbook:

1. **Audit queue (Redis LIST)** — message queue between gateway and audit worker. Back-pressure by queue-depth check; 503 to caller when full.
2. **Postgres `LISTEN/NOTIFY`** — event bus between DB and dashboard SSE. Single listener per replica; fan-out in-process.
3. **Redis pub/sub `apex.policies.invalidate`** — cache invalidation signal. Fire-and-forget, best-effort — the 5s TTL bounds staleness even if a message is dropped.

Back-pressure propagates **outward only**: the gateway refuses new requests before it does anything unsafe (drop an audit, debit a balance without writing the decision). The primer's rule is "back-pressure all the way to the edge"; we extend that with per-tenant rate limits so a runaway agent degrades itself, not the fleet.

---

## 10. Consistency, availability, and the CAP trade

APEX-Pay sits firmly on the **CP** side of CAP for the **decision path** and **AP** for the **observability path**.

| Subsystem | Choice | Rationale |
|---|---|---|
| Decision (policy + receipt issuance) | **CP** — fail-closed on any unavailability | A wrong allow is worse than no allow |
| Balance debit on `/pay` | **CP** with strong consistency (single-writer, FOR UPDATE) | Money math cannot go eventually consistent |
| Audit log write | **CP** at DB, **AP** on the wire (Redis queue tolerates brief Redis outages by back-pressuring) | Loss is unacceptable; latency is negotiable |
| SSE dashboard feed | **AP** — may lag, must never block decisions | Observability must not be on the critical path |
| Daily spend counter | **AP** with periodic reconciliation | Optimization only |

**Idempotency** is enforced on `/pay` via `(agent_id, idempotency_key)` uniqueness; duplicate posts return the original receipt (extracted from `audit_logs`). This survives network retries on the agent side and gateway retries internally.

---

## 11. Scaling the design

### 11.1 Horizontal scale: gateway replicas

The gateway is stateless. Scale out by adding replicas behind the LB. Auto-scale on CPU + P99 latency. Expected ceiling per replica: ~500 RPS on a 2-vCPU container at 80% CPU.

### 11.2 Database federation

At v3 scale, `audit_logs` dominates write volume. Two complementary strategies:

- **Partitioning by time**: `audit_logs` partitioned monthly, with hot partitions on SSD and cold ones migrated to columnar (e.g., TimescaleDB continuous aggregates, or pg_partman + columnar). This is the **primary scale lever** and the one we recommend first — it delays any sharding need significantly.
- **Federation by tenant** (if multi-tenant): route `agent_id → tenant_id → DB cluster`. Each tenant gets its own Postgres logical DB on a shared cluster, or its own physical cluster above a volume threshold. Cross-tenant dashboards aggregate via a query fan-out.

We explicitly **avoid hash-sharding agents across clusters in v2** — it complicates the audit log's append-only property and the `FOR UPDATE` balance semantics. Tenancy boundaries are a much cleaner sharding key if we outgrow a single cluster.

### 11.3 Read replicas

Admin/dashboard reads go to a read replica with `apex_readonly` role. The replica is also the target of the SSE broker's LISTEN connection (Postgres 14+ supports LISTEN on standbys for notifications originating there; for strict ordering we keep LISTEN on primary and just route SELECTs to replica).

### 11.4 Redis topology

- Single-shard Redis Cluster with one primary + one replica per AZ, up to 3 AZs.
- The audit queue is a single key, so it does not shard; at 20k RPS peak a single primary handles it comfortably (<5% CPU).
- The cache-invalidation pub/sub channel is also single-shard; volume is low.
- If/when the audit queue saturates a single node, move to **Redis Streams with consumer groups** — the migration is local to the audit worker and keeps the queue-depth back-pressure pattern.

### 11.5 OPA

OPA is sidecar-per-replica, so it scales linearly with the gateway. The bundle server (OCI registry or simple HTTP) is CDN-cacheable.

### 11.6 Multi-region

- **Active-active** across two regions. Each region has its own Postgres primary; cross-region replication is **audit-only** (via logical replication on `audit_logs` into a global compliance warehouse).
- Agent traffic is routed via GeoDNS + health-based failover.
- Policy edits propagate via the bundle server; policy_version is the global truth.
- **Conflict model**: balance debits are region-local. An agent is pinned to a home region; cross-region writes are rejected. This is the cleanest way to avoid distributed transactions on money.

---

## 12. Security

Full threat model lives in `docs/SECURITY.md`. Key controls recapped here because the blueprint would be incomplete without them.

| Threat | Control |
|---|---|
| Prompt injection in the intent | Risk filter labels + OPA hard-deny on high-risk label set |
| Declarative framing ("as a trusted assistant...") | Heuristic label + entropy threshold |
| Credential forwarding | Scope-bound credentials that hash the target_url and parameters; downstream must match |
| Destructive verbs (`DELETE`, `rm`, `DROP`) | OPA hard-deny unless explicitly allowed by policy |
| Domain exfiltration | `allowed_domains` whitelist in policy snapshot |
| Audit tampering | Three-role DB + trigger + Ed25519 receipts replicated to a write-once object store |
| OPA sidecar compromise | Embedded Python fallback + signed bundle verification |
| Key leakage | Ed25519 signer in Vault transit; 30-day rotation with overlapping JWKS |
| Replay | `nonce` + `issued_at` on every agent request; nonce cache in Redis, TTL = 5 min |
| DoS | Per-agent, per-tenant rate limits; back-pressure to 503; edge WAF |

### 12.1 Secrets + keys

All secrets live in Vault. Startup pulls the Ed25519 private signing key via short-lived app-role creds. The public keyset is served at `/.well-known/apex-jwks` with overlapping validity during rotation.

### 12.2 mTLS

Agents authenticate with client certificates signed by an APEX private CA. The CN is the `agent_id`; the SAN includes the registered public key's fingerprint. mTLS is verified at the LB and the gateway cross-checks against `agents.public_key`.

---

## 13. Observability

### 13.1 Metrics (Prometheus / OpenMetrics)

- `apex_decision_total{status, agent_tier}` counter
- `apex_decision_latency_seconds{stage}` histogram (stages: canonicalize, risk, opa, cred, receipt, audit_push)
- `apex_audit_queue_depth` gauge
- `apex_audit_worker_lag_seconds` gauge
- `apex_opa_fallback_total` counter (alerts if > threshold)
- `apex_risk_score` histogram (helps tune thresholds)
- `apex_hitl_pending` gauge
- `apex_policy_divergence_total{policy_version}` counter (shadow-eval of new policy vs old)

### 13.2 Tracing

Logfire (OTel-compatible). A single trace covers edge → gateway → shield stages → DB → SSE. Spans include the `intent_hash` as an attribute so an audit row links to its exact trace.

### 13.3 Logging

- Structured JSON, correlation-id per request (request_id + intent_hash).
- Never log raw intent parameters if classified as sensitive (PII/payment). The audit DB record is the authoritative one and has different access controls.

### 13.4 Alerting

| Alert | Condition |
|---|---|
| Audit queue depth | > 50% of max for 5 min |
| OPA fallback rate | > 1% of decisions for 5 min |
| Decision P99 latency | > 2× SLO for 10 min |
| Balance debit reconciliation error | any |
| Receipt verification failures by third parties | rate > baseline — possible key distribution issue |
| HITL queue age | oldest > 15 min |

---

## 14. Deployment topology

```
Region us-east-1 (primary)                Region us-west-2 (active standby)
├── Edge: CloudFront + WAF                ├── Edge: CloudFront + WAF
├── LB: ALB                               ├── LB: ALB
├── Gateway: 8× Fargate tasks (autoscale) ├── Gateway: 4× Fargate tasks
├── OPA sidecar per task                  ├── OPA sidecar per task
├── Audit worker: 4× Fargate tasks        ├── Audit worker: 2× Fargate tasks
├── Redis Cluster: 3 AZ, primary+replica  ├── Redis Cluster: 3 AZ
├── Postgres: Aurora primary + 2 replicas ├── Postgres: Aurora primary + 2 replicas
├── Vault: HA cluster                     ├── Vault: replicated
└── Reviewer UI: CloudFront + S3          └── Reviewer UI: CloudFront + S3

Cross-region:
- Audit-log logical replication → compliance warehouse (S3 + Glue)
- Policy bundles → OCI registry (global)
- Vault replication for key material
```

Deployment unit is a container image per service (gateway, audit-worker, reviewer-ui). Infrastructure is Terraform; services are Fargate behind ALB for v1, with a migration path to EKS when we need richer scheduling (co-locate Llama Guard GPU pods with gateway pods).

---

## 15. Roadmap / open questions

1. **Execution-proxy mode (OPEN)**: should APEX-Pay itself make the downstream tool call rather than handing the agent a credential? Pros: complete mediation, easier audit. Cons: couples availability of the gateway to every tool; scope creep into vendor SDKs. **Leaning:** offer as an opt-in for high-risk tools only, with a pluggable `ToolExecutor` interface.
2. **Llama Guard co-location**: when LLM risk classifier becomes default, we need GPU pods. Likely EKS + Karpenter + L40S spot instances, with a heuristic-only fast path retained for low-risk intents.
3. **Multi-tenant HITL UI**: current reviewer console is single-tenant. Needs tenant scoping + reviewer RBAC.
4. **Formal verification of Rego / Python parity**: property-based testing today; SMT-backed eq-check is a stretch goal.
5. **Signed policy bundles**: bundle server signs manifests; OPA verifies before load. Deferred to v2.
6. **Cross-region active-active for balance debits**: requires either a CRDT balance or per-region sub-balances with periodic reconciliation. Deferred — pinning agents to a home region is the pragmatic v2 answer.
7. **Hardware-backed keys**: move Ed25519 signer from Vault transit to YubiHSM / Nitro Enclaves for the highest-tier customers.

---

## 16. Checklist for each new feature touching APEX-Pay

Before any code merges to `main`:

- [ ] Intent path still fails closed on OPA unreachable.
- [ ] Every new decision outcome writes to `audit_logs` with `intent_hash` and `policy_version`.
- [ ] If a new DB table is added, its role grants are explicit (no default PUBLIC grants).
- [ ] If the receipt envelope changes, `v` is bumped and verifiers handle both versions during the rollout window.
- [ ] New config keys have a safe default AND an env override.
- [ ] Prometheus metric added for any new stage ≥10 ms on the hot path.
- [ ] Test parity: Rego test + Python test for any OPA change.
- [ ] `docs/SECURITY.md` updated if the threat model or trust boundary moves.

---

*Last updated: 2026-04-20. Owner: APEX-Pay platform team.*
