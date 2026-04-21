-- =============================================================================
-- APEX-Pay: Supabase SQL Schema
-- Agentic Transaction Gateway — Policy-Gated Execution Layer
--
-- Design Notes:
--   • All tables use UUID primary keys for global uniqueness across services.
--   • ACID compliance is enforced via PostgreSQL transactions (Supabase default).
--   • The `audit_logs` table is INSERT-only by the audit writer role (Least Privilege).
--   • `allowed_domains` is stored as a JSONB array for flexible domain matching.
--   • Timestamps default to UTC via `now()` to avoid timezone drift.
-- =============================================================================

-- ---------- EXTENSIONS ----------
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- =============================================================================
-- TABLE: agents
-- Represents an autonomous AI agent registered with the gateway.
-- `current_balance` is updated atomically during settlement.
-- =============================================================================
CREATE TABLE IF NOT EXISTS agents (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name            TEXT NOT NULL UNIQUE,
    public_key      TEXT NOT NULL,                          -- PEM or base64-encoded public key
    current_balance NUMERIC(18, 4) NOT NULL DEFAULT 0.0
        CHECK (current_balance >= 0),
    status          TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'revoked')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_agents_status ON agents (status);
CREATE INDEX idx_agents_name   ON agents (name);

-- =============================================================================
-- TABLE: policies
-- Per-agent spending policy. One active policy row per agent.
-- `allowed_domains` stores a JSONB array of domain strings the agent may call.
-- `max_per_transaction` enforces per-request ceiling (paper: M = 10).
-- `daily_limit` enforces cumulative budget window  (paper: B_d = 100).
-- =============================================================================
CREATE TABLE IF NOT EXISTS policies (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id            UUID NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    max_per_transaction NUMERIC(18, 4) NOT NULL DEFAULT 10.0
        CHECK (max_per_transaction > 0),
    daily_limit         NUMERIC(18, 4) NOT NULL DEFAULT 100.0
        CHECK (daily_limit > 0),
    allowed_domains     JSONB NOT NULL DEFAULT '[]'::JSONB,  -- e.g. ["api.stripe.com", "api.openai.com"]
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT uq_active_policy_per_agent
        UNIQUE (agent_id, is_active)                        -- At most one active policy per agent
);

CREATE INDEX idx_policies_agent ON policies (agent_id) WHERE is_active = TRUE;

-- =============================================================================
-- TABLE: audit_logs
-- Immutable, append-only ledger of every policy decision.
-- The DB role used by the audit writer has INSERT-only privileges.
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID NOT NULL REFERENCES agents (id) ON DELETE SET NULL,
    raw_intent      JSONB NOT NULL,                         -- Full tool_call payload from the agent
    projected_cost  NUMERIC(18, 4),                         -- Extracted cost from intent analysis
    action_domain   TEXT,                                   -- Target domain extracted from tool_call
    risk_score      NUMERIC(5, 4) DEFAULT 0.0
        CHECK (risk_score >= 0 AND risk_score <= 1),
    status          TEXT NOT NULL
        CHECK (status IN ('APPROVED', 'DENIED', 'ERROR')),
    denial_reason   TEXT,                                   -- NULL when APPROVED
    transaction_id  UUID,                                   -- Populated after downstream settlement
    policy_snapshot JSONB,                                  -- Frozen copy of policy at decision time
    latency_ms      NUMERIC(10, 2),                         -- Round-trip decision latency
    intent_hash     TEXT,                                   -- SHA-256 of canonical intent (shield)
    receipt         JSONB,                                  -- Ed25519 signed receipt (shield)
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_audit_agent     ON audit_logs (agent_id);
CREATE INDEX idx_audit_status    ON audit_logs (status);
CREATE INDEX idx_audit_created   ON audit_logs (created_at);
CREATE INDEX idx_audit_agent_day ON audit_logs (agent_id, created_at)
    WHERE status = 'APPROVED';                              -- Fast daily-spend aggregation
CREATE INDEX IF NOT EXISTS idx_audit_intent_hash
    ON audit_logs (intent_hash) WHERE intent_hash IS NOT NULL;

-- Exactly-once audit dedup (migration 003). At-least-once delivery from the
-- Redis queue is collapsed via (intent_hash, agent_id, minute-bucket).
CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_logs_dedup
    ON audit_logs (intent_hash, agent_id, date_trunc('minute', created_at))
    WHERE intent_hash IS NOT NULL;

-- =============================================================================
-- TABLE: transactions
-- Settlement ledger tracking the state machine from the APEX paper:
-- CHALLENGED → INITIATED → SETTLED → CONSUMED
-- =============================================================================
CREATE TABLE IF NOT EXISTS transactions (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID NOT NULL REFERENCES agents (id),
    ref_id          TEXT NOT NULL UNIQUE,                    -- Challenge reference
    amount          NUMERIC(18, 4) NOT NULL CHECK (amount > 0),
    state           TEXT NOT NULL DEFAULT 'CHALLENGED'
        CHECK (state IN ('CHALLENGED', 'INITIATED', 'SETTLED', 'CONSUMED')),
    token           TEXT,                                    -- HMAC-signed payment token
    token_expiry    TIMESTAMPTZ,
    idempotency_key TEXT,
    consumed_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_txn_state    ON transactions (state);
CREATE INDEX idx_txn_agent    ON transactions (agent_id);
CREATE INDEX idx_txn_token    ON transactions (token) WHERE token IS NOT NULL;
CREATE INDEX idx_txn_idem_key ON transactions (idempotency_key) WHERE idempotency_key IS NOT NULL;

-- =============================================================================
-- FUNCTION: update_updated_at()
-- Auto-touch `updated_at` on row modification.
-- =============================================================================
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_agents_updated
    BEFORE UPDATE ON agents FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_policies_updated
    BEFORE UPDATE ON policies FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE TRIGGER trg_transactions_updated
    BEFORE UPDATE ON transactions FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- =============================================================================
-- VIEW: v_daily_agent_spend
-- Pre-computed daily spend per agent for fast policy checks.
-- =============================================================================
CREATE OR REPLACE VIEW v_daily_agent_spend AS
SELECT
    agent_id,
    DATE(created_at AT TIME ZONE 'UTC') AS spend_date,
    COALESCE(SUM(projected_cost), 0)    AS total_spent,
    COUNT(*)                            AS request_count
FROM audit_logs
WHERE status = 'APPROVED'
GROUP BY agent_id, DATE(created_at AT TIME ZONE 'UTC');

-- =============================================================================
-- ROLES & LEAST-PRIVILEGE GRANTS
-- Three scoped roles following Principle of Least Privilege:
--   1. apex_gateway  — reads agents, policies; reads/writes transactions
--   2. apex_auditor  — INSERT-only on audit_logs (no SELECT/UPDATE/DELETE)
--   3. apex_readonly — SELECT-only for observability dashboards
-- =============================================================================

-- Role: apex_gateway (API server)
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'apex_gateway') THEN
        CREATE ROLE apex_gateway LOGIN PASSWORD 'change_me_gateway';
    END IF;
END $$;

GRANT SELECT         ON agents, policies TO apex_gateway;
GRANT SELECT, UPDATE ON agents            TO apex_gateway;  -- balance updates
GRANT SELECT, INSERT, UPDATE ON transactions TO apex_gateway;
GRANT SELECT         ON v_daily_agent_spend TO apex_gateway;

-- Role: apex_auditor (audit log writer)
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'apex_auditor') THEN
        CREATE ROLE apex_auditor LOGIN PASSWORD 'change_me_auditor';
    END IF;
END $$;

GRANT INSERT ON audit_logs TO apex_auditor;
-- Intentionally NO select/update/delete on audit_logs for this role.

-- Role: apex_readonly (observability / dashboards)
DO $$ BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'apex_readonly') THEN
        CREATE ROLE apex_readonly LOGIN PASSWORD 'change_me_readonly';
    END IF;
END $$;

GRANT SELECT ON agents, policies, audit_logs, transactions, v_daily_agent_spend TO apex_readonly;

-- Sequence grants for INSERT operations
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO apex_gateway;
GRANT USAGE ON ALL SEQUENCES IN SCHEMA public TO apex_auditor;
