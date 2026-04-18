-- =============================================================================
-- Migration 001: APEX-Shield hardening
-- =============================================================================
-- Additive to schema.sql. Safe to run multiple times (IF NOT EXISTS / IF EXISTS).
--
--  1. Adds two columns to audit_logs for the shield:
--       - intent_hash        SHA-256 of canonical tool_call (non-repudiation anchor)
--       - receipt            JSONB of the Ed25519 signed receipt
--     Neither column is required (shield can be disabled); existing workers
--     continue to write the original fields.
--
--  2. Adds `shield_hitl_requests` — a durable store for escalated intents
--     so HITL state survives gateway restarts when we move past the
--     in-memory dev store in apex_pay/shield/hitl_store.py.
--
--  3. Adds explicit REVOKE statements on audit_logs for the auditor role
--     to make the "INSERT only" posture visible in grep, and adds a
--     write-once trigger that rejects UPDATE/DELETE on audit_logs.
--
--  4. Grants the new HITL table to apex_gateway with the minimum set.
-- =============================================================================

-- ── (1) audit_logs additions ──────────────────────────────────────────────
ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS intent_hash TEXT,
    ADD COLUMN IF NOT EXISTS receipt     JSONB;

CREATE INDEX IF NOT EXISTS idx_audit_intent_hash
    ON audit_logs (intent_hash)
    WHERE intent_hash IS NOT NULL;

-- ── (2) shield_hitl_requests ──────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS shield_hitl_requests (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id        UUID NOT NULL REFERENCES agents (id) ON DELETE CASCADE,
    intent_hash     TEXT NOT NULL,
    reason          TEXT NOT NULL,
    violations      JSONB NOT NULL DEFAULT '[]'::JSONB,
    opa_input       JSONB NOT NULL,
    risk_score      NUMERIC(5, 4) NOT NULL DEFAULT 0
        CHECK (risk_score >= 0 AND risk_score <= 1),
    risk_entropy    NUMERIC(5, 4) NOT NULL DEFAULT 0
        CHECK (risk_entropy >= 0 AND risk_entropy <= 1),
    resolution      TEXT CHECK (resolution IN ('approved', 'denied')),
    resolver        TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_hitl_agent    ON shield_hitl_requests (agent_id);
CREATE INDEX IF NOT EXISTS idx_hitl_pending  ON shield_hitl_requests (created_at)
    WHERE resolution IS NULL;

-- ── (3) Write-once enforcement on audit_logs ──────────────────────────────
-- Even though the apex_auditor role only has INSERT, defense-in-depth: add
-- a trigger so if any role ever does get UPDATE/DELETE by accident it still
-- cannot mutate an existing audit record.
CREATE OR REPLACE FUNCTION reject_audit_mutation()
RETURNS TRIGGER AS $$
BEGIN
    RAISE EXCEPTION 'audit_logs is append-only (tried % on id=%)', TG_OP, OLD.id;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_no_update ON audit_logs;
CREATE TRIGGER trg_audit_no_update
    BEFORE UPDATE OR DELETE ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();

-- Explicit revokes to make the posture visible in grep.
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM apex_auditor;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs FROM apex_gateway;
-- apex_auditor stays INSERT-only.
GRANT INSERT ON audit_logs TO apex_auditor;

-- ── (4) HITL grants: gateway can INSERT/SELECT/UPDATE resolution ──────────
GRANT SELECT, INSERT, UPDATE ON shield_hitl_requests TO apex_gateway;
GRANT SELECT                   ON shield_hitl_requests TO apex_readonly;

-- =============================================================================
-- Verification queries (run manually after migration)
-- =============================================================================
-- SELECT has_table_privilege('apex_auditor', 'audit_logs', 'UPDATE');  -- false
-- SELECT has_table_privilege('apex_auditor', 'audit_logs', 'INSERT');  -- true
-- SELECT has_table_privilege('apex_auditor', 'audit_logs', 'SELECT');  -- false
-- SELECT has_table_privilege('apex_readonly', 'shield_hitl_requests', 'SELECT'); -- true
-- SELECT has_table_privilege('apex_readonly', 'shield_hitl_requests', 'INSERT'); -- false
