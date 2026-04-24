-- =============================================================================
-- Migration 005: audit_logs.financial_action_hash
-- =============================================================================
-- Second content-address on the audit row. `intent_hash` (migration 001) is
-- the SHA-256 of the canonical shield intent — covers the FULL tool_call
-- including non-monetary fields. `financial_action_hash` is the SHA-256 of
-- the canonical FinancialAction envelope (see apex_pay/shield/financial_action.py).
--
-- Why two hashes?
--   • intent_hash is stable across ALL intents; useful for non-repudiation
--     on the agent's exact submitted call.
--   • financial_action_hash is stable only for monetary intents, and its
--     canonical form omits non-monetary fields. Finance/compliance teams
--     can join by financial_action_hash to reconcile two audit rows that
--     describe the same logical money move under different shell shapes
--     (idempotent retries across transport changes, etc.).
--
-- Nullable: non-monetary intents leave this column NULL.
-- Indexed: partial on `financial_action_hash IS NOT NULL` so the index is
-- small and queries against it are fast.
--
-- Idempotent. Safe to re-run.
-- =============================================================================

ALTER TABLE audit_logs
    ADD COLUMN IF NOT EXISTS financial_action_hash TEXT;

CREATE INDEX IF NOT EXISTS idx_audit_financial_action_hash
    ON audit_logs (financial_action_hash)
    WHERE financial_action_hash IS NOT NULL;

-- Sanity check (run manually):
--   SELECT count(*) FROM audit_logs WHERE financial_action_hash IS NOT NULL;
