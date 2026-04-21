-- =============================================================================
-- Migration 003: Audit log deduplication
-- =============================================================================
-- Blueprint §7.5 requires exactly-once INSERT semantics for the audit worker.
-- At-least-once delivery from the Redis queue is tolerable (workers can crash
-- after INSERT but before BLPOP commit), but a second INSERT of the same
-- logical record would pollute dashboards and billing analytics.
--
-- Dedup key = (intent_hash, agent_id, created_at truncated to the minute).
-- Per-minute bucketing lets legitimate retries inside a minute collapse into
-- one row while still permitting the same intent to legitimately recur in a
-- later minute (e.g. cron tasks).
--
-- Rows without an intent_hash (shield-disabled / legacy) are exempt: the
-- partial index ignores them so nothing regresses for non-shield callers.
--
-- Idempotent: CREATE UNIQUE INDEX ... IF NOT EXISTS. Safe to re-run.
-- =============================================================================

CREATE UNIQUE INDEX IF NOT EXISTS uq_audit_logs_dedup
    ON audit_logs (
        intent_hash,
        agent_id,
        date_trunc('minute', created_at)
    )
    WHERE intent_hash IS NOT NULL;

-- =============================================================================
-- Verification:
--   -- Should be UNIQUE, partial (intent_hash IS NOT NULL):
--   SELECT indexdef FROM pg_indexes
--    WHERE tablename = 'audit_logs' AND indexname = 'uq_audit_logs_dedup';
--
--   -- Legitimate behaviour check: inserting the same (intent_hash, agent_id)
--   -- twice inside the same minute should fail with unique_violation; the
--   -- audit worker should catch SQLSTATE 23505 and treat it as success.
-- =============================================================================
