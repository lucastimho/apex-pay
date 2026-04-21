-- =============================================================================
-- Migration 004: audit_logs monthly partitioning (OPT-IN, scale-only)
-- =============================================================================
-- Blueprint §6.1 / §11.2: at v3 scale (~28 GB/day of audit records), the
-- hot partition should fit in RAM and cold partitions should compress to
-- columnar. This migration is OPTIONAL — run it only when you are ready
-- to schedule a cutover window. The existing `audit_logs` table keeps
-- working in the meantime.
--
-- THIS SCRIPT DOES NOT MOVE DATA. It:
--   1. Creates `audit_logs_partitioned` — the same schema, partitioned
--      by RANGE on `created_at`. No data, no constraints-on-parent quirks.
--   2. Creates a helper function `apex_create_audit_partition(year, month)`
--      so cron can provision next month's partition ahead of the roll-over.
--   3. Pre-creates the current month + next month partitions.
--   4. Does NOT swap tables. Cutover is a separate, deliberate step —
--      see the block at the bottom for the procedure.
--
-- Idempotent: every CREATE is IF NOT EXISTS, the function is OR REPLACE.
-- Safe to re-run.
-- =============================================================================

-- ── 1. Partitioned sibling of audit_logs ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS audit_logs_partitioned (
    id              UUID NOT NULL DEFAULT uuid_generate_v4(),
    agent_id        UUID NOT NULL,
    raw_intent      JSONB NOT NULL,
    projected_cost  NUMERIC(18, 4),
    action_domain   TEXT,
    risk_score      NUMERIC(5, 4) DEFAULT 0.0
        CHECK (risk_score >= 0 AND risk_score <= 1),
    status          TEXT NOT NULL
        CHECK (status IN ('APPROVED', 'DENIED', 'ERROR')),
    denial_reason   TEXT,
    transaction_id  UUID,
    policy_snapshot JSONB,
    latency_ms      NUMERIC(10, 2),
    intent_hash     TEXT,
    receipt         JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (id, created_at)          -- PK must include the partition key
) PARTITION BY RANGE (created_at);

-- Shared indexes on the parent propagate to new partitions automatically
-- in Postgres 11+.
CREATE INDEX IF NOT EXISTS idx_auditp_agent     ON audit_logs_partitioned (agent_id);
CREATE INDEX IF NOT EXISTS idx_auditp_status    ON audit_logs_partitioned (status);
CREATE INDEX IF NOT EXISTS idx_auditp_created   ON audit_logs_partitioned (created_at);
CREATE INDEX IF NOT EXISTS idx_auditp_intent    ON audit_logs_partitioned (intent_hash)
    WHERE intent_hash IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_auditp_dedup
    ON audit_logs_partitioned (
        intent_hash, agent_id, date_trunc('minute', created_at), created_at
    )
    WHERE intent_hash IS NOT NULL;

-- ── 2. Monthly partition helper ──────────────────────────────────────────────
-- Usage (e.g. from a pg_cron job): SELECT apex_create_audit_partition(2026, 5);
CREATE OR REPLACE FUNCTION apex_create_audit_partition(p_year INT, p_month INT)
RETURNS TEXT AS $$
DECLARE
    part_name TEXT;
    range_start DATE;
    range_end DATE;
    ddl TEXT;
BEGIN
    range_start := make_date(p_year, p_month, 1);
    range_end   := (range_start + INTERVAL '1 month')::DATE;
    part_name   := format('audit_logs_p_%s%s',
                          p_year,
                          lpad(p_month::TEXT, 2, '0'));

    ddl := format(
        'CREATE TABLE IF NOT EXISTS %I PARTITION OF audit_logs_partitioned '
        'FOR VALUES FROM (%L) TO (%L);',
        part_name, range_start, range_end
    );
    EXECUTE ddl;

    -- Propagate append-only trigger to each partition so the write-once
    -- property survives the partitioning cutover.
    EXECUTE format(
        'DROP TRIGGER IF EXISTS trg_audit_no_update_%s ON %I;',
        part_name, part_name
    );
    EXECUTE format(
        'CREATE TRIGGER trg_audit_no_update_%s '
        'BEFORE UPDATE OR DELETE ON %I '
        'FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();',
        part_name, part_name
    );

    RETURN part_name;
END;
$$ LANGUAGE plpgsql;

-- ── 3. Pre-create the current + next month so writes never miss ─────────────
-- Works on fresh installs and on re-runs (function is idempotent).
DO $$
DECLARE
    now_date DATE := (now() AT TIME ZONE 'UTC')::DATE;
    next_month DATE := (now_date + INTERVAL '1 month')::DATE;
BEGIN
    PERFORM apex_create_audit_partition(
        EXTRACT(YEAR FROM now_date)::INT,
        EXTRACT(MONTH FROM now_date)::INT
    );
    PERFORM apex_create_audit_partition(
        EXTRACT(YEAR FROM next_month)::INT,
        EXTRACT(MONTH FROM next_month)::INT
    );
END $$;

-- ── 4. Grants mirror the unpartitioned table ─────────────────────────────────
GRANT INSERT ON audit_logs_partitioned TO apex_auditor;
GRANT SELECT ON audit_logs_partitioned TO apex_readonly;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs_partitioned FROM PUBLIC;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs_partitioned FROM apex_auditor;
REVOKE UPDATE, DELETE, TRUNCATE ON audit_logs_partitioned FROM apex_gateway;

-- =============================================================================
-- Cutover procedure (MANUAL — run only during a scheduled maintenance window)
-- =============================================================================
--
-- 1. Stop the audit worker (or let the Redis queue back-pressure).
-- 2. Copy existing rows:
--      INSERT INTO audit_logs_partitioned
--      SELECT id, agent_id, raw_intent, projected_cost, action_domain,
--             risk_score, status, denial_reason, transaction_id,
--             policy_snapshot, latency_ms, intent_hash, receipt, created_at
--      FROM audit_logs;
-- 3. Swap names (single short transaction — locks both tables briefly):
--      BEGIN;
--      ALTER TABLE audit_logs RENAME TO audit_logs_legacy;
--      ALTER TABLE audit_logs_partitioned RENAME TO audit_logs;
--      -- Recreate the notify trigger on the new table if needed:
--      CREATE TRIGGER trg_audit_notify
--          AFTER INSERT ON audit_logs
--          FOR EACH ROW EXECUTE FUNCTION notify_audit_insert();
--      COMMIT;
-- 4. Restart the audit worker. Monitor `apex_audit_queue_depth`.
-- 5. Keep `audit_logs_legacy` for at least 30 days as a safety net, then
--    VACUUM FULL + DROP.
-- =============================================================================

-- =============================================================================
-- Recommended pg_cron schedule after cutover (run in the "cron" or "postgres"
-- database, targeting the APEX database):
--
--   SELECT cron.schedule(
--       'apex-audit-next-partition',
--       '0 0 25 * *',  -- 25th of each month at 00:00 UTC
--       $$ SELECT apex_create_audit_partition(
--            EXTRACT(YEAR  FROM (now() + interval '1 month'))::INT,
--            EXTRACT(MONTH FROM (now() + interval '1 month'))::INT
--          ); $$
--   );
-- =============================================================================
