-- =============================================================================
-- Migration 002: Live-stream audit_logs via LISTEN / NOTIFY
-- =============================================================================
-- Fires a tiny `pg_notify('audit_feed', <id>::text)` on every INSERT into
-- audit_logs. The SSE endpoint in apex_pay/routers/dashboard.py opens a
-- dedicated asyncpg connection, LISTEN-s on 'audit_feed', and — on each
-- notification — hydrates the full row via SELECT through the readonly
-- role. Payload is kept to the row id only so we stay well under the 8 KB
-- NOTIFY cap even as raw_intent / policy_snapshot grow.
--
-- Idempotent: OR REPLACE on the function, DROP IF EXISTS on the trigger.
-- Safe to re-run.
-- =============================================================================

CREATE OR REPLACE FUNCTION notify_audit_insert()
RETURNS TRIGGER AS $$
BEGIN
    -- Emit id only. The listener is responsible for SELECT-ing the row.
    -- pg_notify() is available to any role; no extra GRANT required.
    PERFORM pg_notify('audit_feed', NEW.id::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_audit_notify ON audit_logs;
CREATE TRIGGER trg_audit_notify
    AFTER INSERT ON audit_logs
    FOR EACH ROW EXECUTE FUNCTION notify_audit_insert();

-- =============================================================================
-- Verification:
--   SELECT tgname FROM pg_trigger WHERE tgrelid = 'audit_logs'::regclass;
--   -- Expect: trg_audit_no_update, trg_audit_notify
--
--   -- In psql session A:
--   LISTEN audit_feed;
--   -- In psql session B:
--   INSERT INTO audit_logs (id, agent_id, raw_intent, status)
--       VALUES (gen_random_uuid(), '<agent-id>', '{}'::jsonb, 'APPROVED');
--   -- Session A should print an `Asynchronous notification "audit_feed"…`
-- =============================================================================
