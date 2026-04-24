"""
Audit Log Worker
=================
Background task that drains the Redis audit queue and persists records
into `audit_logs` via the INSERT-only `apex_auditor` database connection.

Run standalone:
    python -m apex_pay.workers.audit_worker

Or as an asyncio background task inside the FastAPI lifespan.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from apex_pay.core.config import settings
from apex_pay.core.database import AuditorSession
from apex_pay.services.audit_queue import AuditQueue

logger = logging.getLogger("apex_pay.audit_worker")


async def drain_audit_queue(queue: AuditQueue, *, batch_size: int = 50) -> None:
    """Continuously drain the queue and INSERT into audit_logs.

    Uses the AuditorSession (INSERT-only role) to enforce Least Privilege.
    """
    logger.info("Audit worker started — draining queue '%s'", settings.redis.audit_queue_name)

    while True:
        try:
            record = await queue.pop(timeout=5)
            if record is None:
                continue  # timeout, loop back

            async with AuditorSession() as session:
                # NOTE: `:param::jsonb` looks natural but SQLAlchemy's text()
                # bindparam regex uses a `(?!:)` negative lookahead, so a
                # colon immediately after the bind name kills the match and
                # the literal `:raw_intent` is sent to asyncpg. Use CAST()
                # instead — functionally identical, parser-safe.
                try:
                    await session.execute(
                        text("""
                            INSERT INTO audit_logs (
                                id, agent_id, raw_intent, projected_cost,
                                action_domain, risk_score, status,
                                denial_reason, transaction_id,
                                policy_snapshot, latency_ms, created_at,
                                intent_hash, financial_action_hash, receipt
                            ) VALUES (
                                :id, :agent_id, CAST(:raw_intent AS jsonb), :projected_cost,
                                :action_domain, :risk_score, :status,
                                :denial_reason, :transaction_id,
                                CAST(:policy_snapshot AS jsonb), :latency_ms, :created_at,
                                :intent_hash, :financial_action_hash, CAST(:receipt AS jsonb)
                            )
                        """),
                        {
                            "id": record.get("id", str(uuid.uuid4())),
                            "agent_id": record["agent_id"],
                            "raw_intent": _to_json_str(record["raw_intent"]),
                            "projected_cost": record.get("projected_cost"),
                            "action_domain": record.get("action_domain"),
                            "risk_score": record.get("risk_score", 0.0),
                            "status": record["status"],
                            "denial_reason": record.get("denial_reason"),
                            "transaction_id": record.get("transaction_id"),
                            "policy_snapshot": _to_json_str(record.get("policy_snapshot")),
                            "latency_ms": record.get("latency_ms"),
                            # Redis payloads are JSON so created_at arrives as an
                            # ISO-8601 string. asyncpg's timestamptz encoder wants
                            # a real datetime; coerce before bind.
                            "created_at": _parse_timestamp(record.get("created_at")),
                            "intent_hash": record.get("intent_hash"),
                            "financial_action_hash": record.get("financial_action_hash"),
                            "receipt": _to_json_str(record.get("receipt")),
                        },
                    )
                    await session.commit()
                except IntegrityError as exc:
                    # Dedup index (migration 003) collapsed a retry of the
                    # same (intent_hash, agent_id, minute) onto an existing
                    # row. At-least-once delivery means this is expected; ack
                    # the redis pop and move on.
                    await session.rollback()
                    if _is_unique_violation(exc):
                        logger.debug(
                            "Audit record dedup hit for id=%s intent_hash=%s",
                            record.get("id"),
                            record.get("intent_hash"),
                        )
                    else:
                        raise

            logger.debug("Persisted audit record %s", record.get("id"))

        except asyncio.CancelledError:
            logger.info("Audit worker shutting down.")
            break
        except Exception:
            logger.exception("Error persisting audit record — will retry.")
            await asyncio.sleep(1)


def _to_json_str(obj) -> str | None:
    """Convert dicts to JSON strings for PostgreSQL JSONB casting."""
    if obj is None:
        return None
    import json
    return json.dumps(obj) if isinstance(obj, (dict, list)) else str(obj)


def _is_unique_violation(exc: IntegrityError) -> bool:
    """Return True if the IntegrityError is a Postgres 23505 (unique_violation)."""
    orig = getattr(exc, "orig", None)
    # asyncpg wraps the SQLSTATE on the original exception.
    sqlstate = getattr(orig, "sqlstate", None) or getattr(orig, "pgcode", None)
    return sqlstate == "23505"


def _parse_timestamp(value) -> datetime:
    """Coerce a created_at payload value into a tz-aware datetime.

    The queue serializes to JSON, so datetimes round-trip as ISO strings.
    asyncpg's timestamptz encoder refuses strings, so we parse back here.
    Unknown / missing values fall back to now() — better a slightly-wrong
    timestamp than a lost audit row.
    """
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            # fromisoformat in 3.11+ handles trailing "Z" and offsets cleanly.
            parsed = datetime.fromisoformat(value)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


async def main() -> None:
    """Entry point for running the worker standalone."""
    queue = AuditQueue()
    await queue.connect()
    try:
        await drain_audit_queue(queue)
    finally:
        await queue.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(main())
