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
                await session.execute(
                    text("""
                        INSERT INTO audit_logs (
                            id, agent_id, raw_intent, projected_cost,
                            action_domain, risk_score, status,
                            denial_reason, transaction_id,
                            policy_snapshot, latency_ms, created_at
                        ) VALUES (
                            :id, :agent_id, :raw_intent::jsonb, :projected_cost,
                            :action_domain, :risk_score, :status,
                            :denial_reason, :transaction_id,
                            :policy_snapshot::jsonb, :latency_ms, :created_at
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
                        "created_at": record.get(
                            "created_at", datetime.now(timezone.utc).isoformat()
                        ),
                    },
                )
                await session.commit()

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
