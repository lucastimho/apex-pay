"""
Audit Feed Broker — single LISTEN connection, many SSE subscribers.
====================================================================

Opens ONE dedicated asyncpg connection at application startup, LISTEN-s on
`audit_feed` (fired by the trigger in migrations/002_audit_notify.sql), and
fans each notification out to per-subscriber `asyncio.Queue`s. Each SSE
client gets a queue instead of its own database connection.

Why a broker and not a per-client connection?

    Supabase's pooler (Supavisor) will trip its own circuit breaker if a
    burst of new Postgres connections hits it while its credential backend
    is stressed — we saw `Circuit breaker open: Failed to retrieve
    database credentials` under that load. Holding one long-lived
    connection for the life of the process sidesteps the connection-storm
    failure mode entirely, and also respects the per-project connection
    cap on managed Postgres.

The broker owns a supervisor task that reconnects with exponential backoff
on any failure. Subscribers are insulated from reconnects — their queues
just stop receiving during the outage, and the 15-second heartbeat in the
SSE endpoint keeps their TCP connection healthy so they don't see a blip.

A single broker per process is enough. If we ever move to multi-worker
uvicorn, each worker has its own broker (and its own LISTEN connection);
all workers still receive every NOTIFY because pg_notify broadcasts to
every connection that's LISTEN-ing on the channel.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

import asyncpg

logger = logging.getLogger("apex_pay.audit_feed_broker")


class AuditFeedBroker:
    """Single-connection LISTEN with fanout to many asyncio.Queue subscribers."""

    # Per-subscriber queue size. If a slow client can't drain fast enough we
    # drop rather than stalling the broker (see _on_notify).
    SUBSCRIBER_QUEUE_SIZE: int = 1000

    # Reconnect backoff — doubles each failure, capped.
    _BACKOFF_INITIAL_SECONDS: float = 1.0
    _BACKOFF_MAX_SECONDS: float = 60.0

    # Liveness probe on the LISTEN connection. Supavisor will idle-close
    # connections silently; a periodic SELECT 1 catches that within the
    # interval and triggers a reconnect.
    _LIVENESS_INTERVAL_SECONDS: float = 30.0

    def __init__(self, dsn: str, *, channel: str = "audit_feed") -> None:
        self._dsn = dsn
        self._channel = channel
        self._conn: Optional[asyncpg.Connection] = None
        self._subscribers: set[asyncio.Queue[str]] = set()
        self._supervisor_task: Optional[asyncio.Task[None]] = None
        # Set by _supervise when the LISTEN connection is healthy and ready
        # to deliver notifications. Cleared on disconnect. Subscribers can
        # peek at it to surface liveness in the UI, but they don't have to.
        self._connected = asyncio.Event()

    # ── Lifecycle ─────────────────────────────────────────────────────────
    async def start(self) -> None:
        """Launch the supervisor task. Non-blocking — returns immediately.

        Callers should NOT await connection establishment before accepting
        traffic; a client that subscribes before the broker is connected
        simply waits in its queue, which is exactly what we want.
        """
        if self._supervisor_task is not None:
            return
        self._supervisor_task = asyncio.create_task(
            self._supervise(), name="audit_feed_broker_supervisor",
        )
        logger.info("Audit feed broker starting (channel=%s)", self._channel)

    async def stop(self) -> None:
        """Cancel the supervisor and close the underlying connection."""
        if self._supervisor_task is not None:
            self._supervisor_task.cancel()
            try:
                await self._supervisor_task
            except asyncio.CancelledError:
                pass
            self._supervisor_task = None
        await self._close_conn()
        # Release any still-blocked subscribers so their SSE generators
        # can unwind cleanly.
        for q in list(self._subscribers):
            try:
                q.put_nowait("")  # empty payload = sentinel; handler skips it
            except asyncio.QueueFull:
                pass
        logger.info("Audit feed broker stopped")

    # ── Subscription API ─────────────────────────────────────────────────
    def subscribe(self) -> asyncio.Queue[str]:
        """Register a new subscriber. Returns a queue that will receive
        notification payloads (audit_log row ids as strings).
        """
        q: asyncio.Queue[str] = asyncio.Queue(maxsize=self.SUBSCRIBER_QUEUE_SIZE)
        self._subscribers.add(q)
        logger.debug("Subscriber added (total=%d)", len(self._subscribers))
        return q

    def unsubscribe(self, q: asyncio.Queue[str]) -> None:
        self._subscribers.discard(q)
        logger.debug("Subscriber removed (total=%d)", len(self._subscribers))

    @property
    def is_connected(self) -> bool:
        return self._connected.is_set()

    # ── Internal ─────────────────────────────────────────────────────────
    def _on_notify(
        self,
        _connection: asyncpg.Connection,
        _pid: int,
        _channel: str,
        payload: str,
    ) -> None:
        """asyncpg callback — runs inline on the LISTEN connection's event
        loop. Fan out to every subscriber without awaiting (put_nowait),
        so a slow subscriber can't stall notification delivery.
        """
        for q in self._subscribers:
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                logger.warning(
                    "Subscriber queue full (%d); dropping notification %s",
                    self.SUBSCRIBER_QUEUE_SIZE, payload,
                )

    async def _supervise(self) -> None:
        """Open the LISTEN connection; reconnect with backoff on failure."""
        backoff = self._BACKOFF_INITIAL_SECONDS
        while True:
            try:
                self._conn = await asyncpg.connect(self._dsn)
                await self._conn.add_listener(self._channel, self._on_notify)
                self._connected.set()
                logger.info(
                    "Audit feed broker connected; LISTEN %s", self._channel,
                )
                backoff = self._BACKOFF_INITIAL_SECONDS

                # Liveness loop — asyncpg's add_listener doesn't notify us
                # when the TCP connection dies silently (Supavisor is known
                # to idle-close). A cheap SELECT 1 catches it within the
                # interval and we drop out of the inner loop to reconnect.
                while True:
                    await asyncio.sleep(self._LIVENESS_INTERVAL_SECONDS)
                    await self._conn.fetchval("SELECT 1")

            except asyncio.CancelledError:
                break
            except Exception as exc:  # noqa: BLE001 — reconnect on anything
                self._connected.clear()
                await self._close_conn()
                logger.warning(
                    "Audit feed broker connection lost (%s); retry in %.1fs",
                    exc, backoff,
                )
                try:
                    await asyncio.sleep(backoff)
                except asyncio.CancelledError:
                    break
                backoff = min(backoff * 2, self._BACKOFF_MAX_SECONDS)

    async def _close_conn(self) -> None:
        conn, self._conn = self._conn, None
        if conn is None:
            return
        try:
            await conn.remove_listener(self._channel, self._on_notify)
        except Exception:  # noqa: BLE001
            pass
        try:
            await conn.close()
        except Exception:  # noqa: BLE001
            pass
