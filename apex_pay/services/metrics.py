"""Prometheus metrics for the APEX-Pay backend.

Blueprint §13.1 enumerates the metric set that the gateway must expose.
All series live in a single default registry so `/metrics` can be scraped
by any Prometheus-compatible collector (Prometheus itself, OTel collector
with the prometheus receiver, Datadog, Grafana Agent, etc).

Why a dedicated module:

* Metric objects must be singletons — creating a Counter twice under the
  same name raises ValueError. A module that is imported once solves it.
* If prometheus_client is not installed (lean test envs, dev without the
  ops dependency pulled), every call in this module is a no-op. That way
  the hot path never grows a branch for "metrics enabled yes/no".

Usage:

    from apex_pay.services import metrics as m
    m.DECISIONS.labels(status="APPROVED", tier="default").inc()
    with m.DECISION_LATENCY.labels(stage="risk").time():
        ...
"""

from __future__ import annotations

from typing import Any


class _Noop:
    """Stand-in for Counter/Gauge/Histogram when prometheus_client is missing.

    Every method returns self so chained calls like `labels(...).inc()` and
    context-manager usage (`with .time(): ...`) stay safe.
    """

    def labels(self, *_args: Any, **_kwargs: Any) -> "_Noop":
        return self

    def inc(self, _amount: float = 1.0) -> None:
        pass

    def dec(self, _amount: float = 1.0) -> None:
        pass

    def set(self, _value: float) -> None:
        pass

    def observe(self, _value: float) -> None:
        pass

    def time(self) -> "_Noop":
        return self

    def __enter__(self) -> "_Noop":
        return self

    def __exit__(self, *_exc: Any) -> None:
        return None


try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        REGISTRY,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    _PROM_AVAILABLE = True
except ImportError:  # pragma: no cover — metrics are optional
    CONTENT_TYPE_LATEST = "text/plain; version=0.0.4; charset=utf-8"
    REGISTRY = None  # type: ignore[assignment]

    def generate_latest(_registry: Any = None) -> bytes:  # type: ignore[misc]
        return b"# prometheus_client not installed\n"

    def _make(_kind: str, *_args: Any, **_kwargs: Any) -> _Noop:
        return _Noop()

    Counter = Gauge = Histogram = _make  # type: ignore[assignment,misc]
    _PROM_AVAILABLE = False


# ── Decision path ───────────────────────────────────────────────────────────
DECISIONS = Counter(
    "apex_decision_total",
    "Count of gateway decisions by outcome.",
    ("status",),  # APPROVED | DENIED | ESCALATED | ERROR
)

DECISION_LATENCY = Histogram(
    "apex_decision_latency_seconds",
    "End-to-end decision latency on /execute.",
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.2, 0.35, 0.5, 1.0, 2.5, 5.0),
)

STAGE_LATENCY = Histogram(
    "apex_decision_stage_latency_seconds",
    "Latency by shield stage.",
    ("stage",),  # risk | opa | credential | receipt | audit_push
    buckets=(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0),
)

# ── Risk / OPA health ───────────────────────────────────────────────────────
RISK_SCORE = Histogram(
    "apex_risk_score",
    "Distribution of risk scores emitted by the classifier.",
    buckets=(0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0),
)

OPA_FALLBACK = Counter(
    "apex_opa_fallback_total",
    "Count of OPA calls that fell back to the embedded evaluator.",
)

# ── Queue / async health ────────────────────────────────────────────────────
AUDIT_QUEUE_DEPTH = Gauge(
    "apex_audit_queue_depth",
    "Current audit queue depth in Redis.",
)

AUDIT_BACKPRESSURE = Counter(
    "apex_audit_backpressure_total",
    "Requests rejected with 503 because the audit queue was saturated.",
)

# ── HITL ────────────────────────────────────────────────────────────────────
HITL_PENDING = Gauge(
    "apex_hitl_pending",
    "Current count of HITL requests awaiting human review.",
)

# ── Auth / replay ───────────────────────────────────────────────────────────
REPLAY_REJECTIONS = Counter(
    "apex_replay_rejections_total",
    "Requests rejected because nonce was reused or timestamp was out of window.",
    ("reason",),  # nonce_reused | timestamp_out_of_window | missing_nonce
)

SIGNATURE_REJECTIONS = Counter(
    "apex_signature_rejections_total",
    "Requests rejected because Ed25519 body signature verification failed.",
    ("reason",),  # missing | malformed | invalid | unknown_agent
)

# ── Semantic (dollar) rate limiter ──────────────────────────────────────────
SEMANTIC_RATE_LIMIT_REJECTIONS = Counter(
    "apex_semantic_rate_limit_rejections_total",
    "Requests rejected because they would exceed the per-agent hourly dollar cap.",
)

SEMANTIC_RATE_LIMIT_SPEND_CENTS = Histogram(
    "apex_semantic_rate_limit_spend_cents",
    "Rolling-window spend (in cents) observed at each check.",
    buckets=(100, 500, 1000, 2500, 5000, 7500, 10000, 15000, 25000, 50000),
)


def render_latest() -> tuple[bytes, str]:
    """Return (payload, content_type) for the /metrics endpoint."""
    if _PROM_AVAILABLE:
        return generate_latest(REGISTRY), CONTENT_TYPE_LATEST
    return generate_latest(), CONTENT_TYPE_LATEST
