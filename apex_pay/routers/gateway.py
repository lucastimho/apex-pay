"""
Gateway Router — Primary APEX-Pay Endpoints
=============================================
Implements the policy-gated execution flow from the APEX paper:

    1. POST /execute   — Intercept tool_call → policy check → approve/deny
    2. GET  /data      — Protected data endpoint (returns 402 challenge or data)
    3. POST /pay       — Settlement endpoint (issues HMAC token)
    4. POST /reset     — Reset ledger for reproducible experiments
    5. GET  /health    — Liveness probe

Rate-limited via SlowAPI to prevent DDoS and agent-looping (blueprint §Step 1).
"""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timezone

import logfire
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from sqlalchemy import select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from apex_pay.core.config import settings
from apex_pay.core.database import GatewaySession
from apex_pay.core.models import Agent, Policy, Transaction
from apex_pay.core.schemas import (
    ChallengeResponse,
    GatewayResponse,
    HealthResponse,
    PolicyDecision,
    SettlementRequest,
    SettlementResponse,
    ToolCallPayload,
)
from apex_pay.services import metrics as m
from apex_pay.services.audit_queue import AuditQueue
from apex_pay.services.body_signature import verify_body
from apex_pay.services.correlation import current_correlation_id
from apex_pay.services.policy_engine import PolicyEngine
from apex_pay.services.replay_guard import default_guard as default_replay_guard
from apex_pay.services.token_service import TokenService
from apex_pay.shield.factory import build_shield_pipeline
from apex_pay.shield.hitl_store import default_store as default_hitl_store
from apex_pay.shield.intent import canonicalize_intent
from apex_pay.shield.pipeline import PolicySnapshot, ShieldDecision

router = APIRouter()
policy_engine = PolicyEngine()
token_service = TokenService()
shield_pipeline = build_shield_pipeline() if settings.shield.enabled else None

_start_time = time.time()


# ── Dependency: DB session ──────────────────────────────────────────────────
async def get_session() -> AsyncSession:
    async with GatewaySession() as session:
        yield session


# ── Dependency: Audit queue (from app state) ────────────────────────────────
def get_audit_queue(request: Request) -> AuditQueue:
    return request.app.state.audit_queue


# =============================================================================
# POST /execute — Primary Policy-Gated Endpoint
# =============================================================================
@router.post(
    "/execute",
    response_model=GatewayResponse,
    summary="Intercept an agent tool-call and validate against policy",
    tags=["gateway"],
)
async def execute_tool_call(
    request: Request,
    payload: ToolCallPayload,
    session: AsyncSession = Depends(get_session),
    audit_queue: AuditQueue = Depends(get_audit_queue),
) -> GatewayResponse:
    """The main APEX-Pay gateway endpoint.

    Intercepts the agent's tool_call JSON payload, runs it through the
    Policy Enforcement Engine, and returns an APPROVED or DENIED decision.
    """
    request_id = uuid.uuid4()
    start = time.perf_counter()

    # ── Back-pressure check (blueprint §Step 2) ────────────────────────
    if await audit_queue.is_saturated():
        m.AUDIT_BACKPRESSURE.inc()
        raise HTTPException(
            status_code=503,
            detail="Audit queue saturated — retry later.",
        )

    # ── Body-signature verification (config-gated; off by default) ─────
    # Blueprint §5.1: agents sign the raw request body with Ed25519. The
    # public key lives on `agents.public_key` as raw-b64 (same as JWKS).
    # We have to read the raw body here (not the parsed Pydantic payload)
    # because the signature is over the bytes exactly as sent. FastAPI has
    # already cached the body by this point, so `await request.body()` is
    # cheap and does not break downstream body parsing.
    if settings.security.require_body_signature:
        raw_body = await request.body()
        # The agent's public key is needed; load through the gateway session.
        pk_result = await session.execute(
            select(Agent.public_key).where(Agent.id == payload.agent_id)
        )
        public_key_encoded = pk_result.scalar_one_or_none()
        sig_result = verify_body(
            public_key_encoded=public_key_encoded,
            body=raw_body,
            signature_header=request.headers.get("x-apex-signature"),
        )
        if sig_result.verdict != "ok":
            m.SIGNATURE_REJECTIONS.labels(reason=sig_result.verdict).inc()
            raise HTTPException(
                status_code=401,
                detail={"reason": sig_result.reason, "code": sig_result.verdict},
            )

    # ── Replay protection (config-gated; off by default) ───────────────
    # Blueprint §5.1 & §12: when enabled, every request must carry a fresh
    # nonce and an issued_at within the server's clock window. Both are
    # checked even if body-signature verification is disabled, so replay
    # of a *legitimate* signed request is still caught.
    if settings.security.require_nonce:
        if not payload.nonce or payload.issued_at is None:
            m.REPLAY_REJECTIONS.labels(reason="missing_nonce").inc()
            raise HTTPException(
                status_code=400,
                detail="Request must include nonce and issued_at when replay protection is enabled.",
            )
        guard = default_replay_guard()
        if guard is None:
            raise HTTPException(status_code=503, detail="Replay guard not initialized.")
        verdict = await guard.check(
            agent_id=str(payload.agent_id),
            nonce=payload.nonce,
            issued_at=int(payload.issued_at),
        )
        if verdict.verdict != "ok":
            m.REPLAY_REJECTIONS.labels(reason=verdict.verdict).inc()
            raise HTTPException(
                status_code=401,
                detail={"reason": verdict.reason, "code": verdict.verdict},
            )

    # ── Legacy policy engine: loads agent/policy/spend from DB ─────────
    # We keep running it for the allow path so the shield stays stateless
    # and the /execute contract still reflects daily-spend math even when
    # the shield is disabled.
    with logfire.span(
        "policy_evaluation",
        agent_id=str(payload.agent_id),
        tool_call=payload.tool_call,
    ):
        decision: PolicyDecision = await policy_engine.evaluate(payload, session)

    # ── APEX-Shield: semantic risk + OPA + credential + receipt ────────
    shield_decision: ShieldDecision | None = None
    if shield_pipeline is not None:
        intent = canonicalize_intent(payload.agent_id, payload.tool_call)
        # Build policy snapshot for OPA. When the legacy policy_engine said
        # "no policy / bad agent", fall back to zero-limits so OPA denies.
        snap_dict = decision.policy_snapshot or {}
        policy_snap = PolicySnapshot(
            max_per_transaction=float(snap_dict.get("max_per_transaction", 0.0)),
            daily_limit=float(snap_dict.get("daily_limit", 0.0)),
            allowed_domains=list(snap_dict.get("allowed_domains", []) or []),
            spent_today=0.0,  # legacy engine already enforced cumulative math
        )
        shield_decision = await shield_pipeline.evaluate(
            intent=intent, policy=policy_snap,
        )

    elapsed_ms = (time.perf_counter() - start) * 1000

    # ── Combine both layers: deny if either says deny ──────────────────
    allowed = decision.allowed
    reason = decision.reason
    status = "APPROVED" if allowed else "DENIED"
    violations: list[str] = []
    hitl_id: uuid.UUID | None = None

    if shield_decision is not None:
        violations = list(shield_decision.violations)
        if shield_decision.escalate and decision.allowed:
            # Shield wants a human; legacy said ok. Route to HITL.
            hitl_req = await default_hitl_store().create(
                agent_id=payload.agent_id,
                intent_hash=shield_decision.intent.intent_hash,
                reason=shield_decision.reason,
                violations=violations,
                opa_input=shield_decision.policy_snapshot,
                risk_score=shield_decision.risk.score,
                risk_entropy=shield_decision.risk.entropy,
            )
            hitl_id = hitl_req.id
            allowed = False
            reason = shield_decision.reason
            status = "ESCALATED"
        elif not shield_decision.allow and decision.allowed:
            # Legacy said ok, shield said no → surface the shield's reason.
            allowed = False
            reason = shield_decision.reason
            status = "DENIED"
        # If legacy already denied, keep the legacy reason; the shield's
        # follow-on deny is redundant (and may be a zero-policy artefact).

    # ── Build response ─────────────────────────────────────────────────
    response = GatewayResponse(
        request_id=request_id,
        allowed=allowed,
        status=status,
        reason=reason,
        latency_ms=round(elapsed_ms, 2),
        violations=violations,
        intent_hash=shield_decision.intent.intent_hash if shield_decision else None,
        risk_score=shield_decision.risk.score if shield_decision else None,
        risk_entropy=shield_decision.risk.entropy if shield_decision else None,
        hitl_request_id=hitl_id,
    )

    if allowed and shield_decision is not None:
        if shield_decision.credential is not None:
            response.ephemeral_credential = shield_decision.credential.token
            response.credential_token_id = shield_decision.credential.token_id
            response.token = shield_decision.credential.token
            response.token_expiry = datetime.fromtimestamp(
                shield_decision.credential.expires_at, tz=timezone.utc,
            )
        if shield_decision.receipt is not None:
            response.receipt = shield_decision.receipt.to_dict()

    # ── Async audit log (non-blocking) ─────────────────────────────────
    # Use the shield's risk score (richer) when available. Note: the
    # AuditLog schema constrains status IN (APPROVED, DENIED, ERROR);
    # "ESCALATED" is normalised to DENIED in the log but carries the
    # specific reason so analysts can distinguish them.
    audit_status = status if status in ("APPROVED", "DENIED") else "DENIED"
    await audit_queue.push(
        agent_id=payload.agent_id,
        raw_intent=payload.tool_call,
        projected_cost=decision.projected_cost,
        action_domain=decision.action_domain,
        risk_score=(
            shield_decision.risk.score if shield_decision else decision.risk_score
        ),
        status=audit_status,
        denial_reason=reason if not allowed else None,
        policy_snapshot=decision.policy_snapshot,
        latency_ms=round(elapsed_ms, 2),
    )

    # ── Metrics ────────────────────────────────────────────────────────
    m.DECISIONS.labels(status=status).inc()
    m.DECISION_LATENCY.observe(elapsed_ms / 1000.0)
    if shield_decision is not None:
        m.RISK_SCORE.observe(float(shield_decision.risk.score))

    # ── Logfire: record decision ───────────────────────────────────────
    logfire.info(
        "Policy decision: {status} for agent {agent_id} — {reason}",
        status=status,
        agent_id=str(payload.agent_id),
        reason=reason,
        latency_ms=round(elapsed_ms, 2),
        projected_cost=decision.projected_cost,
        intent_hash=response.intent_hash,
        violations=violations,
        request_id=current_correlation_id(),
    )

    return response


# =============================================================================
# GET /data — Protected Data Endpoint (HTTP 402 Challenge Flow)
# =============================================================================
@router.get(
    "/data",
    summary="Access protected data — returns 402 challenge or data",
    tags=["gateway"],
)
async def get_data(
    request: Request,
    baseline: str = "payment_with_policy",
    session: AsyncSession = Depends(get_session),
) -> dict:
    """Implements the APEX /data endpoint.

    - If baseline is `no_policy`, returns data directly.
    - If no payment token header, returns HTTP 402 with a challenge.
    - If valid token, verifies and consumes it, then returns data.
    """
    # no_policy baseline — direct access
    if baseline == "no_policy":
        return {
            "status": "ok",
            "baseline": baseline,
            "data": {"title": "Protected research data", "content": "..."},
        }

    # Check for payment token
    token = request.headers.get("x-payment-token")

    if not token:
        # Issue HTTP 402 challenge
        ref_id = str(uuid.uuid4())
        amount = 10.0

        # Create challenge record
        txn = Transaction(
            agent_id=uuid.UUID("00000000-0000-0000-0000-000000000000"),  # placeholder
            ref_id=ref_id,
            amount=amount,
            state="CHALLENGED",
        )
        session.add(txn)
        await session.commit()

        raise HTTPException(
            status_code=402,
            detail={
                "amount": amount,
                "ref_id": ref_id,
                "baseline": baseline,
                "upi_link": f"upi://pay?ref={ref_id}&amount={amount}",
                "message": "Payment Required",
            },
        )

    # Verify and consume token
    is_valid, reason, payload = token_service.verify(token)
    if not is_valid:
        raise HTTPException(status_code=403, detail={"allowed": False, "reason": reason})

    ref_id = payload.get("ref_id")
    if ref_id:
        # Consume the token (state → CONSUMED)
        result = await session.execute(
            select(Transaction).where(
                Transaction.ref_id == ref_id,
                Transaction.state == "SETTLED",
            )
        )
        txn = result.scalar_one_or_none()
        if txn is None:
            raise HTTPException(
                status_code=403,
                detail={"allowed": False, "reason": "token_already_consumed"},
            )
        txn.state = "CONSUMED"
        txn.consumed_at = datetime.now(timezone.utc)
        await session.commit()

    return {
        "status": "ok",
        "baseline": baseline,
        "data": {"title": "Protected research data", "content": "..."},
    }


# =============================================================================
# POST /pay — Settlement Endpoint
# =============================================================================
@router.post(
    "/pay",
    response_model=SettlementResponse,
    summary="Settle a payment challenge and receive a signed token",
    tags=["gateway"],
)
async def settle_payment(
    request: Request,
    body: SettlementRequest,
    session: AsyncSession = Depends(get_session),
    audit_queue: AuditQueue = Depends(get_audit_queue),
) -> SettlementResponse:
    """Implements the APEX /pay settlement endpoint.

    Evaluates policy, settles payment state, and issues a signed token.
    """
    # Load the challenge record
    result = await session.execute(
        select(Transaction).where(Transaction.ref_id == body.ref_id)
    )
    txn = result.scalar_one_or_none()

    if txn is None:
        raise HTTPException(status_code=404, detail="Unknown ref_id.")

    # Idempotency: if already settled with same key, return existing token
    if txn.state == "SETTLED" and body.idempotency_key and txn.idempotency_key == body.idempotency_key:
        return SettlementResponse(
            status="success",
            ref_id=txn.ref_id,
            amount=float(txn.amount),
            token=txn.token,
            token_expiry=int(txn.token_expiry.timestamp()) if txn.token_expiry else None,
            state=txn.state,
        )

    if txn.state not in ("CHALLENGED", "INITIATED"):
        raise HTTPException(
            status_code=409,
            detail=f"Transaction in state '{txn.state}' cannot be settled.",
        )

    # Policy check (if payment_with_policy baseline)
    if body.baseline == "payment_with_policy":
        # Load agent's policy for per-request and daily checks
        policy_result = await session.execute(
            select(Policy).where(Policy.agent_id == txn.agent_id, Policy.is_active.is_(True))
        )
        policy = policy_result.scalar_one_or_none()

        if policy:
            # Per-request check
            if body.amount > float(policy.max_per_transaction):
                await audit_queue.push(
                    agent_id=txn.agent_id,
                    raw_intent={"ref_id": body.ref_id, "amount": body.amount},
                    projected_cost=body.amount,
                    action_domain=None,
                    risk_score=0.0,
                    status="DENIED",
                    denial_reason="exceeds_per_transaction_limit",
                )
                return SettlementResponse(
                    status="blocked",
                    ref_id=body.ref_id,
                    amount=body.amount,
                    allowed=False,
                    reason="exceeds_per_transaction_limit",
                )

            # Daily budget check
            today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            spend_result = await session.execute(
                text("""
                    SELECT COALESCE(SUM(amount), 0) FROM transactions
                    WHERE agent_id = :agent_id
                      AND state IN ('SETTLED', 'CONSUMED')
                      AND created_at >= :today
                """),
                {"agent_id": str(txn.agent_id), "today": today_start},
            )
            spent_today = float(spend_result.scalar_one())

            if spent_today + body.amount > float(policy.daily_limit):
                await audit_queue.push(
                    agent_id=txn.agent_id,
                    raw_intent={"ref_id": body.ref_id, "amount": body.amount},
                    projected_cost=body.amount,
                    action_domain=None,
                    risk_score=0.0,
                    status="DENIED",
                    denial_reason="daily_budget_exceeded",
                )
                return SettlementResponse(
                    status="blocked",
                    ref_id=body.ref_id,
                    amount=body.amount,
                    allowed=False,
                    reason=f"daily_budget exceeded ({spent_today + body.amount:.2f} > {float(policy.daily_limit):.2f})",
                )

    # Atomic balance debit: lock the agent row, verify balance, decrement,
    # then flip the transaction to SETTLED — all in one DB transaction so
    # a crash mid-flight cannot double-spend or issue a token with no debit.
    agent_lock = await session.execute(
        select(Agent).where(Agent.id == txn.agent_id).with_for_update()
    )
    agent = agent_lock.scalar_one_or_none()
    if agent is None:
        raise HTTPException(status_code=404, detail="Agent not found for transaction.")

    if float(agent.current_balance) < float(body.amount):
        await audit_queue.push(
            agent_id=txn.agent_id,
            raw_intent={"ref_id": body.ref_id, "amount": body.amount},
            projected_cost=body.amount,
            action_domain=None,
            risk_score=0.0,
            status="DENIED",
            denial_reason="insufficient_balance",
        )
        await session.rollback()
        return SettlementResponse(
            status="blocked",
            ref_id=body.ref_id,
            amount=body.amount,
            allowed=False,
            reason=(
                f"insufficient_balance "
                f"({float(agent.current_balance):.2f} < {body.amount:.2f})"
            ),
        )

    # Issue signed token
    token, expiry = token_service.issue(body.ref_id, body.amount)

    agent.current_balance = float(agent.current_balance) - float(body.amount)
    txn.state = "SETTLED"
    txn.token = token
    txn.token_expiry = datetime.fromtimestamp(expiry, tz=timezone.utc)
    txn.idempotency_key = body.idempotency_key
    await session.commit()

    logfire.info(
        "Payment settled: ref_id={ref_id}, amount={amount}",
        ref_id=body.ref_id,
        amount=body.amount,
    )

    return SettlementResponse(
        status="success",
        ref_id=body.ref_id,
        amount=body.amount,
        token=token,
        token_expiry=expiry,
        state="SETTLED",
    )


# =============================================================================
# POST /reset — Ledger Reset (for reproducible experiments)
# =============================================================================
@router.post("/reset", summary="Clear ledger for experiment boundaries", tags=["admin"])
async def reset_ledger(session: AsyncSession = Depends(get_session)) -> dict:
    await session.execute(text("DELETE FROM transactions"))
    await session.commit()
    return {"status": "ok", "message": "Ledger cleared."}


# =============================================================================
# POST /shield/verify-receipt — Third-party receipt verification
# =============================================================================
@router.post("/shield/verify-receipt", tags=["shield"])
async def verify_receipt(body: dict) -> dict:
    """Verify a signed execution receipt against the gateway's keyring.

    Third parties (downstream APIs, auditors) can POST {receipt, signature, kid}
    here and get back {valid, reason}. This does not touch the DB; the
    signature is self-contained.
    """
    if shield_pipeline is None:
        raise HTTPException(status_code=503, detail="Shield is disabled on this gateway.")

    from apex_pay.shield.receipt_service import SignedReceipt
    try:
        signed = SignedReceipt.from_dict(body)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Malformed receipt: {exc}")

    ok, reason = shield_pipeline.receipts.verify(signed)
    return {"valid": ok, "reason": reason}


# =============================================================================
# GET /.well-known/apex-jwks — Public key distribution
# =============================================================================
@router.get("/.well-known/apex-jwks", tags=["shield"], include_in_schema=False)
async def apex_jwks() -> Response:
    """JWKS-style endpoint for the Ed25519 receipt signing keys.

    The blueprint calls for offline, third-party receipt verification — which
    needs the gateway's public key(s). Returning them here lets verifiers
    pin on `kid` and rotate without a flag day (blueprint §12.1, §7.3).

    Format follows RFC 7517 JWK with the OKP key type (RFC 8037):
        { "keys": [ { "kty": "OKP", "crv": "Ed25519", "kid": "...", "x": "<b64url>" } ] }

    Every published kid is also the kid the gateway will accept in
    SignedReceipt.verify, so an external verifier can trust this endpoint
    as authoritative. Cache-Control is short (5 min) so rotations propagate
    quickly; downstream caches respect it.
    """
    if shield_pipeline is None:
        raise HTTPException(status_code=503, detail="Shield is disabled on this gateway.")

    import base64
    import json

    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    def _b64url(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")

    keys = []
    keyring = shield_pipeline.receipts._keyring  # noqa: SLF001 — intentional
    for kid, pub in keyring.public_keys.items():
        raw = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
        keys.append({
            "kty": "OKP",
            "crv": "Ed25519",
            "use": "sig",
            "alg": "EdDSA",
            "kid": kid,
            "x": _b64url(raw),
        })

    body = json.dumps({"keys": keys}).encode("utf-8")
    return Response(
        content=body,
        media_type="application/jwk-set+json",
        headers={"Cache-Control": "public, max-age=300"},
    )


# =============================================================================
# GET /shield/verify-receipt — Query-string / cacheable verification
# =============================================================================
@router.get("/shield/verify-receipt", tags=["shield"])
async def verify_receipt_get(receipt: str) -> dict:
    """GET variant of verify-receipt.

    `receipt` is the url-safe base64 of the canonical JSON `{receipt, signature,
    kid}` envelope. This form plays well with caches and CDNs because the
    result is deterministic in the query string, and it lets clients with
    no JSON body capability (e.g. curl one-liners, shell scripts) verify
    without constructing a POST.

    Mirrors POST /shield/verify-receipt exactly — same verification logic,
    same response shape. No DB access.
    """
    if shield_pipeline is None:
        raise HTTPException(status_code=503, detail="Shield is disabled on this gateway.")

    import base64
    import json

    from apex_pay.shield.receipt_service import SignedReceipt

    try:
        # Accept both urlsafe-b64 and plain-b64 for ergonomics.
        padded = receipt + "=" * (-len(receipt) % 4)
        try:
            decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        except Exception:
            decoded = base64.b64decode(padded.encode("ascii"))
        envelope = json.loads(decoded.decode("utf-8"))
        signed = SignedReceipt.from_dict(envelope)
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Malformed receipt: {exc}")

    ok, reason = shield_pipeline.receipts.verify(signed)
    return {"valid": ok, "reason": reason}


# =============================================================================
# GET /health — Liveness Probe
# =============================================================================
@router.get("/health", response_model=HealthResponse, tags=["ops"])
async def health() -> HealthResponse:
    from apex_pay import __version__

    return HealthResponse(
        status="ok",
        version=__version__,
        uptime_seconds=round(time.time() - _start_time, 2),
    )


# =============================================================================
# GET /ready — Readiness Probe
# =============================================================================
@router.get("/ready", tags=["ops"])
async def ready(
    request: Request,
    session: AsyncSession = Depends(get_session),
    audit_queue: AuditQueue = Depends(get_audit_queue),
) -> Response:
    """Readiness check.

    Liveness (`/health`) answers "is the process up?". This endpoint answers
    "is the process able to serve decisions *right now*?". It returns 503
    when any dependency that the hot path needs is unreachable, so an
    orchestrator (k8s readinessProbe, ALB target group health check) can
    pull the replica out of rotation without killing it.
    """
    checks: dict[str, dict[str, str]] = {}
    ok = True

    # ── DB: gateway role must be able to execute a trivial query ────────
    try:
        await session.execute(text("SELECT 1"))
        checks["database"] = {"status": "ok"}
    except Exception as exc:
        ok = False
        checks["database"] = {"status": "fail", "error": str(exc)[:200]}

    # ── Redis: audit queue must accept LLEN ─────────────────────────────
    try:
        depth = await audit_queue.depth()
        checks["redis"] = {"status": "ok", "queue_depth": str(depth)}
    except Exception as exc:
        ok = False
        checks["redis"] = {"status": "fail", "error": str(exc)[:200]}

    # ── OPA (or embedded fallback): must return a decision on a no-op ───
    if shield_pipeline is not None:
        try:
            probe = await shield_pipeline.opa.evaluate({
                "intent": {"function": "ready_probe", "parameters": {}},
                "policy": {
                    "max_per_transaction": 0,
                    "daily_limit": 0,
                    "allowed_domains": [],
                    "spent_today": 0,
                },
                "risk": {"score": 0, "entropy": 0, "labels": []},
                "thresholds": {
                    "risk_block": settings.shield.risk_block_threshold,
                    "risk_escalate": settings.shield.risk_escalate_threshold,
                    "entropy_escalate": settings.shield.entropy_escalate_threshold,
                },
            })
            checks["opa"] = {
                "status": "ok",
                "backend": "sidecar" if settings.shield.opa_url else "embedded",
                "probe_allow": str(probe.allow),
            }
        except Exception as exc:
            ok = False
            checks["opa"] = {"status": "fail", "error": str(exc)[:200]}
    else:
        checks["opa"] = {"status": "disabled"}

    # ── Audit feed broker: SSE dashboards break silently if this is down ─
    broker = getattr(request.app.state, "audit_feed_broker", None)
    if broker is not None:
        # Broker reconnects on its own with exponential backoff; disconnect
        # is a warning, not a hard-fail of the gateway's hot path.
        connected = bool(getattr(broker, "is_connected", False))
        checks["audit_feed_broker"] = {
            "status": "ok" if connected else "degraded",
        }
    else:
        checks["audit_feed_broker"] = {"status": "unknown"}

    payload = {"ready": ok, "checks": checks}
    return Response(
        media_type="application/json",
        status_code=200 if ok else 503,
        content=_json_dumps(payload),
    )


def _json_dumps(obj) -> str:
    import json
    return json.dumps(obj)


# =============================================================================
# GET /metrics — Prometheus scrape endpoint
# =============================================================================
@router.get("/metrics", tags=["ops"], include_in_schema=False)
async def metrics_endpoint(
    audit_queue: AuditQueue = Depends(get_audit_queue),
) -> Response:
    """Prometheus scrape target.

    Emits the metric set defined in `apex_pay.services.metrics`. The audit
    queue depth is sampled here (rather than written on every push) so we
    don't pay a Redis call on the hot path just to keep a gauge fresh.
    """
    try:
        depth = await audit_queue.depth()
        m.AUDIT_QUEUE_DEPTH.set(float(depth))
    except Exception:
        # Don't let a Redis blip fail the scrape. Gauge retains last value.
        pass

    payload, content_type = m.render_latest()
    return Response(content=payload, media_type=content_type)
