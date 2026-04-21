"""Correlation-id middleware + contextvar.

Blueprint §13.3 requires a correlation id on every request so a single
trace can be followed across the gateway, the shield stages, the Redis
push, the audit worker, and the SSE fan-out.

Design:

* One contextvar, `CORRELATION_ID`, readable from anywhere in the async
  call stack. Default is an empty string so reads never raise.
* A Starlette middleware that generates (or propagates) the id per request
  and sets the contextvar. On the response, we echo the id back as the
  `X-Request-ID` header so callers can join their own logs to ours.
* If an inbound `X-Request-ID` header is present and looks sane, we
  propagate it; otherwise we mint a fresh UUID. This lets an ingress (LB,
  API gateway) control the id while the service still generates one when
  called directly.

The middleware does NOT log on every request — the FastAPI access logger
and Logfire span already cover that, and adding another log line per
request doubles the volume. Consumers of the contextvar should include
the id in their own log records when it is set.
"""

from __future__ import annotations

import re
import uuid
from contextvars import ContextVar

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

CORRELATION_ID: ContextVar[str] = ContextVar("apex_correlation_id", default="")

# Accept any reasonable client-supplied id: UUIDs, short hex, short base64url.
# We cap length so a malicious caller cannot bloat every log line.
_ID_OK = re.compile(r"^[A-Za-z0-9._\-]{1,128}$")

_HEADER = "X-Request-ID"


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Set CORRELATION_ID contextvar and echo it as X-Request-ID."""

    async def dispatch(self, request: Request, call_next) -> Response:
        incoming = request.headers.get(_HEADER, "")
        rid = incoming if _ID_OK.fullmatch(incoming) else uuid.uuid4().hex
        token = CORRELATION_ID.set(rid)
        try:
            response = await call_next(request)
        finally:
            CORRELATION_ID.reset(token)
        response.headers[_HEADER] = rid
        return response


def current_correlation_id() -> str:
    """Return the correlation id for the current task, or '' if none set."""
    return CORRELATION_ID.get()
