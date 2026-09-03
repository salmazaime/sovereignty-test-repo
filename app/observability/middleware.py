# app/observability/middleware.py
"""
ASGI middleware run on EVERY request: generates/propagates a request
ID, times the request, logs a single structured access-log line, and
records HTTP metrics. This is the one place request-level
cross-cutting concerns live -- individual routes never need to
remember to log their own start/end or record their own HTTP metric.
"""

import logging
import time

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.observability.context import generate_request_id, set_company_id, set_request_id
from app.observability.metrics import HTTP_REQUEST_DURATION_SECONDS, HTTP_REQUESTS_TOTAL

logger = logging.getLogger("access")

REQUEST_ID_HEADER = "X-Request-ID"


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> Response:
        # A caller (e.g. an upstream proxy, or the GitHub interceptor
        # itself) may already have a request ID for this operation --
        # honoring an incoming header lets tracing survive across
        # service boundaries instead of starting fresh at each hop.
        incoming_id = request.headers.get(REQUEST_ID_HEADER)
        request_id = incoming_id or generate_request_id()
        set_request_id(request_id)

        start = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # Even an unhandled exception must still get logged with
            # its request_id and recorded in metrics before re-raising
            # -- otherwise a crash is invisible in both the access log
            # and the metrics, exactly when visibility matters most.
            duration = time.perf_counter() - start
            logger.exception(
                "request_failed method=%s path=%s duration_s=%.4f",
                request.method, request.url.path, duration,
            )
            HTTP_REQUESTS_TOTAL.labels(request.method, request.url.path, "500").inc()
            HTTP_REQUEST_DURATION_SECONDS.labels(request.method, request.url.path).observe(duration)
            raise

        duration = time.perf_counter() - start
        response.headers[REQUEST_ID_HEADER] = request_id

        logger.info(
            "request method=%s path=%s status=%d duration_s=%.4f",
            request.method, request.url.path, response.status_code, duration,
        )
        HTTP_REQUESTS_TOTAL.labels(request.method, request.url.path, str(response.status_code)).inc()
        HTTP_REQUEST_DURATION_SECONDS.labels(request.method, request.url.path).observe(duration)

        return response
        