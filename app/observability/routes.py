# app/observability/routes.py
"""
Exposes Prometheus's text-format metrics. Deliberately UNAUTHENTICATED
in this implementation -- Prometheus scrapers typically don't carry
application credentials, and the standard production pattern is to
restrict this endpoint at the NETWORK layer (firewall rule, or in
Kubernetes a NetworkPolicy limiting which pods/namespaces can reach
it) rather than requiring an API key the scraper would need to be
configured with. Naming this explicitly rather than silently leaving
/metrics open with no comment: in a real deployment, this endpoint
should not be reachable from the public internet, even though this
route itself performs no request-level auth check.
"""

from fastapi import APIRouter, Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

router = APIRouter()


@router.get("/metrics", tags=["ops"], include_in_schema=False)
def metrics() -> Response:
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
    