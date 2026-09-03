# app/observability/metrics.py
"""
Every metric this app exposes, defined ONCE, here -- same discipline
as app/db/repository.py being the only file with raw SQL. Scattering
Counter()/Histogram() definitions across route files would risk
duplicate metric names (Prometheus client raises at registration if
two Counters share a name) and makes it impossible to see the full
metric surface area in one place.
"""

from prometheus_client import Counter, Histogram

HTTP_REQUESTS_TOTAL = Counter(
    "http_requests_total", "Total HTTP requests", ["method", "path", "status_code"],
)
HTTP_REQUEST_DURATION_SECONDS = Histogram(
    "http_request_duration_seconds", "HTTP request latency", ["method", "path"],
)

POLICY_DECISIONS_TOTAL = Counter(
    "policy_decisions_total", "Policy decisions by outcome", ["outcome"],
)

INGESTION_TOTAL = Counter(
    "ingestion_total", "Ingestion attempts by result", ["result"],  # result: success | partial | failure
)
INGESTION_DURATION_SECONDS = Histogram(
    "ingestion_duration_seconds", "Time to complete an ingestion (Postgres + graph write)",
)

