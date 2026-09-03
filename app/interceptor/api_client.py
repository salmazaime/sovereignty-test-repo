# app/interceptor/api_client.py
"""
The ONLY way this interceptor talks to the backend. Imports nothing
from app.db or app.graph -- verified by the absence of any such
import below. All communication is REST/HTTP via `httpx`, exactly
as required: this script can run on ANY machine with network access
to the API (a GitHub Actions runner, a client's own CI runner,
a laptop), with zero database driver or credential requirements
beyond the API's own URL.

Note on endpoint paths: our API (built in Steps 8-11) does not
currently version its routes under /api/v1 -- endpoints are plain
/ingest, /transfer-request, etc. This client targets the ACTUAL
existing routes rather than inventing a /api/v1 prefix that doesn't
exist in the codebase yet. Adding API versioning is a legitimate
future improvement (Step 16/17 territory) -- flagged here rather
than silently papered over with a fake path.
"""

import logging

import httpx

logger = logging.getLogger(__name__)


class SovereigntyAPIError(Exception):
    """Raised for unreachable API or unexpected (non-2xx, non-403) responses."""


class SovereigntyAPIClient:
    def __init__(self, base_url: str, api_key: str, timeout_seconds: float = 15.0) -> None:
        self._api_key = api_key
        self._client = httpx.Client(
            base_url=base_url,
            timeout=timeout_seconds,
            headers={"X-API-Key": api_key},  
        )

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "SovereigntyAPIClient":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()

    def ingest(self, ingestion_payload: dict) -> str:
        """Returns entity_id. 201 and 207 (Step 7's partial-success state) both usable."""
        try:
            response = self._client.post("/ingest", json=ingestion_payload)
        except httpx.RequestError as exc:
            raise SovereigntyAPIError(f"Could not reach API for /ingest: {exc}") from exc

        if response.status_code in (201, 207):
            body = response.json()
            entity_id = body.get("entity_id") or body.get("detail", {}).get("entity_id")
            if response.status_code == 207:
                logger.warning("Ingestion partially succeeded (graph sync pending): %s", body)
            if not entity_id:
                raise SovereigntyAPIError(f"/ingest response missing entity_id: {body}")
            return entity_id

        raise SovereigntyAPIError(f"/ingest failed: {response.status_code} {response.text}")

    def request_transfer(self, transfer_payload: dict) -> dict:
        try:
            response = self._client.post("/transfer-request", json=transfer_payload)
        except httpx.RequestError as exc:
            raise SovereigntyAPIError(f"Could not reach API for /transfer-request: {exc}") from exc

        if response.status_code != 201:
            raise SovereigntyAPIError(f"/transfer-request failed: {response.status_code} {response.text}")
        return response.json()
        
    