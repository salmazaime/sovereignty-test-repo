# app/interceptor/cli.py
"""
The orchestration logic, deliberately structured so it's testable
WITHOUT a live API or a real repository checkout: run_gate() accepts
already-discovered resources and an already-constructed api_client,
so tests can inject fakes for both (see tests/test_interceptor_cli.py).
scripts/run_pipeline_interceptor.py (14.17) is the thin, untested-by-
design wiring layer that does real filesystem walks and constructs
the real SovereigntyAPIClient, then calls this function.
"""

import logging

from app.connectors.base import DiscoveredResource
from app.connectors.region_lookup import RegionCountryTable
from app.interceptor.api_client import SovereigntyAPIClient, SovereigntyAPIError
from app.interceptor.assembler import assemble_ingestion_requests

logger = logging.getLogger(__name__)

BLOCKING_OUTCOMES = {"DENY", "REVIEW"}


def run_gate(
    resources: list[DiscoveredResource],
    api_client: SovereigntyAPIClient,
    company_name: str,
    company_sector: str,
    region_table: RegionCountryTable,
    initiated_by: str,
    initiating_application: str,
) -> int:
    """
    Returns the process exit code: 0 if every resolvable resource is
    ALLOWED, 1 if ANY resource is DENY/REVIEW or the API is
    unreachable (fail closed, consistent with every other gate in
    this project since Step 11).

    Resources with no resolvable cloud/region (e.g. the synthetic
    repo-content bundle, an untracked K8s resource) are ingested for
    audit visibility but skipped for the transfer decision itself --
    see repo_scanner.py's module docstring for why that's a
    deliberate boundary, not an oversight.
    """
    ingestion_requests = assemble_ingestion_requests(resources, company_name, company_sector, region_table)
    if not ingestion_requests and not resources:
        logger.info("No infrastructure or content resources discovered -- nothing to evaluate.")
        return 0

    resource_by_name = {r.name: r for r in resources}
    blocked: list[dict] = []
    evaluated_count = 0

    for request in ingestion_requests:
        resource = resource_by_name.get(request.entity_name)
        try:
            entity_id = api_client.ingest(request.model_dump(mode="json"))
        except SovereigntyAPIError as exc:
            logger.error("Ingestion failed for %s: %s -- failing closed.", request.entity_name, exc)
            blocked.append({"entity": request.entity_name, "reason": f"ingestion_error: {exc}"})
            continue

        if resource is None or resource.cloud_provider not in ("aws", "azure"):
            logger.info(
                "%s has no resolvable cloud destination -- ingested for audit, "
                "not evaluated for transfer decision.", request.entity_name,
            )
            continue

        country = region_table.country_for(resource.cloud_provider, resource.region)
        destination_country = country or "UNKNOWN"
        if country is None:
            logger.warning(
                "Region '%s' for %s has no known country mapping -- using 'UNKNOWN', "
                "which the decision engine's adequacy check will correctly route to REVIEW.",
                resource.region, request.entity_name,
            )

        try:
            transfer = api_client.request_transfer({
                "entity_id": entity_id,
                "operation": "iac_declared_infrastructure",
                "destination_cloud": resource.cloud_provider,
                "destination_service": resource.resource_type,
                "destination_region": resource.region,
                "destination_country": destination_country,
                "initiated_by": initiated_by,
                "initiating_application": initiating_application,
            })
        except SovereigntyAPIError as exc:
            logger.error("Transfer decision failed for %s: %s -- failing closed.", request.entity_name, exc)
            blocked.append({"entity": request.entity_name, "reason": f"decision_error: {exc}"})
            continue

        evaluated_count += 1
        outcome = transfer["outcome"]
        logger.info("%s -> %s (%s)", request.entity_name, outcome, transfer["reason_code"])

        if outcome in BLOCKING_OUTCOMES:
            blocked.append({
                "entity": request.entity_name,
                "outcome": outcome,
                "reason": transfer["reason_code"],
                "policy_reference": transfer.get("policy_reference"),
            })

    if blocked:
        logger.error("Sovereignty gate FAILED. %d resource(s) blocked:", len(blocked))
        for item in blocked:
            logger.error("  - %s", item)
        return 1

    logger.info("Sovereignty gate PASSED. %d resource(s) evaluated, all ALLOWED.", evaluated_count)
    return 0
    