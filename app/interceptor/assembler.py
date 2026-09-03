# app/interceptor/assembler.py
"""
Thin pass-through to the SAME transform function built in Step 13
(app/connectors/transform.py) -- every DiscoveredResource, regardless
of whether it came from a live cloud API, a parsed .tf file, a K8s
manifest, or a repo content scan, funnels through the ONE existing
transform function. This file exists only to batch the call and
attach company context, not to duplicate any transformation logic.
"""

import logging

from app.connectors.base import DiscoveredResource
from app.connectors.region_lookup import RegionCountryTable
from app.connectors.transform import to_ingestion_request
from app.schemas import IngestionRequest

logger = logging.getLogger(__name__)


def assemble_ingestion_requests(
    resources: list[DiscoveredResource],
    company_name: str,
    company_sector: str,
    region_table: RegionCountryTable,
) -> list[IngestionRequest]:
    requests: list[IngestionRequest] = []
    for resource in resources:
        try:
            requests.append(to_ingestion_request(resource, company_name, company_sector, region_table))
        except Exception as exc:  # noqa: BLE001 -- one malformed resource must not abort the whole batch
            logger.error(
                "Could not build IngestionRequest for %s (%s): %s -- skipping.",
                resource.name, resource.resource_type, exc,
            )
            continue
    return requests
    