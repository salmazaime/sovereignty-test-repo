"""
Orchestrator, extended to accept and forward optional DLP finding
maps. Signature changes are additive-with-defaults -- every existing
call site (tests, Step 13's original scripts) still works unchanged.
"""

import logging

from app.connectors.aws.client import AWSClientFactory
from app.connectors.aws.ec2_connector import discover_ec2_instances
from app.connectors.aws.s3_connector import discover_s3_buckets
from app.connectors.azure.blob_connector import discover_blob_containers
from app.connectors.azure.client import AzureClientFactory
from app.connectors.azure.vm_connector import discover_virtual_machines
from app.connectors.base import DiscoveredResource
from app.connectors.region_lookup import RegionCountryTable
from app.connectors.transform import to_ingestion_request
from app.db.repository import PostgresRepository
from app.graph.repository import GraphRepository
from app.ingestion.pipeline import GraphProjectionError, ingest_discovery_finding

logger = logging.getLogger(__name__)


def _ingest_resources(
    resources: list[DiscoveredResource],
    postgres_repo: PostgresRepository,
    graph_repo: GraphRepository,
    region_table: RegionCountryTable,
    company_name: str,
    company_sector: str,
) -> tuple[int, int]:
    succeeded, failed = 0, 0
    for resource in resources:
        try:
            request = to_ingestion_request(resource, company_name, company_sector, region_table)
            ingest_discovery_finding(postgres_repo, graph_repo, request)
            succeeded += 1
        except GraphProjectionError as exc:
            logger.warning("Graph sync pending for %s: %s", resource.name, exc)
            succeeded += 1
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to ingest %s (%s): %s", resource.name, resource.resource_type, exc)
            failed += 1
    return succeeded, failed


def run_aws_discovery(
    regions: list[str],
    postgres_repo: PostgresRepository,
    graph_repo: GraphRepository,
    region_table: RegionCountryTable,
    company_name: str,
    company_sector: str,
    macie_findings_by_bucket: dict[str, list[dict]] | None = None,
) -> None:
    macie_findings_by_bucket = macie_findings_by_bucket or {}
    for region in regions:
        logger.info("Scanning AWS region %s", region)
        factory = AWSClientFactory(region)

        buckets = discover_s3_buckets(factory, dlp_findings_by_resource=macie_findings_by_bucket)
        instances = discover_ec2_instances(factory)

        ok, failed = _ingest_resources(
            buckets + instances, postgres_repo, graph_repo, region_table, company_name, company_sector
        )
        logger.info("AWS %s: %d ingested, %d failed", region, ok, failed)


def run_azure_discovery(
    subscription_id: str,
    resource_groups: list[str],
    postgres_repo: PostgresRepository,
    graph_repo: GraphRepository,
    region_table: RegionCountryTable,
    company_name: str,
    company_sector: str,
    purview_findings_by_container: dict[str, list[dict]] | None = None,
) -> None:
    purview_findings_by_container = purview_findings_by_container or {}
    factory = AzureClientFactory(subscription_id)
    for rg in resource_groups:
        logger.info("Scanning Azure resource group %s", rg)

        containers = discover_blob_containers(
            factory, rg, dlp_findings_by_resource=purview_findings_by_container
        )
        vms = discover_virtual_machines(factory, rg)

        ok, failed = _ingest_resources(
            containers + vms, postgres_repo, graph_repo, region_table, company_name, company_sector
        )
        logger.info("Azure %s: %d ingested, %d failed", rg, ok, failed)
        