"""
Real entry point for cloud discovery, now DLP-aware. If
MACIE_FINDINGS_EXPORT_PATH / PURVIEW_SCAN_EXPORT_PATH are set and
the files exist and parse successfully, their findings are used
PER-RESOURCE wherever available; every resource NOT covered by those
exports still gets local regex/PDF/OCR sampling automatically, since
the smart-fallback logic lives inside the connectors themselves
(13.15/13.16) at the per-bucket/per-container level, not as a
global switch here.
"""

import logging
import os
from pathlib import Path

from app.config import Neo4jConfig, PostgresConfig
from app.connectors.aws.macie_connector import load_macie_findings_file
from app.connectors.azure.purview_connector import load_purview_scan_file
from app.connectors.region_lookup import RegionCountryTable
from app.connectors.runner import run_aws_discovery, run_azure_discovery
from app.db.client import PostgresClient
from app.db.repository import PostgresRepository
from app.graph.client import GraphClient
from app.graph.repository import GraphRepository
from app.logging_setup import configure_logging

logger = logging.getLogger(__name__)


def main() -> None:
    configure_logging()
    pg_config = PostgresConfig.from_env()
    neo_config = Neo4jConfig.from_env()
    region_table = RegionCountryTable.load(Path("config/region_country_map.json"))

    company_name = os.environ.get("DISCOVERY_COMPANY_NAME", "Acme Corp")
    company_sector = os.environ.get("DISCOVERY_COMPANY_SECTOR", "banking")
    aws_regions = os.environ.get("AWS_DISCOVERY_REGIONS", "eu-west-3").split(",")
    azure_sub_id = os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    azure_rgs = os.environ.get("AZURE_DISCOVERY_RESOURCE_GROUPS", "").split(",")

    macie_export_path = os.environ.get("MACIE_FINDINGS_EXPORT_PATH", "")
    purview_export_path = os.environ.get("PURVIEW_SCAN_EXPORT_PATH", "")

    macie_findings: dict[str, list[dict]] = {}
    if macie_export_path:
        macie_findings = load_macie_findings_file(Path(macie_export_path))
    else:
        logger.info("MACIE_FINDINGS_EXPORT_PATH not set -- all S3 buckets will use local regex/PDF/OCR sampling.")

    purview_findings: dict[str, list[dict]] = {}
    if purview_export_path:
        purview_findings = load_purview_scan_file(Path(purview_export_path))
    else:
        logger.info("PURVIEW_SCAN_EXPORT_PATH not set -- all Blob containers will use local regex/PDF/OCR sampling.")

    with PostgresClient(pg_config) as pg_client, GraphClient(neo_config) as graph_client:
        postgres_repo = PostgresRepository(pg_client.pool)
        graph_repo = GraphRepository(graph_client.driver)

        try:
            run_aws_discovery(
                aws_regions, postgres_repo, graph_repo, region_table,
                company_name, company_sector,
                macie_findings_by_bucket=macie_findings,
            )
        except Exception as exc:  # noqa: BLE001
            logger.error("AWS discovery run failed entirely: %s", exc)

        if azure_sub_id and azure_rgs != [""]:
            try:
                run_azure_discovery(
                    azure_sub_id, azure_rgs, postgres_repo, graph_repo,
                    region_table, company_name, company_sector,
                    purview_findings_by_container=purview_findings,
                )
            except Exception as exc:  # noqa: BLE001
                logger.error("Azure discovery run failed entirely: %s", exc)
        else:
            logger.info("AZURE_SUBSCRIPTION_ID not set -- skipping Azure discovery.")


if __name__ == "__main__":
    main()
    