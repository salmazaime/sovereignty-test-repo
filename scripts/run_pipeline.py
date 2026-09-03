"""
End-to-end demonstration: two entities, one depending on the other,
ingested through the full pipeline into both Postgres and Neo4j.
This is the first script in the project that actually represents
your architecture working as ONE system rather than two separate demos.
"""

import logging

from app.config import Neo4jConfig, PostgresConfig
from app.db.client import PostgresClient
from app.db.repository import PostgresRepository
from app.graph.client import GraphClient
from app.graph.repository import GraphRepository
from app.ingestion.pipeline import GraphProjectionError, ingest_discovery_finding
from app.logging_setup import configure_logging
from app.schemas import (
    AssetInfo,
    CanonicalSchemaPayload,
    Classification,
    DependencyLink,
    EntityType,
    IngestionRequest,
    ResidencyLock,
    SensitivityCategory,
)

logger = logging.getLogger(__name__)


def main() -> None:
    configure_logging()
    pg_config = PostgresConfig.from_env()
    neo_config = Neo4jConfig.from_env()

    with PostgresClient(pg_config) as pg_client, GraphClient(neo_config) as graph_client:
        postgres_repo = PostgresRepository(pg_client.pool)
        graph_repo = GraphRepository(graph_client.driver)

        # Entity 1: the sensitive dataset, ingested first.
        asset_request = IngestionRequest(
            company_name="Acme Corp",
            company_sector="banking",
            entity_type=EntityType.DATA_ASSET,
            entity_name="payroll_2026_07.csv",
            business_owner="hr-team",
            environment="prod",
            plugin_used="aws_s3_plugin",
            phase="INITIAL_DISCOVERY",
            payload=CanonicalSchemaPayload(
                asset=AssetInfo(
                    granularity="dataset",
                    resource_type="s3_object",
                    content_findings=[],
                ),
                classification=Classification(
                    sensitivity_category=[SensitivityCategory.NATIONAL_ID],
                    residency_lock=ResidencyLock.NONE,
                    aggregate_sensitivity="high",
                ),
            ),
            overall_confidence=0.95,
        )
        asset_id = ingest_discovery_finding(postgres_repo, graph_repo, asset_request)
        logger.info("Ingested asset entity_id=%s", asset_id)

        # Entity 2: a workload that depends on the asset above,
        # ingested second — so the dependency CAN be resolved this time.
        workload_request = IngestionRequest(
            company_name="Acme Corp",
            company_sector="banking",
            entity_type=EntityType.WORKLOAD,
            entity_name="hr-payroll-app",
            business_owner="hr-team",
            environment="prod",
            plugin_used="aws_ec2_plugin",
            phase="INITIAL_DISCOVERY",
            payload=CanonicalSchemaPayload(
                asset=AssetInfo(
                    granularity="workload",
                    resource_type="ec2_instance",
                    content_findings=[],
                ),
                classification=Classification(
                    sensitivity_category=[SensitivityCategory.NONE],
                    residency_lock=ResidencyLock.NONE,
                    aggregate_sensitivity="low",
                ),
            ),
            overall_confidence=0.9,
            dependencies=[
                DependencyLink(
                    target_entity_type=EntityType.DATA_ASSET,
                    target_entity_name="payroll_2026_07.csv",
                    confidence=0.95,
                )
            ],
        )
        try:
            workload_id = ingest_discovery_finding(postgres_repo, graph_repo, workload_request)
            logger.info("Ingested workload entity_id=%s", workload_id)
        except GraphProjectionError as exc:
            logger.error("Recoverable failure, safe to retry: %s", exc)
            return

        # Prove the dependency now shows up in the graph.
        impact = graph_repo.get_impact_radius(str(asset_id), max_hops=3)
        logger.info("Impact radius of the sensitive asset:")
        for node in impact:
            logger.info("  -> %s (%s)", node["name"], node["labels"])


if __name__ == "__main__":
    main()
    