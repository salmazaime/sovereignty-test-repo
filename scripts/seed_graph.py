"""
Seeds the knowledge graph with the same scenario we built manually
in the Neo4j Browser, but through the actual application code path.
Run this instead of typing Cypher by hand from now on.
"""

import logging

from app.config import Neo4jConfig
from app.graph.client import GraphClient
from app.graph.repository import GraphRepository
from app.logging_setup import configure_logging

logger = logging.getLogger(__name__)


def main() -> None:
    configure_logging()
    config = Neo4jConfig.from_env()

    with GraphClient(config) as client:
        repo = GraphRepository(client.driver)

        # NOTE: replace these with the real ENTITY.id UUIDs from your
        # Postgres rows in Step 3, so both databases refer to the
        # same real-world entities.
        asset_id = "PASTE_YOUR_POSTGRES_ENTITY_ID_HERE"
        workload_id = "11111111-1111-1111-1111-111111111111"
        parent_workload_id = "22222222-2222-2222-2222-222222222222"

        repo.upsert_asset(
            entity_id=asset_id,
            name="payroll_2026_07.csv",
            resource_type="s3_object",
        )
        repo.upsert_workload(
            entity_id=workload_id,
            name="hr-payroll-app",
            resource_type="ec2_instance",
        )
        repo.upsert_workload(
            entity_id=parent_workload_id,
            name="core-hr-platform",
            resource_type="ec2_instance",
        )

        repo.link_depends_on(workload_id, asset_id, confidence=0.95)
        repo.link_depends_on(workload_id, parent_workload_id, confidence=1.0)

        logger.info("Seed complete. Querying impact radius...")
        impact = repo.get_impact_radius(asset_id, max_hops=3)
        for node in impact:
            logger.info("  -> %s (%s)", node["name"], node["labels"])


if __name__ == "__main__":
    main()
    