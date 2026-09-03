"""
Idempotent equivalent of the manual Step 3 sanity insert. Run this
as many times as you want — it upserts, it doesn't duplicate.
"""

import logging

from app.config import PostgresConfig
from app.db.client import PostgresClient
from app.db.repository import PostgresRepository
from app.logging_setup import configure_logging

logger = logging.getLogger(__name__)


def main() -> None:
    configure_logging()
    config = PostgresConfig.from_env()

    with PostgresClient(config) as client:
        repo = PostgresRepository(client.pool)

        company_id = repo.upsert_company(name="Acme Corp", sector="banking")
        logger.info("Company id: %s", company_id)

        entity_id = repo.upsert_entity(
            company_id=company_id,
            entity_type="DATA_ASSET",
            name="payroll_2026_07.csv",
            business_owner="hr-team",
            environment="prod",
        )
        logger.info("Entity id: %s", entity_id)

        schema_id = repo.insert_canonical_schema(
            company_id=company_id,
            entity_id=entity_id,
            phase="INITIAL_DISCOVERY",
            plugin_used="aws_s3_plugin",
            payload={
                "asset": {
                    "granularity": "dataset",
                    "resource_type": "s3_object",
                    "content_findings": [
                        {
                            "category": "national_id",
                            "field_or_location": "column:CIN",
                            "confidence": 0.97,
                            "detector": "regex",
                        }
                    ],
                },
                "classification": {
                    "sensitivity_category": ["national_id"],
                    "residency_lock": "none",
                    "aggregate_sensitivity": "high",
                },
            },
            overall_confidence=0.95,
        )
        logger.info("Canonical schema id: %s", schema_id)

        entity = repo.get_entity(entity_id)
        logger.info("Fetched back: %s", entity)


if __name__ == "__main__":
    main()
    