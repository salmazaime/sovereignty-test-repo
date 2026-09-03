"""
Provisions a new API key for a company's machine clients (the
GitHub interceptor, discovery connectors). The plaintext key is
printed ONCE -- copy it immediately into the calling system's
secrets store; it cannot be recovered afterward since only its hash
is persisted.
"""

import logging
import sys

from app.auth.api_keys import generate_api_key
from app.config import PostgresConfig
from app.db.client import PostgresClient
from app.db.repository import PostgresRepository
from app.logging_setup import configure_logging

logger = logging.getLogger(__name__)


def main() -> None:
    configure_logging()
    if len(sys.argv) < 2:
        print("Usage: python -m scripts.create_api_key <company_name>")
        sys.exit(1)

    company_name = sys.argv[1]
    config = PostgresConfig.from_env()

    with PostgresClient(config) as client:
        repo = PostgresRepository(client.pool)
        company_id = repo.upsert_company(name=company_name, sector="unspecified")
        plaintext, key_hash = generate_api_key()
        key_id = repo.create_api_key(company_id=company_id, name="ci-interceptor", key_hash=key_hash, created_by=None)

        logger.info("API key created (id=%s) for company '%s'.", key_id, company_name)
        print(f"\n  X-API-Key: {plaintext}\n")
        print("Store this now -- it will not be shown again.\n")


if __name__ == "__main__":
    main()
    