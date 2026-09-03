# scripts/seed_admin_user.py -- REPLACE the placeholder password_hash
import logging

from app.auth.security import hash_password
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
        user_id = repo.upsert_user_account(
            company_id=company_id,
            name="Compliance Reviewer",
            email="reviewer@acme.test",
            password_hash=hash_password("change-me-in-production"),  # REAL hash now
        )
        repo.assign_role(user_id, "compliance_reviewer")
        repo.assign_role(user_id, "admin")
        logger.info("Reviewer user_id: %s (roles: compliance_reviewer, admin)", user_id)


if __name__ == "__main__":
    main()
    