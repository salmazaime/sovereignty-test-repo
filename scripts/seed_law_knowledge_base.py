"""
Seeds LAW_DOCUMENT/LAW_CLAUSE with real article text for the
provisions the decision engine already cites. Paraphrased summaries,
not verbatim legal text reproduction — for an actual audit-facing
system you'd want the real official text and a link to the official
gazette publication, but a paraphrase is sufficient to prove the
join and reconstruction logic works.
"""

import logging

from app.config import PostgresConfig
from app.db.client import PostgresClient
from app.db.repository import PostgresRepository
from app.logging_setup import configure_logging

logger = logging.getLogger(__name__)

CLAUSES = [
    {
        "law_name": "loi_09-08",
        "law_version": "2009",
        "article_number": "43",
        "policy_reference_code": "art_43_loi_09-08",
        "content": (
            "Personal data may be transferred to a foreign country only if that "
            "country ensures an adequate level of protection, as determined by "
            "the CNDP, or if a specific derogation applies (consent, vital "
            "interest, contract necessity, legal claims, or CNDP authorization)."
        ),
    },
    {
        "law_name": "loi_05-20",
        "law_version": "2020",
        "article_number": "11",
        "policy_reference_code": "art_11_loi_05-20",
        "content": (
            "Sensitive data, as classified under the entity's information "
            "systems, must be hosted exclusively within Moroccan national "
            "territory."
        ),
    },
    {
        "law_name": "decree_2.24.921",
        "law_version": "2024",
        "article_number": "n/a",
        "policy_reference_code": "decree_2.24.921",
        "content": (
            "Cloud and hosting providers handling sensitive or OIV-classified "
            "data must themselves be qualified/certified for that purpose."
        ),
    },
]


def main() -> None:
    configure_logging()
    config = PostgresConfig.from_env()

    with PostgresClient(config) as client:
        repo = PostgresRepository(client.pool)
        for clause in CLAUSES:
            doc_id = repo.upsert_law_document(
                name=clause["law_name"],
                version=clause["law_version"],
                country="Morocco",
                issuing_authority="CNDP" if "09-08" in clause["law_name"] else "DGSSI",
            )
            clause_id = repo.upsert_law_clause(
                law_document_id=doc_id,
                article_number=clause["article_number"],
                content=clause["content"],
                policy_reference_code=clause["policy_reference_code"],
            )
            logger.info("Seeded clause %s -> %s", clause["policy_reference_code"], clause_id)


if __name__ == "__main__":
    main()
    