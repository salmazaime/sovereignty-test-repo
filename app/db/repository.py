"""
Repository layer for Postgres. The ONLY file in the project allowed
to contain raw SQL (Step 6's rule). Every query uses %s placeholders
with parameters passed separately -- never f-strings/format() with
untrusted values, the SQL-injection-prevention discipline held
throughout this project.
"""

import json
import logging
from dataclasses import dataclass
from typing import Any, Optional
from uuid import UUID

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class EntityRecord:
    id: UUID
    company_id: UUID
    entity_type: str
    name: str
    business_owner: Optional[str]
    environment: Optional[str]


class PostgresRepository:
    def __init__(self, pool: ConnectionPool) -> None:
        self._pool = pool

    # ============================================================
    # Companies (Step 6, extended Step 9 for OIV fields)
    # ============================================================

    def upsert_company(self, name: str, sector: str) -> UUID:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO COMPANY (name, sector)
                    VALUES (%s, %s)
                    ON CONFLICT (name) DO UPDATE
                        SET sector = EXCLUDED.sector
                    RETURNING id;
                    """,
                    (name, sector),
                )
                row = cur.fetchone()
                conn.commit()
                return row["id"]

    def get_company_profile(self, company_id: UUID) -> Optional[dict]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT id, name, is_oiv, oiv_sector, qualified_provider_required
                    FROM COMPANY WHERE id = %s;
                    """,
                    (str(company_id),),
                )
                return cur.fetchone()

    # ============================================================
    # Entities (Step 6)
    # ============================================================

    def upsert_entity(
        self,
        company_id: UUID,
        entity_type: str,
        name: str,
        business_owner: Optional[str] = None,
        environment: Optional[str] = None,
    ) -> UUID:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO ENTITY (company_id, entity_type, name, business_owner, environment)
                    VALUES (%s, %s, %s, %s, %s)
                    ON CONFLICT (company_id, entity_type, name) DO UPDATE
                        SET business_owner = EXCLUDED.business_owner,
                            environment = EXCLUDED.environment,
                            updated_at = now()
                    RETURNING id;
                    """,
                    (str(company_id), entity_type, name, business_owner, environment),
                )
                row = cur.fetchone()
                conn.commit()
                return row["id"]

    def get_entity(self, entity_id: UUID) -> Optional[EntityRecord]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT id, company_id, entity_type, name, business_owner, environment
                    FROM ENTITY WHERE id = %s;
                    """,
                    (str(entity_id),),
                )
                row = cur.fetchone()
                return EntityRecord(**row) if row else None

    def get_entity_by_natural_key(
        self, company_id: UUID, entity_type: str, name: str
    ) -> Optional[EntityRecord]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT id, company_id, entity_type, name, business_owner, environment
                    FROM ENTITY
                    WHERE company_id = %s AND entity_type = %s AND name = %s;
                    """,
                    (str(company_id), entity_type, name),
                )
                row = cur.fetchone()
                return EntityRecord(**row) if row else None

    # ============================================================
    # Canonical schema (Step 6, Step 9 for classification read)
    # ============================================================

    def insert_canonical_schema(
        self,
        company_id: UUID,
        entity_id: UUID,
        phase: str,
        plugin_used: str,
        payload: dict[str, Any],
        overall_confidence: float,
    ) -> UUID:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    UPDATE CANONICAL_SCHEMA
                    SET is_latest = false
                    WHERE entity_id = %s AND is_latest = true;
                    """,
                    (str(entity_id),),
                )
                cur.execute(
                    """
                    INSERT INTO CANONICAL_SCHEMA
                        (company_id, entity_id, phase, plugin_used, payload, overall_confidence, is_latest)
                    VALUES (%s, %s, %s, %s, %s, %s, true)
                    RETURNING id;
                    """,
                    (
                        str(company_id), str(entity_id), phase, plugin_used,
                        json.dumps(payload), overall_confidence,
                    ),
                )
                schema_id = cur.fetchone()["id"]
                cur.execute(
                    "UPDATE ENTITY SET latest_canonical_schema_id = %s WHERE id = %s;",
                    (str(schema_id), str(entity_id)),
                )
                conn.commit()
                return schema_id

    def get_latest_classification(self, entity_id: UUID) -> Optional[dict]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT payload -> 'classification' AS classification
                    FROM CANONICAL_SCHEMA
                    WHERE entity_id = %s AND is_latest = true
                    ORDER BY generated_at DESC LIMIT 1;
                    """,
                    (str(entity_id),),
                )
                row = cur.fetchone()
                return row["classification"] if row else None

    def get_latest_canonical_schema_id(self, entity_id: UUID) -> Optional[UUID]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT id FROM CANONICAL_SCHEMA
                    WHERE entity_id = %s AND is_latest = true
                    ORDER BY generated_at DESC LIMIT 1;
                    """,
                    (str(entity_id),),
                )
                row = cur.fetchone()
                return row["id"] if row else None

    # ============================================================
    # Transfer requests + policy decisions (Step 9)
    # ============================================================

    def insert_transfer_request(
        self,
        company_id: UUID,
        entity_id: UUID,
        operation: str,
        source_country: Optional[str],
        destination_country: str,
        destination_deployment_type: str,
        initiated_by: Optional[str],
        initiating_application: Optional[str],
    ) -> UUID:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO TRANSFER_REQUEST
                        (company_id, entity_id, operation, source_country,
                         destination_country, destination_deployment_type,
                         initiated_by, initiating_application, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'PENDING')
                    RETURNING id;
                    """,
                    (
                        str(company_id), str(entity_id), operation, source_country,
                        destination_country, destination_deployment_type,
                        initiated_by, initiating_application,
                    ),
                )
                row = cur.fetchone()
                conn.commit()
                return row["id"]

    def get_transfer_request(self, transfer_request_id: UUID) -> Optional[dict]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT * FROM TRANSFER_REQUEST WHERE id = %s;", (str(transfer_request_id),))
                return cur.fetchone()

    def update_transfer_request_status(self, transfer_request_id: UUID, status: str) -> None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE TRANSFER_REQUEST SET status = %s WHERE id = %s;",
                    (status, str(transfer_request_id)),
                )
                conn.commit()

    def insert_policy_decision(
        self,
        company_id: UUID,
        entity_id: UUID,
        canonical_schema_id: UUID,
        transfer_request_id: Optional[UUID],
        decision: str,
        decision_features: dict,
        model_name: str = "rule_based_engine",
        model_version: str = "v1",
    ) -> UUID:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    UPDATE POLICY_DECISION SET is_current = false
                    WHERE entity_id = %s AND is_current = true;
                    """,
                    (str(entity_id),),
                )
                cur.execute(
                    """
                    INSERT INTO POLICY_DECISION
                        (company_id, entity_id, canonical_schema_id, transfer_request_id,
                         model_name, model_version, decision_features, decision, is_current)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, true)
                    RETURNING id;
                    """,
                    (
                        str(company_id), str(entity_id), str(canonical_schema_id),
                        str(transfer_request_id) if transfer_request_id else None,
                        model_name, model_version, json.dumps(decision_features), decision,
                    ),
                )
                row = cur.fetchone()
                conn.commit()
                return row["id"]

    def get_policy_decision(self, policy_decision_id: UUID) -> Optional[dict]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT id, company_id, entity_id, canonical_schema_id,
                           transfer_request_id, decision, decision_features
                    FROM POLICY_DECISION WHERE id = %s;
                    """,
                    (str(policy_decision_id),),
                )
                return cur.fetchone()

    def get_current_policy_decision_for_transfer(self, transfer_request_id: UUID) -> Optional[dict]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT * FROM POLICY_DECISION
                    WHERE transfer_request_id = %s AND is_current = true
                    ORDER BY decided_at DESC LIMIT 1;
                    """,
                    (str(transfer_request_id),),
                )
                return cur.fetchone()

    # ============================================================
    # Human review (Step 10)
    # ============================================================

    def upsert_user_account(
        self, company_id: UUID, name: str, email: str, password_hash: str
    ) -> UUID:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO USER_ACCOUNT (company_id, name, email, password_hash)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (email) DO UPDATE
                        SET name = EXCLUDED.name
                    RETURNING id;
                    """,
                    (str(company_id), name, email, password_hash),
                )
                row = cur.fetchone()
                conn.commit()
                return row["id"]

    def create_authorization_request(
        self, company_id: UUID, policy_decision_id: UUID, reason: str, expires_in_days: int = 30
    ) -> UUID:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO AUTHORIZATION_REQUEST
                        (company_id, policy_decision_id, reason, status, expires_at)
                    VALUES (%s, %s, %s, 'PENDING', now() + (%s || ' days')::interval)
                    RETURNING id;
                    """,
                    (str(company_id), str(policy_decision_id), reason, expires_in_days),
                )
                row = cur.fetchone()
                conn.commit()
                return row["id"]

    def list_pending_authorization_requests(self, company_id: UUID) -> list[dict]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT
                        ar.id AS authorization_request_id, ar.reason, ar.expires_at,
                        pd.id AS policy_decision_id, pd.decision_features,
                        e.id AS entity_id, e.name AS entity_name, e.entity_type
                    FROM AUTHORIZATION_REQUEST ar
                    JOIN POLICY_DECISION pd ON ar.policy_decision_id = pd.id
                    JOIN ENTITY e ON pd.entity_id = e.id
                    WHERE ar.company_id = %s AND ar.status = 'PENDING' AND ar.expires_at > now()
                    ORDER BY ar.decision_at NULLS FIRST, pd.decided_at ASC;
                    """,
                    (str(company_id),),
                )
                return cur.fetchall()

    def get_authorization_request(self, authorization_request_id: UUID) -> Optional[dict]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT * FROM AUTHORIZATION_REQUEST WHERE id = %s;",
                    (str(authorization_request_id),),
                )
                return cur.fetchone()

    def get_authorization_request_by_policy_decision(self, policy_decision_id: UUID) -> Optional[dict]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT * FROM AUTHORIZATION_REQUEST
                    WHERE policy_decision_id = %s
                    ORDER BY decision_at DESC NULLS FIRST LIMIT 1;
                    """,
                    (str(policy_decision_id),),
                )
                return cur.fetchone()

    def resolve_authorization_request(
        self,
        authorization_request_id: UUID,
        reviewer_user_id: UUID,
        approve: bool,
        cndp_reference: Optional[str] = None,
    ) -> bool:
        """
        Race-condition-safe via a conditional UPDATE -- see Step 10's
        reasoning: the WHERE clause only matches a row still PENDING
        and unexpired at execution time; rowcount tells the caller
        whether THIS call was the one that won the race.
        """
        new_status = "APPROVED" if approve else "REJECTED"
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    UPDATE AUTHORIZATION_REQUEST
                    SET status = %s, reviewed_by = %s, decision_at = now(), cndp_reference = %s
                    WHERE id = %s AND status = 'PENDING' AND expires_at > now();
                    """,
                    (new_status, str(reviewer_user_id), cndp_reference, str(authorization_request_id)),
                )
                conn.commit()
                return cur.rowcount == 1

    # ============================================================
    # Deployment actions (Step 11)
    # ============================================================

    def insert_deployment_action(
        self,
        company_id: UUID,
        policy_decision_id: UUID,
        target_region_id: Optional[UUID],
        mode: str,
        status: str,
        executed_by: Optional[UUID],
        log_ref: Optional[str],
    ) -> UUID:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO DEPLOYMENT_ACTION
                        (company_id, policy_decision_id, target_region_id, mode,
                         status, executed_at, executed_by, log_ref)
                    VALUES (%s, %s, %s, %s, %s, now(), %s, %s)
                    RETURNING id;
                    """,
                    (
                        str(company_id), str(policy_decision_id),
                        str(target_region_id) if target_region_id else None,
                        mode, status,
                        str(executed_by) if executed_by else None,
                        log_ref,
                    ),
                )
                row = cur.fetchone()
                conn.commit()
                return row["id"]

    # ============================================================
    # Legal knowledge base (Step 12)
    # ============================================================

    def upsert_law_document(self, name: str, version: str, country: str, issuing_authority: str) -> UUID:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO LAW_DOCUMENT (name, version, country, issuing_authority)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (name, version) DO UPDATE
                        SET issuing_authority = EXCLUDED.issuing_authority
                    RETURNING id;
                    """,
                    (name, version, country, issuing_authority),
                )
                row = cur.fetchone()
                conn.commit()
                return row["id"]

    def upsert_law_clause(
        self, law_document_id: UUID, article_number: str, content: str, policy_reference_code: str
    ) -> UUID:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO LAW_CLAUSE (law_document_id, article_number, content, policy_reference_code)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (policy_reference_code) DO UPDATE
                        SET content = EXCLUDED.content
                    RETURNING id;
                    """,
                    (str(law_document_id), article_number, content, policy_reference_code),
                )
                row = cur.fetchone()
                conn.commit()
                return row["id"]

    def get_law_clause_by_reference(self, policy_reference: str) -> Optional[dict]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT lc.id, lc.article_number, lc.content, ld.name AS law_name
                    FROM LAW_CLAUSE lc
                    JOIN LAW_DOCUMENT ld ON lc.law_document_id = ld.id
                    WHERE lc.policy_reference_code = %s;
                    """,
                    (policy_reference,),
                )
                return cur.fetchone()

    def insert_classification_evidence(
        self, policy_decision_id: UUID, law_clause_id: UUID, triggered_by: str
    ) -> UUID:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO CLASSIFICATION_EVIDENCE
                        (policy_decision_id, law_clause_id, triggered_by, status)
                    VALUES (%s, %s, %s, 'ACTIVE')
                    RETURNING id;
                    """,
                    (str(policy_decision_id), str(law_clause_id), triggered_by),
                )
                row = cur.fetchone()
                conn.commit()
                return row["id"]

    def reconstruct_decision(self, policy_decision_id: UUID) -> Optional[dict]:
        """
        The audit-trail query. NOTE (fixed per Step 15.6): pd.company_id
        is now explicitly selected so callers can enforce tenant
        isolation on this endpoint -- it was missing before, which
        left /policy-decisions/{id}/audit without a real ownership
        check despite auth being wired everywhere else.
        """
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT
                        pd.id AS policy_decision_id,
                        pd.company_id AS decision_company_id,
                        pd.decision, pd.decision_features, pd.model_name,
                        pd.model_version, pd.decided_at,
                        c.name AS company_name, c.is_oiv, c.qualified_provider_required,
                        e.name AS entity_name, e.entity_type,
                        cs.payload AS canonical_schema_payload, cs.generated_at AS canonical_schema_generated_at,
                        tr.operation, tr.source_country, tr.destination_country, tr.destination_deployment_type,
                        ar.status AS authorization_status, ar.reviewed_by,
                        ar.decision_at AS review_decided_at, ar.cndp_reference,
                        lc.article_number, lc.content AS law_clause_content, ld.name AS law_name
                    FROM POLICY_DECISION pd
                    JOIN COMPANY c ON pd.company_id = c.id
                    JOIN ENTITY e ON pd.entity_id = e.id
                    JOIN CANONICAL_SCHEMA cs ON pd.canonical_schema_id = cs.id
                    LEFT JOIN TRANSFER_REQUEST tr ON pd.transfer_request_id = tr.id
                    LEFT JOIN AUTHORIZATION_REQUEST ar ON ar.policy_decision_id = pd.id
                    LEFT JOIN CLASSIFICATION_EVIDENCE ce ON ce.policy_decision_id = pd.id
                    LEFT JOIN LAW_CLAUSE lc ON ce.law_clause_id = lc.id
                    LEFT JOIN LAW_DOCUMENT ld ON lc.law_document_id = ld.id
                    WHERE pd.id = %s;
                    """,
                    (str(policy_decision_id),),
                )
                return cur.fetchone()

    def generate_compliance_evidence_pack(
        self, company_id: UUID, generated_by: UUID, period_start: str, period_end: str
    ) -> UUID:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO COMPLIANCE_EVIDENCE_PACK (company_id, generated_by, period_start, period_end)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id;
                    """,
                    (str(company_id), str(generated_by), period_start, period_end),
                )
                pack_id = cur.fetchone()["id"]
                cur.execute(
                    """
                    INSERT INTO COMPLIANCE_EVIDENCE_ITEM (pack_id, policy_decision_id, entity_type, entity_id)
                    SELECT %s, pd.id, e.entity_type, e.id
                    FROM POLICY_DECISION pd
                    JOIN ENTITY e ON pd.entity_id = e.id
                    WHERE pd.company_id = %s
                      AND pd.decided_at::date BETWEEN %s AND %s
                      AND pd.is_current = true;
                    """,
                    (str(pack_id), str(company_id), period_start, period_end),
                )
                conn.commit()
                return pack_id

    def get_evidence_pack_items(self, pack_id: UUID) -> list[dict]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    "SELECT policy_decision_id FROM COMPLIANCE_EVIDENCE_ITEM WHERE pack_id = %s;",
                    (str(pack_id),),
                )
                return cur.fetchall()

    # ============================================================
    # Auth (Step 15)
    # ============================================================

    def get_user_by_email(self, email: str) -> Optional[dict]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT * FROM USER_ACCOUNT WHERE email = %s;", (email,))
                return cur.fetchone()

    def get_user_roles(self, user_id: UUID) -> list[str]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT r.name FROM ROLE r
                    JOIN USER_ROLE ur ON ur.role_id = r.id
                    WHERE ur.user_id = %s;
                    """,
                    (str(user_id),),
                )
                return [row["name"] for row in cur.fetchall()]

    def assign_role(self, user_id: UUID, role_name: str) -> None:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT id FROM ROLE WHERE name = %s;", (role_name,))
                role = cur.fetchone()
                if role is None:
                    raise ValueError(f"Unknown role: {role_name}")
                cur.execute(
                    """
                    INSERT INTO USER_ROLE (user_id, role_id)
                    VALUES (%s, %s)
                    ON CONFLICT (user_id, role_id) DO NOTHING;
                    """,
                    (str(user_id), role["id"]),
                )
                conn.commit()

    def create_api_key(self, company_id: UUID, name: str, key_hash: str, created_by: Optional[UUID]) -> UUID:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    INSERT INTO API_KEY (company_id, name, key_hash, created_by)
                    VALUES (%s, %s, %s, %s)
                    RETURNING id;
                    """,
                    (str(company_id), name, key_hash, str(created_by) if created_by else None),
                )
                row = cur.fetchone()
                conn.commit()
                return row["id"]

    def get_api_key(self, key_hash: str) -> Optional[dict]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute("SELECT * FROM API_KEY WHERE key_hash = %s;", (key_hash,))
                return cur.fetchone()

    def touch_api_key_last_used(self, api_key_id: UUID) -> None:
        with self._pool.connection() as conn:
            with conn.cursor() as cur:
                cur.execute("UPDATE API_KEY SET last_used_at = now() WHERE id = %s;", (str(api_key_id),))
                conn.commit()
                


    def list_recent_policy_decisions(self, company_id: UUID, limit: int = 25) -> list[dict]:
        with self._pool.connection() as conn:
            with conn.cursor(row_factory=dict_row) as cur:
                cur.execute(
                    """
                    SELECT
                        pd.id AS policy_decision_id, pd.decision, pd.decided_at, pd.model_name,
                        e.name AS entity_name, e.entity_type,
                        tr.destination_country, tr.destination_deployment_type
                    FROM POLICY_DECISION pd
                    JOIN ENTITY e ON pd.entity_id = e.id
                    LEFT JOIN TRANSFER_REQUEST tr ON pd.transfer_request_id = tr.id
                    WHERE pd.company_id = %s AND pd.is_current = true
                    ORDER BY pd.decided_at DESC
                    LIMIT %s;
                    """,
                    (str(company_id), limit),
                )
                return cur.fetchall()

                