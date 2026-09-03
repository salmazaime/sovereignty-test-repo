"""
HTTP routes. Every state-changing or company-scoped endpoint requires
authentication (Step 15) -- either a human JWT with an appropriate
role, or a machine API key. Tenant isolation is enforced explicitly
on every route that touches company-owned data: the authenticated
identity's company_id/roles are compared against the resource's
actual owning company before any read or write proceeds.
"""

import logging
from pathlib import Path
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from app.observability.metrics import POLICY_DECISIONS_TOTAL
import time
from app.observability.metrics import INGESTION_DURATION_SECONDS, INGESTION_TOTAL


from app.api.dependencies import get_graph_repo, get_postgres_repo
from app.auth.dependencies import AuthenticatedUser, get_current_user, require_api_key, require_role
from app.db.repository import PostgresRepository
from app.graph.repository import GraphRepository
from app.ingestion.pipeline import GraphProjectionError, ingest_discovery_finding
from app.policy.engine import DecisionInput, DecisionOutcome, decide_transfer
from app.policy.lookup_tables import AdequacyTable, QualifiedProviderTable
from app.policy.status_resolution import EffectiveStatus, resolve_transfer_status
from app.schemas import (
    DecisionAuditRecord, DeploymentActionRequest, DeploymentActionResponse,
    EvidencePackRequest, EvidencePackResponse, HealthResponse, IngestionRequest,
    IngestionResponse, PendingReviewSummary, RecentDecisionSummary, ResidencyLock,
    ReviewResolution, ReviewResolutionResponse, TransferDecisionResponse,
    TransferRequestPayload, TransferStatusResponse,
)

logger = logging.getLogger(__name__)
router = APIRouter()

_ADEQUACY_TABLE = AdequacyTable.load(Path("config/cndp_adequacy_countries.json"))
_QUALIFIED_PROVIDER_TABLE = QualifiedProviderTable.load(Path("config/qualified_providers.json"))


# ============================================================
# Health (Step 8) -- no auth, this is a liveness/readiness probe
# ============================================================

@router.get("/health", response_model=HealthResponse, tags=["ops"])
def health_check(
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
    graph_repo: GraphRepository = Depends(get_graph_repo),
) -> HealthResponse:
    pg_status = "ok"
    neo_status = "ok"

    try:
        postgres_repo.get_entity_by_natural_key(
            company_id=UUID(int=0), entity_type="DATA_ASSET", name="__healthcheck__"
        )
    except Exception as exc:  # noqa: BLE001
        logger.error("Postgres health check failed: %s", exc)
        pg_status = "unreachable"

    try:
        graph_repo.get_impact_radius(entity_id="__healthcheck__", max_hops=1)
    except Exception as exc:  # noqa: BLE001
        logger.error("Neo4j health check failed: %s", exc)
        neo_status = "unreachable"

    response = HealthResponse(postgres=pg_status, neo4j=neo_status)
    if pg_status != "ok" or neo_status != "ok":
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=response.model_dump())
    return response


# ============================================================
# Ingestion (Step 7) -- machine auth (API key) + tenant check
# ============================================================

@router.post("/ingest", response_model=IngestionResponse, status_code=status.HTTP_201_CREATED, tags=["ingestion"])
def ingest(
    request: IngestionRequest,
    authenticated_company_id: str = Depends(require_api_key),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
    graph_repo: GraphRepository = Depends(get_graph_repo),
) -> IngestionResponse:
    company = postgres_repo.get_company_profile(UUID(authenticated_company_id))
    if company is None or company["name"] != request.company_name:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated API key does not match the company in the request payload.",
        )

    try:
        entity_id = ingest_discovery_finding(postgres_repo, graph_repo, request)
    except GraphProjectionError as exc:
        logger.error("Partial ingestion failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_207_MULTI_STATUS,
            detail={
                "message": "Entity persisted to Postgres; graph projection failed and needs retry.",
                "entity_id": str(exc.entity_id),
            },
        ) from exc
    except Exception as exc:  # noqa: BLE001
        logger.error("Total ingestion failure: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Ingestion failed before any data was persisted.",
        ) from exc

    return IngestionResponse(entity_id=str(entity_id), status="ingested")


# ============================================================
# Transfer requests / decisions (Step 9) -- machine auth + tenant check
# ============================================================

@router.post("/transfer-request", response_model=TransferDecisionResponse, status_code=status.HTTP_201_CREATED, tags=["policy"])
def transfer_request(
    body: TransferRequestPayload,
    authenticated_company_id: str = Depends(require_api_key),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> TransferDecisionResponse:
    entity_uuid = UUID(body.entity_id)

    entity = postgres_repo.get_entity(entity_uuid)
    if entity is None:
        raise HTTPException(status_code=404, detail=f"Entity {body.entity_id} not found.")

    if str(entity.company_id) != authenticated_company_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This entity does not belong to the authenticated company.",
        )

    classification = postgres_repo.get_latest_classification(entity_uuid)
    if classification is None:
        raise HTTPException(
            status_code=409,
            detail=f"Entity {body.entity_id} has no canonical schema yet -- ingest it first.",
        )

    company = postgres_repo.get_company_profile(entity.company_id)
    canonical_schema_id = postgres_repo.get_latest_canonical_schema_id(entity_uuid)

    decision_input = DecisionInput(
        residency_lock=ResidencyLock(classification["residency_lock"]),
        qualified_provider_required=company["qualified_provider_required"],
        destination_cloud=body.destination_cloud,
        destination_region=body.destination_region,
        destination_country=body.destination_country,
    )
    result = decide_transfer(decision_input, _ADEQUACY_TABLE, _QUALIFIED_PROVIDER_TABLE)
    POLICY_DECISIONS_TOTAL.labels(outcome=result.outcome.value).inc()   

    transfer_request_id = postgres_repo.insert_transfer_request(
        company_id=entity.company_id,
        entity_id=entity_uuid,
        operation=body.operation,
        source_country=body.source_country,
        destination_country=body.destination_country,
        destination_deployment_type=body.destination_cloud,
        initiated_by=body.initiated_by,
        initiating_application=body.initiating_application,
    )

    policy_decision_id = postgres_repo.insert_policy_decision(
        company_id=entity.company_id,
        entity_id=entity_uuid,
        canonical_schema_id=canonical_schema_id,
        transfer_request_id=transfer_request_id,
        decision=result.outcome.value,
        decision_features={
            "reason_code": result.reason_code,
            "policy_reference": result.policy_reference,
            "destination_country": body.destination_country,
            "destination_cloud": body.destination_cloud,
        },
    )

    status_map = {
        DecisionOutcome.ALLOW: "ALLOWED",
        DecisionOutcome.DENY: "DENIED",
        DecisionOutcome.REVIEW: "REVIEW_PENDING",
    }
    postgres_repo.update_transfer_request_status(transfer_request_id, status_map[result.outcome])

    if result.outcome == DecisionOutcome.REVIEW:
        postgres_repo.create_authorization_request(
            company_id=entity.company_id,
            policy_decision_id=policy_decision_id,
            reason=result.reason_code,
        )

    law_clause = postgres_repo.get_law_clause_by_reference(result.policy_reference)
    if law_clause is not None:
        postgres_repo.insert_classification_evidence(
            policy_decision_id=policy_decision_id,
            law_clause_id=law_clause["id"],
            triggered_by=result.reason_code,
        )
    else:
        logger.warning(
            "No LAW_CLAUSE found for policy_reference=%s -- evidence link skipped.", result.policy_reference
        )

    return TransferDecisionResponse(
        transfer_request_id=str(transfer_request_id),
        policy_decision_id=str(policy_decision_id),
        outcome=result.outcome.value,
        reason_code=result.reason_code,
        policy_reference=result.policy_reference,
    )


@router.get("/transfer-request/{transfer_request_id}/status", response_model=TransferStatusResponse, tags=["policy"])
def get_transfer_status(
    transfer_request_id: UUID,
    authenticated_company_id: str = Depends(require_api_key),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> TransferStatusResponse:
    transfer = postgres_repo.get_transfer_request(transfer_request_id)
    if transfer is None:
        raise HTTPException(status_code=404, detail="Transfer request not found.")
    if str(transfer["company_id"]) != authenticated_company_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant mismatch.")

    current_decision = postgres_repo.get_current_policy_decision_for_transfer(transfer_request_id)
    authorization_request = None
    if current_decision is not None:
        authorization_request = postgres_repo.get_authorization_request_by_policy_decision(current_decision["id"])

    resolution = resolve_transfer_status(
        transfer_request_status=transfer["status"], authorization_request=authorization_request
    )

    if resolution.requires_status_update:
        new_status = "ALLOWED" if resolution.effective_status == EffectiveStatus.ALLOWED else "DENIED"
        postgres_repo.update_transfer_request_status(transfer_request_id, new_status)
        logger.info("Transfer %s status resolved to %s (%s)", transfer_request_id, new_status, resolution.reason)

    return TransferStatusResponse(
        transfer_request_id=str(transfer_request_id),
        effective_status=resolution.effective_status.value,
        reason=resolution.reason,
    )


# ============================================================
# Deployment actions (Step 11) -- machine auth + tenant check
# ============================================================

@router.post("/deployment-actions", response_model=DeploymentActionResponse, status_code=status.HTTP_201_CREATED, tags=["policy"])
def record_deployment_action(
    body: DeploymentActionRequest,
    authenticated_company_id: str = Depends(require_api_key),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> DeploymentActionResponse:
    transfer_id = UUID(body.transfer_request_id)
    transfer = postgres_repo.get_transfer_request(transfer_id)
    if transfer is None:
        raise HTTPException(status_code=404, detail="Transfer request not found.")
    if str(transfer["company_id"]) != authenticated_company_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Tenant mismatch.")

    current_decision = postgres_repo.get_current_policy_decision_for_transfer(transfer_id)
    if current_decision is None:
        raise HTTPException(status_code=409, detail="No policy decision exists yet for this transfer request.")

    authorization_request = postgres_repo.get_authorization_request_by_policy_decision(current_decision["id"])
    resolution = resolve_transfer_status(
        transfer_request_status=transfer["status"], authorization_request=authorization_request
    )

    if resolution.effective_status != EffectiveStatus.ALLOWED:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Refusing to record deployment: current effective status is "
                f"{resolution.effective_status.value} ({resolution.reason}), not ALLOWED."
            ),
        )

    deployment_action_id = postgres_repo.insert_deployment_action(
        company_id=transfer["company_id"],
        policy_decision_id=current_decision["id"],
        target_region_id=UUID(body.target_region_id) if body.target_region_id else None,
        mode=body.mode,
        status="EXECUTED",
        executed_by=UUID(body.executed_by) if body.executed_by else None,
        log_ref=body.log_ref,
    )
    postgres_repo.update_transfer_request_status(transfer_id, "COMPLETED")

    return DeploymentActionResponse(deployment_action_id=str(deployment_action_id), status="EXECUTED")


# ============================================================
# Human review (Step 10) -- human auth (JWT + role) + tenant check
# ============================================================

@router.get("/companies/{company_id}/reviews", response_model=list[PendingReviewSummary], tags=["policy"])
def list_reviews(
    company_id: UUID,
    user: AuthenticatedUser = Depends(require_role("compliance_reviewer", "admin")),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> list[PendingReviewSummary]:
    if str(company_id) != user.company_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot view another company's reviews.")

    rows = postgres_repo.list_pending_authorization_requests(company_id)
    return [
        PendingReviewSummary(
            authorization_request_id=str(r["authorization_request_id"]),
            reason=r["reason"],
            expires_at=r["expires_at"].isoformat(),
            entity_id=str(r["entity_id"]),
            entity_name=r["entity_name"],
            entity_type=r["entity_type"],
        )
        for r in rows
    ]


@router.post("/reviews/{authorization_request_id}/resolve", response_model=ReviewResolutionResponse, tags=["policy"])
def resolve_review(
    authorization_request_id: UUID,
    body: ReviewResolution,
    user: AuthenticatedUser = Depends(require_role("compliance_reviewer", "admin")),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> ReviewResolutionResponse:
    auth_request = postgres_repo.get_authorization_request(authorization_request_id)
    if auth_request is None:
        raise HTTPException(status_code=404, detail="Authorization request not found.")
    if str(auth_request["company_id"]) != user.company_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot resolve another company's review.")

    resolved = postgres_repo.resolve_authorization_request(
        authorization_request_id=authorization_request_id,
        reviewer_user_id=UUID(user.user_id),
        approve=body.approve,
        cndp_reference=body.cndp_reference,
    )

    if not resolved:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="This review was already resolved or has expired.",
        )

    policy_decision_id = auth_request["policy_decision_id"]
    original_decision = postgres_repo.get_policy_decision(policy_decision_id)
    final_outcome = DecisionOutcome.ALLOW if body.approve else DecisionOutcome.DENY

    new_decision_id = postgres_repo.insert_policy_decision(
        company_id=original_decision["company_id"],
        entity_id=original_decision["entity_id"],
        canonical_schema_id=original_decision["canonical_schema_id"],
        transfer_request_id=original_decision["transfer_request_id"],
        decision=final_outcome.value,
        decision_features={
            "reason_code": "human_review_resolution",
            "original_authorization_request_id": str(authorization_request_id),
            "cndp_reference": body.cndp_reference,
        },
        model_name="human_reviewer",
        model_version="n/a",
    )

    return ReviewResolutionResponse(
        authorization_request_id=str(authorization_request_id),
        resolved=True,
        new_policy_decision_id=str(new_decision_id),
        message=f"Review resolved as {final_outcome.value}.",
    )


# ============================================================
# Audit / compliance (Step 12) -- human auth
# ============================================================

@router.get("/policy-decisions/{policy_decision_id}/audit", response_model=DecisionAuditRecord, tags=["compliance"])
def get_decision_audit(
    policy_decision_id: UUID,
    user: AuthenticatedUser = Depends(get_current_user),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> DecisionAuditRecord:
    row = postgres_repo.reconstruct_decision(policy_decision_id)
    if row is None:
        raise HTTPException(status_code=404, detail="Policy decision not found.")

    # Tenant check -- NOW enforceable because reconstruct_decision's
    # query was fixed (Step 15.6 gap) to select pd.company_id.
    if str(row["decision_company_id"]) != user.company_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot view another company's decision.")

    return DecisionAuditRecord(
        policy_decision_id=str(row["policy_decision_id"]),
        decision=row["decision"],
        decision_features=row["decision_features"],
        model_name=row["model_name"],
        decided_at=row["decided_at"].isoformat(),
        company_name=row["company_name"],
        is_oiv=row["is_oiv"],
        entity_name=row["entity_name"],
        entity_type=row["entity_type"],
        canonical_schema_payload=row["canonical_schema_payload"],
        operation=row["operation"],
        destination_country=row["destination_country"],
        authorization_status=row["authorization_status"],
        cndp_reference=row["cndp_reference"],
        law_article=row["article_number"],
        law_content=row["law_clause_content"],
    )


@router.post("/compliance/evidence-packs", response_model=EvidencePackResponse, status_code=status.HTTP_201_CREATED, tags=["compliance"])
def create_evidence_pack(
    body: EvidencePackRequest,
    user: AuthenticatedUser = Depends(require_role("compliance_officer", "admin")),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> EvidencePackResponse:
    pack_id = postgres_repo.generate_compliance_evidence_pack(
        company_id=UUID(user.company_id),
        generated_by=UUID(user.user_id),
        period_start=body.period_start,
        period_end=body.period_end,
    )
    items = postgres_repo.get_evidence_pack_items(pack_id)
    return EvidencePackResponse(
        pack_id=str(pack_id),
        item_count=len(items),
        policy_decision_ids=[str(i["policy_decision_id"]) for i in items],
    )

@router.post("/ingest", response_model=IngestionResponse, status_code=status.HTTP_200_OK)
def ingest(
    request: IngestionRequest,
    authenticated_company_id: str = Depends(require_api_key),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
    graph_repo: GraphRepository = Depends(get_graph_repo),
) -> IngestionResponse:
    company = postgres_repo.get_company_profile(UUID(authenticated_company_id))
    if company is None or company["name"] != request.company_name:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="...")

    start = time.perf_counter()
    try:
        entity_id = ingest_discovery_finding(postgres_repo, graph_repo, request)
    except GraphProjectionError as exc:
        INGESTION_TOTAL.labels(result="partial").inc()
        INGESTION_DURATION_SECONDS.observe(time.perf_counter() - start)
        logger.error("Partial ingestion failure: %s", exc)
        raise HTTPException(status_code=status.HTTP_207_MULTI_STATUS, detail={...}) from exc
    except Exception as exc:  # noqa: BLE001
        INGESTION_TOTAL.labels(result="failure").inc()
        INGESTION_DURATION_SECONDS.observe(time.perf_counter() - start)
        logger.error("Total ingestion failure: %s", exc)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="...") from exc

    INGESTION_TOTAL.labels(result="success").inc()
    INGESTION_DURATION_SECONDS.observe(time.perf_counter() - start)
    return IngestionResponse(entity_id=str(entity_id), status="ingested")


@router.get(
        "/companies/{company_id}/decisions",
        response_model=list[RecentDecisionSummary],
        tags=["compliance"],
)
def list_recent_decisions(
        company_id: UUID,
        user: AuthenticatedUser = Depends(get_current_user),
        postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> list[RecentDecisionSummary]:
        if str(company_id) != user.company_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Cannot view another company's decisions.")

        rows = postgres_repo.list_recent_policy_decisions(company_id)
        return [
            RecentDecisionSummary(
                policy_decision_id=str(r["policy_decision_id"]),
                decision=r["decision"],
                decided_at=r["decided_at"].isoformat(),
                model_name=r["model_name"],
                entity_name=r["entity_name"],
                entity_type=r["entity_type"],
                destination_country=r["destination_country"],
            )
            for r in rows
        ]


