"""
The orchestration layer: takes one IngestionRequest, writes to
Postgres (source of truth), then projects the result into Neo4j
(derived graph). See the module docstring in each repository for
why each database is queried the way it is.

Ordering is deliberate and load-bearing: Postgres write happens
FIRST, always. If it fails, we stop — nothing touches the graph.
If Postgres succeeds but the graph write fails, we log a specific,
actionable error and re-raise a typed exception so the caller can
decide whether to retry immediately or queue for later. Because
graph writes are idempotent (MERGE), a later retry is always safe.
"""

import logging
from uuid import UUID

from app.db.repository import PostgresRepository
from app.graph.repository import GraphRepository
from app.schemas import IngestionRequest

logger = logging.getLogger(__name__)


class GraphProjectionError(Exception):
    """
    Raised when the Postgres write succeeded but the Neo4j write
    failed. Distinct exception type on purpose: the caller needs to
    know this is a PARTIAL failure (data is safely persisted in the
    source of truth, just not yet reflected in the graph) as opposed
    to a total failure where nothing happened at all.
    """

    def __init__(self, entity_id: UUID, original_error: Exception) -> None:
        self.entity_id = entity_id
        self.original_error = original_error
        super().__init__(
            f"Postgres write for entity {entity_id} succeeded, but the "
            f"graph projection failed: {original_error}. The entity is "
            f"safely persisted; retry the graph sync for this entity_id."
        )


def ingest_discovery_finding(
    postgres_repo: PostgresRepository,
    graph_repo: GraphRepository,
    request: IngestionRequest,
) -> UUID:
    """
    Writes one discovery finding to both stores. Returns the
    Postgres entity_id, which is the same value used as the graph
    node's entity_id property — this shared identifier is what keeps
    the two databases logically linked despite having no enforced FK
    between them (per the ERD's cross-boundary reference notes).
    """
    # --- Step 1: Postgres (source of truth). Must succeed first. ---
    company_id = postgres_repo.upsert_company(
        name=request.company_name, sector=request.company_sector
    )
    entity_id = postgres_repo.upsert_entity(
        company_id=company_id,
        entity_type=request.entity_type.value,
        name=request.entity_name,
        business_owner=request.business_owner,
        environment=request.environment,
    )
    postgres_repo.insert_canonical_schema(
        company_id=company_id,
        entity_id=entity_id,
        phase=request.phase,
        plugin_used=request.plugin_used,
        payload=request.payload.model_dump(mode="json"),
        overall_confidence=request.overall_confidence,
    )
    logger.info("Postgres write complete for entity_id=%s (%s)", entity_id, request.entity_name)

    # --- Step 2: Neo4j (derived projection). Failure here is recoverable. ---
    try:
        _project_to_graph(postgres_repo, graph_repo, entity_id, request)
    except Exception as exc:  # noqa: BLE001 — intentionally broad: any graph
        # failure must be caught here so we can raise our typed error below,
        # rather than letting the caller see a raw driver/network exception.
        logger.error(
            "Graph projection failed for entity_id=%s: %s", entity_id, exc
        )
        raise GraphProjectionError(entity_id=entity_id, original_error=exc) from exc

    logger.info("Graph projection complete for entity_id=%s", entity_id)
    return entity_id


def _project_to_graph(
    postgres_repo: PostgresRepository,
    graph_repo: GraphRepository,
    entity_id: UUID,
    request: IngestionRequest,
) -> None:
    if request.entity_type == request.entity_type.DATA_ASSET:
        graph_repo.upsert_asset(
            entity_id=str(entity_id),
            name=request.entity_name,
            resource_type=request.payload.asset.resource_type,
        )
    else:
        graph_repo.upsert_workload(
            entity_id=str(entity_id),
            name=request.entity_name,
            resource_type=request.payload.asset.resource_type,
        )

    # Resolve each declared dependency to its Postgres entity_id, then
    # link it in the graph. If a dependency's target hasn't been
    # ingested yet, we skip it and log rather than fail the whole
    # operation — a dangling dependency reference shouldn't block
    # ingesting the entity that legitimately exists right now.
    for dep in request.dependencies:
        target = postgres_repo.get_entity_by_natural_key(
            company_id=postgres_repo.upsert_company(
                name=request.company_name, sector=request.company_sector
            ),
            entity_type=dep.target_entity_type.value,
            name=dep.target_entity_name,
        )
        if target is None:
            logger.warning(
                "Dependency target '%s' (%s) not found yet — skipping link, "
                "will need to be re-run once that entity is ingested.",
                dep.target_entity_name, dep.target_entity_type.value,
            )
            continue

        graph_repo.link_depends_on(
            from_entity_id=str(entity_id),
            to_entity_id=str(target.id),
            confidence=dep.confidence,
        )
        