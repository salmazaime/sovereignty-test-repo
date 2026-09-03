"""
Repository layer for the knowledge graph.

This is the ONLY file in the project allowed to contain Cypher
queries. Keeping all queries in one place (a "repository" pattern)
means if you ever need to change how a query works, there's exactly
one place to look — not queries scattered across every script that
happens to need graph data.
"""

import logging
from typing import Any

from neo4j import Driver, ManagedTransaction

logger = logging.getLogger(__name__)


class GraphRepository:
    def __init__(self, driver: Driver) -> None:
        self._driver = driver

    def upsert_asset(
        self,
        entity_id: str,
        name: str,
        resource_type: str,
    ) -> None:
        """
        Create the Asset node if it doesn't exist, or update its
        properties if it does. Safe to call on every discovery scan
        without creating duplicates.
        """
        with self._driver.session() as session:
            session.execute_write(
                self._upsert_asset_tx, entity_id, name, resource_type
            )

    @staticmethod
    def _upsert_asset_tx(
        tx: ManagedTransaction, entity_id: str, name: str, resource_type: str
    ) -> None:
        tx.run(
            """
            MERGE (a:Asset {entity_id: $entity_id})
            SET a.name = $name,
                a.resource_type = $resource_type,
                a.last_seen_at = datetime()
            """,
            entity_id=entity_id,
            name=name,
            resource_type=resource_type,
        )

    def upsert_workload(
        self,
        entity_id: str,
        name: str,
        resource_type: str,
    ) -> None:
        with self._driver.session() as session:
            session.execute_write(
                self._upsert_workload_tx, entity_id, name, resource_type
            )

    @staticmethod
    def _upsert_workload_tx(
        tx: ManagedTransaction, entity_id: str, name: str, resource_type: str
    ) -> None:
        tx.run(
            """
            MERGE (w:Workload {entity_id: $entity_id})
            SET w.name = $name,
                w.resource_type = $resource_type,
                w.last_seen_at = datetime()
            """,
            entity_id=entity_id,
            name=name,
            resource_type=resource_type,
        )

    def link_depends_on(
        self,
        from_entity_id: str,
        to_entity_id: str,
        confidence: float,
    ) -> None:
        """
        Create (or refresh) a DEPENDS_ON edge between two already-
        existing entities, identified by their entity_id — which
        must match the ENTITY.id UUID in Postgres.
        """
        with self._driver.session() as session:
            session.execute_write(
                self._link_depends_on_tx, from_entity_id, to_entity_id, confidence
            )

    @staticmethod
    def _link_depends_on_tx(
        tx: ManagedTransaction,
        from_entity_id: str,
        to_entity_id: str,
        confidence: float,
    ) -> None:
        tx.run(
            """
            MATCH (from_node {entity_id: $from_id})
            MATCH (to_node {entity_id: $to_id})
            MERGE (from_node)-[r:DEPENDS_ON]->(to_node)
            SET r.confidence = $confidence,
                r.updated_at = datetime()
            """,
            from_id=from_entity_id,
            to_id=to_entity_id,
            confidence=confidence,
        )

    def get_impact_radius(
        self, entity_id: str, max_hops: int = 3
    ) -> list[dict[str, Any]]:
        """
        Return every node reachable within `max_hops` of the given
        entity, following DEPENDS_ON or DEPLOYED_IN relationships in
        either direction. This is the query that answers: "if this
        entity is sensitive, what else inherits that sensitivity?"
        """
        with self._driver.session() as session:
            return session.execute_read(
                self._get_impact_radius_tx, entity_id, max_hops
            )

    @staticmethod
    def _get_impact_radius_tx(
        tx: ManagedTransaction, entity_id: str, max_hops: int
    ) -> list[dict[str, Any]]:
        result = tx.run(
            """
            MATCH (start {entity_id: $entity_id})
            MATCH (start)-[:DEPENDS_ON|DEPLOYED_IN*1..%d]-(connected)
            RETURN DISTINCT connected.entity_id AS entity_id,
                             connected.name AS name,
                             labels(connected) AS labels
            """
            % max_hops,
            entity_id=entity_id,
        )
        return [dict(record) for record in result]
        