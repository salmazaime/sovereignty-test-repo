"""
Thin wrapper around the official Neo4j Python driver.

Why wrap it at all, instead of using the driver directly everywhere?
Two reasons:
1. Connection lifecycle (open/close, verify_connectivity) should
   happen in exactly one place, not scattered across every script
   that touches the graph.
2. It gives you one seam to add things later (retry policy, metrics,
   query timeouts) without touching every call site.
"""

import logging
from types import TracebackType
from typing import Optional, Type

from neo4j import Driver, GraphDatabase

from app.config import Neo4jConfig

logger = logging.getLogger(__name__)


class GraphClient:
    """Context-manager wrapper around a Neo4j Driver instance."""

    def __init__(self, config: Neo4jConfig) -> None:
        self._config = config
        self._driver: Optional[Driver] = None

    def __enter__(self) -> "GraphClient":
        self._driver = GraphDatabase.driver(
            self._config.uri,
            auth=(self._config.user, self._config.password),
        )
        # Fails fast if Neo4j is unreachable or credentials are wrong,
        # instead of letting the first real query fail confusingly later.
        self._driver.verify_connectivity()
        logger.info("Connected to Neo4j at %s", self._config.uri)
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        if self._driver is not None:
            self._driver.close()
            logger.info("Neo4j connection closed")

    @property
    def driver(self) -> Driver:
        if self._driver is None:
            raise RuntimeError(
                "GraphClient must be used as a context manager: "
                "'with GraphClient(config) as client: ...'"
            )
        return self._driver
        