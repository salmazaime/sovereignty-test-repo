"""
Thin wrapper around a psycopg connection pool.

Why a POOL and not a single connection (unlike GraphClient, which
wraps a single driver instance)? Postgres connections are relatively
expensive to open. A pool keeps a small set of connections open and
hands them out/returns them as needed — this is standard practice
for any service that will handle more than one request at a time,
and it's the detail that separates "toy script" from "service that
could actually sit behind an API."
"""

import logging
from types import TracebackType
from typing import Optional, Type

from psycopg_pool import ConnectionPool

from app.config import PostgresConfig

logger = logging.getLogger(__name__)


class PostgresClient:
    def __init__(self, config: PostgresConfig, min_size: int = 1, max_size: int = 5) -> None:
        self._config = config
        self._min_size = min_size
        self._max_size = max_size
        self._pool: Optional[ConnectionPool] = None

    def __enter__(self) -> "PostgresClient":
        conninfo = (
            f"host={self._config.host} "
            f"port={self._config.port} "
            f"user={self._config.user} "
            f"password={self._config.password} "
            f"dbname={self._config.database}"
        )
        self._pool = ConnectionPool(
            conninfo=conninfo,
            min_size=self._min_size,
            max_size=self._max_size,
            open=True,
        )
        # Fails fast, same rationale as GraphClient.verify_connectivity().
        self._pool.wait(timeout=10)
        logger.info(
            "Connected to Postgres at %s:%s/%s",
            self._config.host, self._config.port, self._config.database,
        )
        return self

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        if self._pool is not None:
            self._pool.close()
            logger.info("Postgres connection pool closed")

    @property
    def pool(self) -> ConnectionPool:
        if self._pool is None:
            raise RuntimeError(
                "PostgresClient must be used as a context manager: "
                "'with PostgresClient(config) as client: ...'"
            )
        return self._pool
        