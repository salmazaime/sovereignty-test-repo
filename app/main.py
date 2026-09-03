"""
FastAPI application entry point. Connections open ONCE at startup,
close ONCE at shutdown (Step 8's lifespan reasoning).
"""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.api.routes import router
from app.auth.routes import router as auth_router
from app.config import Neo4jConfig, PostgresConfig
from app.db.client import PostgresClient
from app.db.repository import PostgresRepository
from app.graph.client import GraphClient
from app.graph.repository import GraphRepository
from app.logging_setup import configure_logging
from app.observability.middleware import RequestContextMiddleware
from app.observability.routes import router as metrics_router
from fastapi.staticfiles import StaticFiles


logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()

    pg_config = PostgresConfig.from_env()
    neo_config = Neo4jConfig.from_env()

    pg_client = PostgresClient(pg_config).__enter__()
    graph_client = GraphClient(neo_config).__enter__()

    app.state.postgres_repo = PostgresRepository(pg_client.pool)
    app.state.graph_repo = GraphRepository(graph_client.driver)

    logger.info("Startup complete: Postgres and Neo4j connections established.")

    yield

    logger.info("Shutting down: closing database connections.")
    pg_client.__exit__(None, None, None)
    graph_client.__exit__(None, None, None)


app = FastAPI(
    title="Sovereign Data Classification Platform",
    version="0.1.0",
    lifespan=lifespan,
)
app.include_router(router)
app.include_router(auth_router)
app.add_middleware(RequestContextMiddleware)
app.include_router(metrics_router)
app.mount("/dashboard", StaticFiles(directory="app/static/dashboard", html=True), name="dashboard")

