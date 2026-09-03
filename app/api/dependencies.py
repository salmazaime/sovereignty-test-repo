"""
FastAPI dependency-injection providers. Route handlers ask for these
by type annotation (see routes.py) instead of reaching into
app.state directly — this indirection is what makes route handlers
easy to unit-test later: in a test, you can swap in a fake repository
without touching the route code at all.
"""

from fastapi import Request

from app.db.repository import PostgresRepository
from app.graph.repository import GraphRepository


def get_postgres_repo(request: Request) -> PostgresRepository:
    return request.app.state.postgres_repo


def get_graph_repo(request: Request) -> GraphRepository:
    return request.app.state.graph_repo
    