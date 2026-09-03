"""
Centralized application configuration.

Why this file exists: hardcoding connection details (hosts, ports,
passwords) inside business logic is the single most common reason
a project can't move from a developer's laptop to any other
environment. Every setting the app needs comes from environment
variables, loaded once, here, and nowhere else.
"""

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv()


@dataclass(frozen=True)
class Neo4jConfig:
    uri: str
    user: str
    password: str

    @classmethod
    def from_env(cls) -> "Neo4jConfig":
        host = os.environ.get("NEO4J_HOST", "localhost")
        port = os.environ.get("NEO4J_BOLT_PORT", "7687")
        uri = f"bolt://{host}:{port}"
        user = os.environ.get("NEO4J_USER", "neo4j")
        password = os.environ.get("NEO4J_PASSWORD", "password")
        return cls(uri=uri, user=user, password=password)


@dataclass(frozen=True)
class PostgresConfig:
    host: str
    port: int
    user: str
    password: str
    database: str

    @classmethod
    def from_env(cls) -> "PostgresConfig":
        return cls(
            host=os.environ.get("POSTGRES_HOST", "localhost"),
            port=int(os.environ.get("POSTGRES_PORT", "5432")),
            user=os.environ.get("POSTGRES_USER", "postgres"),
            password=os.environ.get("POSTGRES_PASSWORD", "postgres"),
            database=os.environ.get("POSTGRES_DB", "atlas_cloud"),
        )
        