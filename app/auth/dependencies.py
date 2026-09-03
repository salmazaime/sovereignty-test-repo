"""
FastAPI-specific auth dependencies -- thin wrappers around the pure
functions in security.py/api_keys.py. Kept in a separate file from
those so the actual crypto logic has zero framework coupling.
"""

import logging
import os
from dataclasses import dataclass

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from app.auth.api_keys import hash_api_key
from app.auth.security import TokenValidationError, decode_access_token
from app.db.repository import PostgresRepository
from app.observability.context import set_company_id


logger = logging.getLogger(__name__)

_bearer_scheme = HTTPBearer(auto_error=False)


def _jwt_secret() -> str:
    secret = os.environ.get("JWT_SECRET_KEY")
    if not secret:
        # Fail LOUD at request time, same "no silent None default"
        # principle as app/config.py's os.environ[...] usage since
        # Step 5 -- a missing secret must never quietly disable auth.
        raise RuntimeError("JWT_SECRET_KEY is not set -- refusing to issue or validate tokens.")
    return secret


@dataclass(frozen=True)
class AuthenticatedUser:
    user_id: str
    company_id: str
    roles: list[str]


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> AuthenticatedUser:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token.")
    try:
        payload = decode_access_token(credentials.credentials, _jwt_secret())
    except TokenValidationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    return AuthenticatedUser(
        user_id=payload["sub"], company_id=payload["company_id"], roles=payload.get("roles", []),
    )


def require_role(*allowed_roles: str):
    """
    A dependency FACTORY -- called with specific role names at route-
    definition time (e.g. `Depends(require_role("admin"))`), returning
    a fresh dependency function closed over those roles. This is the
    standard FastAPI pattern for parameterized authorization checks --
    without it, you'd need a separate hardcoded dependency function
    per distinct role combination.
    """
    def _checker(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if not set(user.roles) & set(allowed_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"This action requires one of these roles: {allowed_roles}.",
            )
        return user
    return _checker


def get_postgres_repo_for_auth(request: Request) -> PostgresRepository:
    # Reuses the SAME app.state.postgres_repo wired up in Step 8's
    # lifespan -- one connection pool for the whole app, not a second.
    return request.app.state.postgres_repo


def require_api_key(
    x_api_key: str | None = Header(default=None),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo_for_auth),
) -> str:
    """
    Returns the authenticated company_id (as a string). Protects
    machine-to-machine endpoints -- interceptors and discovery
    connectors have no human session to present a JWT for.
    """
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-API-Key header.")

    record = postgres_repo.get_api_key(hash_api_key(x_api_key))
    if record is None or record["revoked"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked API key.")

    postgres_repo.touch_api_key_last_used(record["id"])
    return str(record["company_id"])


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
) -> AuthenticatedUser:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token.")
    try:
        payload = decode_access_token(credentials.credentials, _jwt_secret())
    except TokenValidationError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc

    set_company_id(payload["company_id"])   # NEW -- now visible in every subsequent log line
    return AuthenticatedUser(
        user_id=payload["sub"], company_id=payload["company_id"], roles=payload.get("roles", []),
    )


def require_api_key(
    x_api_key: str | None = Header(default=None),
    postgres_repo: PostgresRepository = Depends(get_postgres_repo_for_auth),
) -> str:
    if not x_api_key:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing X-API-Key header.")

    record = postgres_repo.get_api_key(hash_api_key(x_api_key))
    if record is None or record["revoked"]:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or revoked API key.")

    postgres_repo.touch_api_key_last_used(record["id"])
    set_company_id(str(record["company_id"]))   # NEW
    return str(record["company_id"])
    