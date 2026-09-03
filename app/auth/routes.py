import logging
import os

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr

from app.auth.dependencies import get_postgres_repo_for_auth
from app.auth.security import ACCESS_TOKEN_EXPIRE_MINUTES, create_access_token, verify_password
from app.db.repository import PostgresRepository

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in_minutes: int = ACCESS_TOKEN_EXPIRE_MINUTES
    roles: list[str] = [] 




@router.post("/login", response_model=TokenResponse)
def login(
    body: LoginRequest,
    postgres_repo: PostgresRepository = Depends(get_postgres_repo_for_auth),
) -> TokenResponse:
    user = postgres_repo.get_user_by_email(body.email)

    invalid_credentials = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid email or password."
    )
    if user is None:
        raise invalid_credentials
    if not verify_password(body.password, user["password_hash"]):
        raise invalid_credentials

    secret = os.environ.get("JWT_SECRET_KEY")
    if not secret:
        logger.error("JWT_SECRET_KEY not set -- cannot issue tokens.")
        raise HTTPException(status_code=500, detail="Server authentication is misconfigured.")

    roles = postgres_repo.get_user_roles(user["id"])
    token = create_access_token(
        subject_user_id=str(user["id"]), company_id=str(user["company_id"]),
        roles=roles, secret_key=secret,
    )
    return TokenResponse(access_token=token, roles=roles)
    
    