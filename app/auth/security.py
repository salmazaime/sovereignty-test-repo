# app/auth/security.py
"""
Password hashing and JWT issuance/verification. Zero FastAPI or
database imports -- same "pure core, thin framework wrapper" split
as app/policy/engine.py: security-critical logic must be testable
without spinning up the whole app or a real HTTP request.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt
from passlib.context import CryptContext

logger = logging.getLogger(__name__)

_pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 480  # 8 hours -- a work-day session, not a permanent one


def hash_password(plain_password: str) -> str:
    return _pwd_context.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """
    Never raises. A malformed stored hash (e.g. the literal string
    'PLACEHOLDER_UNTIL_STEP_15' left over from Step 10's seed script)
    fails closed as "no match" rather than crashing the login route.
    """
    try:
        return _pwd_context.verify(plain_password, password_hash)
    except ValueError:
        logger.warning("Stored password hash is malformed -- treating verification as failed.")
        return False


def create_access_token(
    subject_user_id: str,
    company_id: str,
    roles: list[str],
    secret_key: str,
    expires_delta: timedelta | None = None,
) -> str:
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    payload: dict[str, Any] = {
        "sub": subject_user_id,
        "company_id": company_id,
        "roles": roles,
        "exp": expire,
        "iat": datetime.now(timezone.utc),
    }
    return jwt.encode(payload, secret_key, algorithm=JWT_ALGORITHM)


class TokenValidationError(Exception):
    pass


def decode_access_token(token: str, secret_key: str) -> dict:
    """
    Raises TokenValidationError (never a raw jwt exception) so callers
    -- specifically the FastAPI dependency in 15.4 -- have exactly
    one exception type to catch, regardless of WHICH way the token
    was invalid (expired, tampered signature, malformed structure).
    """
    try:
        return jwt.decode(token, secret_key, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError as exc:
        raise TokenValidationError("Token has expired.") from exc
    except jwt.InvalidTokenError as exc:
        raise TokenValidationError(f"Invalid token: {exc}") from exc
        