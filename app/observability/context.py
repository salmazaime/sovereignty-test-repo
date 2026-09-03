# app/observability/context.py
"""
Holds the "current request's" identifying info via contextvars --
NOT threading.local (see Step 16 introduction for why that would be
wrong under FastAPI's async model). Every module that logs can pull
the current request_id without it being explicitly passed down
through every function call -- the alternative (threading it through
every function signature) would pollute every layer of this project
with a parameter nothing but logging actually needs.
"""

import uuid
from contextvars import ContextVar

_request_id_var: ContextVar[str] = ContextVar("request_id", default="-")
_company_id_var: ContextVar[str] = ContextVar("company_id", default="-")


def generate_request_id() -> str:
    return str(uuid.uuid4())


def set_request_id(request_id: str) -> None:
    _request_id_var.set(request_id)


def get_request_id() -> str:
    return _request_id_var.get()


def set_company_id(company_id: str) -> None:
    _company_id_var.set(company_id)


def get_company_id() -> str:
    return _company_id_var.get()
    