"""
Resolves the CURRENT effective status of a transfer request, handling
the one case that needs active logic rather than a straight lookup:
an expired, unresolved AUTHORIZATION_REQUEST. Kept pure (no I/O) for
the same reason app/policy/engine.py is pure — testability and
auditability.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum


class EffectiveStatus(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    REVIEW_PENDING = "REVIEW_PENDING"


@dataclass(frozen=True)
class StatusResolution:
    effective_status: EffectiveStatus
    reason: str
    requires_status_update: bool  # True if the caller must persist a change


def resolve_transfer_status(
    transfer_request_status: str,
    authorization_request: dict | None,
    now: datetime | None = None,
) -> StatusResolution:
    """
    transfer_request_status: the TRANSFER_REQUEST.status value as
        currently stored (e.g. 'REVIEW_PENDING').
    authorization_request: the linked AUTHORIZATION_REQUEST row, or
        None if this transfer never needed one (i.e. it was decided
        ALLOW/DENY outright by the engine, no human review involved).
    """
    now = now or datetime.now(timezone.utc)

    if transfer_request_status == "ALLOWED":
        return StatusResolution(EffectiveStatus.ALLOWED, "engine_or_review_allowed", False)
    if transfer_request_status == "DENIED":
        return StatusResolution(EffectiveStatus.DENIED, "engine_or_review_denied", False)

    if transfer_request_status != "REVIEW_PENDING":
        # PENDING, COMPLETED, ABORTED aren't meaningful "is this clear
        # to proceed" states — treat as not-yet-decided defensively
        # rather than guessing.
        return StatusResolution(EffectiveStatus.REVIEW_PENDING, "no_decision_yet", False)

    if authorization_request is None:
        # Defensive: REVIEW_PENDING with no linked authorization
        # request is an inconsistent state that shouldn't happen if
        # the rest of the system is correct — but if it does, fail
        # closed rather than assume anything.
        return StatusResolution(EffectiveStatus.DENIED, "inconsistent_state_no_authorization_request", True)

    if authorization_request["status"] == "APPROVED":
        return StatusResolution(EffectiveStatus.ALLOWED, "human_review_approved", True)
    if authorization_request["status"] == "REJECTED":
        return StatusResolution(EffectiveStatus.DENIED, "human_review_rejected", True)

    # Still PENDING at the AUTHORIZATION_REQUEST level — check expiry.
    if authorization_request["expires_at"] <= now:
        # THE fail-closed rule in code: silence past the deadline
        # resolves to DENIED, never ALLOWED.
        return StatusResolution(EffectiveStatus.DENIED, "authorization_request_expired", True)

    return StatusResolution(EffectiveStatus.REVIEW_PENDING, "awaiting_human_review", False)
    