"""
The pure decision engine. Deliberately has ZERO database or network
calls — it's a pure function: same inputs always produce the same
output. This is what makes it trivially unit-testable (see tests/)
and, more importantly, what makes it AUDITABLE: given any past
decision's inputs, you can re-run this function and get the exact
same answer, which matters a great deal when a decision needs to be
defended to CNDP or an internal auditor later.
"""

from dataclasses import dataclass
from enum import Enum

from app.policy.lookup_tables import AdequacyTable, QualifiedProviderTable
from app.schemas import ResidencyLock


class DecisionOutcome(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVIEW = "REVIEW"


@dataclass(frozen=True)
class DecisionInput:
    residency_lock: ResidencyLock
    qualified_provider_required: bool  # from COMPANY.qualified_provider_required
    destination_cloud: str
    destination_region: str
    destination_country: str


@dataclass(frozen=True)
class DecisionResult:
    outcome: DecisionOutcome
    reason_code: str
    policy_reference: str


def decide_transfer(
    decision_input: DecisionInput,
    adequacy_table: AdequacyTable,
    qualified_provider_table: QualifiedProviderTable,
) -> DecisionResult:
    """
    Implements the two-gate logic we designed earlier in this
    conversation:

    Gate 1 (Axis 3 — residency lock): if the asset is locked to
    Morocco, OR the owning company requires a qualified provider for
    ANY of its data, the destination must appear on the qualified-
    provider table. This check happens FIRST and, if it fails, no
    amount of country-adequacy standing can override it — this is
    what makes it a hard gate rather than a weighted signal, exactly
    as we designed classification.residency_lock to behave.

    Gate 2 (Axis 4 — transfer eligibility): only reached if Gate 1
    doesn't apply. Checks the destination country against the CNDP
    adequacy list.
    """
    requires_sovereign_hosting = (
        decision_input.residency_lock != ResidencyLock.NONE
        or decision_input.qualified_provider_required
    )

    if requires_sovereign_hosting:
        is_qualified = qualified_provider_table.is_qualified(
            decision_input.destination_cloud, decision_input.destination_region
        )
        if is_qualified:
            return DecisionResult(
                outcome=DecisionOutcome.ALLOW,
                reason_code="qualified_sovereign_provider",
                policy_reference="decree_2.24.921",
            )
        return DecisionResult(
            outcome=DecisionOutcome.DENY,
            reason_code="no_sovereign_region_available",
            policy_reference=(
                "art_11_loi_05-20"
                if decision_input.residency_lock == ResidencyLock.SENSITIVE_HOSTING_REQUIRED
                else "decree_2.24.921"
            ),
        )

    # Gate 2: ordinary Axis 4 transfer eligibility.
    if adequacy_table.is_adequate(decision_input.destination_country):
        return DecisionResult(
            outcome=DecisionOutcome.ALLOW,
            reason_code="destination_on_adequacy_list",
            policy_reference="art_43_loi_09-08",
        )

    # Not on the adequate list: MVP scope treats this as REVIEW, not
    # an automatic DENY — a derogation (consent, contract necessity,
    # etc.) or CNDP authorization might still apply, and that's a
    # judgment call for a human, not something this engine should
    # decide alone. This is a deliberate, documented scope limit —
    # see Step-9 notes below for what a fuller version would add.
    return DecisionResult(
        outcome=DecisionOutcome.REVIEW,
        reason_code="destination_not_on_adequacy_list",
        policy_reference="art_43_loi_09-08",
    )
    