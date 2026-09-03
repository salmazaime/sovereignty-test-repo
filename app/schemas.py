"""
Pydantic models: the validation boundary for everything entering
this system, from cloud connectors, the CI interceptor, and the API
itself. See Step 7's module docstring reasoning for why validation
lives here rather than trusting raw dicts anywhere downstream.
"""

from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, confloat


# ============================================================
# Enums (fixed, matching Loi 09-08 Art. 1 §4 categories exactly)
# ============================================================

class SensitivityCategory(str, Enum):
    NATIONAL_ID = "national_id"
    HEALTH = "health"
    GENETIC = "genetic"
    RACIAL_ETHNIC_ORIGIN = "racial_ethnic_origin"
    POLITICAL = "political"
    RELIGIOUS_PHILOSOPHICAL = "religious_philosophical"
    UNION = "union"
    CRIMINAL_RECORD_OR_SECURITY_MEASURE = "criminal_record_or_security_measure"
    ORDINARY_PII = "ordinary_pii"
    NONE = "none"


class ResidencyLock(str, Enum):
    NONE = "none"
    SENSITIVE_HOSTING_REQUIRED = "sensitive_hosting_required"
    OIV_HOSTING_REQUIRED = "oiv_hosting_required"


class EntityType(str, Enum):
    DATA_ASSET = "DATA_ASSET"
    WORKLOAD = "WORKLOAD"


# ============================================================
# Canonical schema payload (Step 7, extended in Step 13)
# ============================================================

class ContentFinding(BaseModel):
    category: SensitivityCategory
    field_or_location: str
    confidence: confloat(ge=0.0, le=1.0)
    detector: str


class NetworkingInfo(BaseModel):
    is_publicly_accessible: bool
    allowed_ip_ranges: list[str] = Field(default_factory=list)
    vpc_or_vnet_id: Optional[str] = None
    security_group_ids: list[str] = Field(default_factory=list)


class EncryptionInfo(BaseModel):
    at_rest_enabled: bool
    key_type: Optional[str] = None


class VendorAttestation(BaseModel):
    provider_name: str
    data_center_country: Optional[str] = None


class InfrastructureContext(BaseModel):
    account_id: str
    region: str
    resource_id: str
    networking: Optional[NetworkingInfo] = None
    encryption: Optional[EncryptionInfo] = None
    vendor_attestation: Optional[VendorAttestation] = None


class AssetInfo(BaseModel):
    granularity: str = Field(pattern="^(field|dataset|workload)$")
    resource_type: str
    content_findings: list[ContentFinding] = Field(default_factory=list)
    infrastructure: Optional[InfrastructureContext] = None


class Classification(BaseModel):
    sensitivity_category: list[SensitivityCategory]
    residency_lock: ResidencyLock
    aggregate_sensitivity: str = Field(pattern="^(low|medium|high|critical)$")


class CanonicalSchemaPayload(BaseModel):
    asset: AssetInfo
    classification: Classification


class DependencyLink(BaseModel):
    target_entity_type: EntityType
    target_entity_name: str
    confidence: confloat(ge=0.0, le=1.0)



class IngestionRequest(BaseModel):
    company_name: str
    company_sector: str
    entity_type: EntityType
    entity_name: str
    business_owner: Optional[str] = None
    environment: Optional[str] = None
    plugin_used: str
    phase: str = Field(pattern="^(INITIAL_DISCOVERY|RUNTIME_TRANSFER)$")
    payload: CanonicalSchemaPayload
    overall_confidence: confloat(ge=0.0, le=1.0)
    dependencies: list[DependencyLink] = Field(default_factory=list)


class IngestionResponse(BaseModel):
    entity_id: str
    status: str



class TransferRequestPayload(BaseModel):
    entity_id: str
    operation: str
    source_country: Optional[str] = None
    destination_cloud: str
    destination_service: str
    destination_region: str
    destination_country: str
    initiated_by: Optional[str] = None
    initiating_application: Optional[str] = None


class TransferDecisionResponse(BaseModel):
    transfer_request_id: str
    policy_decision_id: str
    outcome: str
    reason_code: str
    policy_reference: str


class TransferStatusResponse(BaseModel):
    transfer_request_id: str
    effective_status: str
    reason: str




class PendingReviewSummary(BaseModel):
    authorization_request_id: str
    reason: str
    expires_at: str
    entity_id: str
    entity_name: str
    entity_type: str


class ReviewResolution(BaseModel):
    approve: bool
    cndp_reference: Optional[str] = None


class ReviewResolutionResponse(BaseModel):
    authorization_request_id: str
    resolved: bool
    new_policy_decision_id: Optional[str] = None
    message: str




class DeploymentActionRequest(BaseModel):
    transfer_request_id: str
    mode: str
    executed_by: Optional[str] = None
    log_ref: Optional[str] = None
    target_region_id: Optional[str] = None


class DeploymentActionResponse(BaseModel):
    deployment_action_id: str
    status: str


class DecisionAuditRecord(BaseModel):
    policy_decision_id: str
    decision: str
    decision_features: dict
    model_name: str
    decided_at: str
    company_name: str
    is_oiv: bool
    entity_name: str
    entity_type: str
    canonical_schema_payload: dict
    operation: Optional[str] = None
    destination_country: Optional[str] = None
    authorization_status: Optional[str] = None
    cndp_reference: Optional[str] = None
    law_article: Optional[str] = None
    law_content: Optional[str] = None


class EvidencePackRequest(BaseModel):
    period_start: str
    period_end: str


class EvidencePackResponse(BaseModel):
    pack_id: str
    item_count: int
    policy_decision_ids: list[str]



class HealthResponse(BaseModel):
    postgres: str
    neo4j: str


class RecentDecisionSummary(BaseModel):
    policy_decision_id: str
    decision: str
    decided_at: str
    model_name: str
    entity_name: str
    entity_type: str
    destination_country: Optional[str] = None

