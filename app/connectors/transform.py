"""
The single function converting a DiscoveredResource into the
IngestionRequest your pipeline (Step 7) already knows how to handle.
Every connector, for every cloud and every resource type, funnels
through here — this is the only place that needs to change if
IngestionRequest's shape ever changes.
"""

from app.connectors.base import DiscoveredResource
from app.connectors.region_lookup import RegionCountryTable
from app.schemas import (
    AssetInfo,
    CanonicalSchemaPayload,
    Classification,
    ContentFinding,
    DependencyLink,
    EncryptionInfo,
    EntityType,
    InfrastructureContext,
    IngestionRequest,
    NetworkingInfo,
    ResidencyLock,
    SensitivityCategory,
    VendorAttestation,
)

_SENSITIVITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _aggregate_sensitivity(findings: list[dict]) -> str:
    """
    Mirrors the 'one bad field pulls the whole document in' rule we
    designed at the very start of this project — max severity across
    all findings, not an average.
    """
    if not findings:
        return "low"
    has_national_id_or_health = any(
        f["category"] in ("national_id", "health", "genetic") for f in findings
    )
    if has_national_id_or_health:
        return "high"
    return "medium"


def to_ingestion_request(
    resource: DiscoveredResource,
    company_name: str,
    company_sector: str,
    region_table: RegionCountryTable,
) -> IngestionRequest:
    # Resolve sovereign country using region table lookup
    country = region_table.country_for(resource.cloud_provider, resource.region)

    sensitivity_categories = (
        [SensitivityCategory(f["category"]) for f in resource.content_findings]
        or [SensitivityCategory.NONE]
    )

    # 1. Build Asset Information Context
    asset_info = AssetInfo(
        granularity=resource.granularity,
        resource_type=resource.resource_type,
        content_findings=[ContentFinding(**f) for f in resource.content_findings],
        infrastructure=InfrastructureContext(
            account_id=resource.account_id,
            region=resource.region,
            resource_id=resource.resource_id,
            networking=NetworkingInfo(
                is_publicly_accessible=resource.is_publicly_accessible,
                allowed_ip_ranges=resource.allowed_ip_ranges,
                vpc_or_vnet_id=resource.vpc_or_vnet_id,
                security_group_ids=resource.security_group_ids,
            ),
            encryption=EncryptionInfo(
                at_rest_enabled=resource.encryption_enabled,
                key_type=resource.encryption_key_type,
            ),
            vendor_attestation=VendorAttestation(
                provider_name=resource.cloud_provider,
                data_center_country=country,
            ),
        ),
    )

    # 2. Build Data Classification Context
    classification_info = Classification(
        sensitivity_category=sensitivity_categories,
        residency_lock=ResidencyLock.NONE,  # Evaluated downstream by policy engine
        aggregate_sensitivity=_aggregate_sensitivity(resource.content_findings),
    )

    # 3. Combine into full Canonical Schema Payload
    canonical_payload = CanonicalSchemaPayload(
        asset=asset_info.model_dump() if hasattr(asset_info, "model_dump") else asset_info.dict(),
        classification=classification_info.model_dump() if hasattr(classification_info, "model_dump") else classification_info.dict(),
    )

    # 4. Construct final pipeline IngestionRequest
    return IngestionRequest(
        company_name=company_name,
        company_sector=company_sector,
        entity_type=(
            EntityType.DATA_ASSET
            if resource.granularity == "dataset"
            else EntityType.WORKLOAD
        ),
        entity_name=resource.name,
        business_owner=resource.tags.get("owner"),
        environment=resource.tags.get("environment"),
        plugin_used=f"{resource.cloud_provider}_{resource.resource_type}_connector",
        phase="INITIAL_DISCOVERY",
        payload=canonical_payload,
        overall_confidence=(
            max((f["confidence"] for f in resource.content_findings), default=0.5)
        ),
        dependencies=[
            DependencyLink(
                target_entity_type=EntityType(t),
                target_entity_name=n,
                confidence=0.8,
            )
            for t, n in resource.dependencies
        ],
    )
    