# app/connectors/base.py
"""
The one shape every cloud connector must produce, regardless of
whether the underlying resource is an S3 bucket, an Azure VM, or
anything added later. This is the seam described in Decision 1 —
adding a third cloud later means writing a connector that emits
THIS type, nothing about the pipeline changes.
"""

from dataclasses import dataclass, field


@dataclass
class DiscoveredResource:
    cloud_provider: str          # "aws" | "azure"
    account_id: str
    region: str
    resource_id: str             # ARN or full Azure resource ID
    resource_type: str           # "s3_bucket" | "ec2_instance" | "azure_blob_container" | "azure_vm"
    name: str
    granularity: str             # "dataset" | "workload"

    is_publicly_accessible: bool
    allowed_ip_ranges: list[str] = field(default_factory=list)
    vpc_or_vnet_id: str | None = None
    security_group_ids: list[str] = field(default_factory=list)

    encryption_enabled: bool = False
    encryption_key_type: str | None = None

    content_findings: list[dict] = field(default_factory=list)
    tags: dict[str, str] = field(default_factory=dict)

    # (entity_type, entity_name) pairs this resource is known to
    # depend on — e.g. an EC2 instance whose tags reference a bucket
    # it reads from. Left empty by default; connectors only populate
    # this where the dependency is DIRECTLY observable from the API
    # response, never guessed. Honest scope limit, see 13.6/13.7.
    dependencies: list[tuple[str, str]] = field(default_factory=list)
    
    