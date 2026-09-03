# app/interceptor/iac/terraform_parser.py
"""
Deterministic Terraform (.tf) parser built on `python-hcl2` -- a real
HCL grammar parser, not regex. Regex against Terraform syntax would
be non-deterministic in practice (multi-line blocks, nested
attributes, references) -- exactly what a "deterministic parser"
requirement rules out.

Every extraction function here follows the same rule as every other
connector in this project since Step 13: on ANY missing or
unparseable attribute, fail toward the MORE cautious classification
(assume public, assume unencrypted), never toward the more permissive
one. This mirrors app/connectors/aws/s3_connector.py's
_is_publicly_accessible() logic exactly -- same doctrine, different
data source (static HCL instead of a live API response).

Scope, stated honestly: S3 public-access and encryption are
correlated across THREE resource types (aws_s3_bucket,
aws_s3_bucket_public_access_block, aws_s3_bucket_server_side_
encryption_configuration) because that's how modern Terraform AWS
provider versions structure this. EC2 and Azure VM public-IP
resolution would require following network_interface -> public_ip
resource reference chains -- NOT implemented here. Both fail-cautious
to "assume public" when the reference chain isn't directly on the
instance/VM resource itself, which is the same "unknown -> assume
risk" principle, just applied at a coarser resolution for compute.
"""

import logging
from pathlib import Path
from typing import Any

import hcl2

from app.connectors.base import DiscoveredResource

logger = logging.getLogger(__name__)

_RELEVANT_RESOURCE_TYPES = {
    "aws_s3_bucket",
    "aws_instance",
    "azurerm_storage_account",
    "azurerm_linux_virtual_machine",
    "azurerm_windows_virtual_machine",
}


def _unwrap(value: Any) -> Any:
    """
    hcl2 represents nested blocks as single-item lists (an HCL
    quirk from how repeated blocks are modeled). This normalizes
    `[{"a": 1}]` -> `{"a": 1}` so extraction code doesn't have to
    special-case this everywhere it touches a nested block.
    """
    if isinstance(value, list) and len(value) == 1:
        return value[0]
    return value


def _load_hcl_file(path: Path) -> dict | None:
    try:
        with path.open("r", encoding="utf-8") as f:
            return hcl2.load(f)
    except Exception as exc:  # noqa: BLE001 -- hcl2 raises various parser-internal errors
        logger.warning("Could not parse Terraform file %s: %s -- skipping.", path, exc)
        return None


def _flatten_resource_blocks(parsed: dict) -> list[tuple[str, str, dict]]:
    """
    Returns a flat list of (resource_type, resource_name, attributes)
    tuples across every `resource` block in the file, regardless of
    hcl2's nested-list representation.
    """
    flat: list[tuple[str, str, dict]] = []
    for resource_entry in parsed.get("resource", []):
        for resource_type, named_blocks in resource_entry.items():
            for resource_name, attrs in named_blocks.items():
                flat.append((resource_type, resource_name, attrs))
    return flat


def _default_region_from_providers(parsed: dict) -> str | None:
    """
    Fallback region when a resource block doesn't declare its own
    `region`/`location` -- Terraform commonly sets region once on
    the provider block. Takes the FIRST aws provider's region found;
    if a codebase uses multiple provider aliases for multi-region
    deployments, this fallback is necessarily approximate -- resources
    with an explicit region attribute always take precedence over this.
    """
    for provider_entry in parsed.get("provider", []):
        aws_config = provider_entry.get("aws")
        if aws_config:
            aws_config = _unwrap(aws_config)
            region = aws_config.get("region")
            if region:
                return region
    return None


def _correlate_s3_public_access(
    bucket_resource_name: str, all_resources: list[tuple[str, str, dict]]
) -> bool:
    """
    Looks for an aws_s3_bucket_public_access_block whose `bucket`
    attribute references this bucket (via the standard Terraform
    reference syntax `aws_s3_bucket.<name>.id`). Public access is
    considered BLOCKED only if all four blocking flags are explicitly
    true. Any correlation failure (no matching block found, an
    attribute missing, an unexpected reference format) fails toward
    "publicly accessible" -- same as the live-API version in Step 13.
    """
    for r_type, _r_name, attrs in all_resources:
        if r_type != "aws_s3_bucket_public_access_block":
            continue
        bucket_ref = str(attrs.get("bucket", ""))
        if bucket_resource_name not in bucket_ref:
            continue
        try:
            all_blocked = all(
                bool(attrs.get(flag, False))
                for flag in (
                    "block_public_acls",
                    "block_public_policy",
                    "ignore_public_acls",
                    "restrict_public_buckets",
                )
            )
            return not all_blocked
        except (TypeError, ValueError) as exc:
            logger.warning(
                "Could not evaluate public_access_block for bucket %s: %s -- assuming public.",
                bucket_resource_name, exc,
            )
            return True

    # ACL attribute directly on the bucket resource is the other
    # common signal -- checked by the caller before falling back here.
    return True  # no correlated public_access_block found -> fail cautious


def _correlate_s3_encryption(
    bucket_resource_name: str, all_resources: list[tuple[str, str, dict]]
) -> tuple[bool, str | None]:
    for r_type, _r_name, attrs in all_resources:
        if r_type != "aws_s3_bucket_server_side_encryption_configuration":
            continue
        bucket_ref = str(attrs.get("bucket", ""))
        if bucket_resource_name not in bucket_ref:
            continue
        try:
            rule = _unwrap(attrs.get("rule", {}))
            default_sse = _unwrap(rule.get("apply_server_side_encryption_by_default", {}))
            algorithm = default_sse.get("sse_algorithm", "")
            key_type = "AWS_KMS" if algorithm == "aws:kms" else "AWS_MANAGED"
            return True, key_type
        except (TypeError, AttributeError) as exc:
            logger.warning(
                "Could not evaluate encryption config for bucket %s: %s -- assuming unencrypted.",
                bucket_resource_name, exc,
            )
            return False, None

    return False, None  # no correlated encryption config found -> fail cautious


def _parse_aws_s3_bucket(
    resource_name: str, attrs: dict, all_resources: list[tuple[str, str, dict]], default_region: str | None
) -> DiscoveredResource:
    bucket_name = attrs.get("bucket", resource_name)
    region = attrs.get("region") or default_region or "unknown"
    tags = dict(_unwrap(attrs.get("tags", {})) or {})

    acl = attrs.get("acl", "")
    if isinstance(acl, str) and "public" in acl.lower():
        is_public = True
    else:
        is_public = _correlate_s3_public_access(resource_name, all_resources)

    encrypted, key_type = _correlate_s3_encryption(resource_name, all_resources)

    return DiscoveredResource(
        cloud_provider="aws",
        account_id="unknown",  # not resolvable from static HCL -- no live STS call available here
        region=region,
        resource_id=f"terraform:aws_s3_bucket.{resource_name}",
        resource_type="s3_bucket",
        name=bucket_name,
        granularity="dataset",
        is_publicly_accessible=is_public,
        encryption_enabled=encrypted,
        encryption_key_type=key_type,
        tags=tags,
    )


def _parse_aws_instance(resource_name: str, attrs: dict, default_region: str | None) -> DiscoveredResource:
    tags = dict(_unwrap(attrs.get("tags", {})) or {})
    name = tags.get("Name", resource_name)

    # associate_public_ip_address is the only DIRECT signal available
    # without following a subnet's auto-assign-public-ip setting or a
    # separate aws_eip resource's association -- both out of scope
    # (see module docstring). Missing entirely -> fail cautious True.
    associate_public_ip = attrs.get("associate_public_ip_address")
    is_public = True if associate_public_ip is None else bool(associate_public_ip)

    root_block_device = _unwrap(attrs.get("root_block_device", {}))
    encrypted = bool(root_block_device.get("encrypted", False)) if root_block_device else False

    security_groups = attrs.get("vpc_security_group_ids", [])
    if not isinstance(security_groups, list):
        security_groups = []

    return DiscoveredResource(
        cloud_provider="aws",
        account_id="unknown",
        region=default_region or "unknown",
        resource_id=f"terraform:aws_instance.{resource_name}",
        resource_type="ec2_instance",
        name=name,
        granularity="workload",
        is_publicly_accessible=is_public,
        security_group_ids=[str(sg) for sg in security_groups],
        encryption_enabled=encrypted,
        encryption_key_type="AWS_MANAGED" if encrypted else None,
        tags=tags,
    )


def _parse_azurerm_storage_account(resource_name: str, attrs: dict) -> DiscoveredResource:
    """
    Encryption is hardcoded True here for the SAME reason
    app/connectors/azure/blob_connector.py hardcodes it: Azure
    Storage encrypts at rest unconditionally, by platform default,
    with no way to disable it -- this is a real platform fact, not
    an inconsistency with the fail-cautious defaults used elsewhere.
    """
    name = attrs.get("name", resource_name)
    region = attrs.get("location", "unknown")
    tags = dict(_unwrap(attrs.get("tags", {})) or {})

    public_access = attrs.get("public_network_access_enabled")
    is_public = True if public_access is None else bool(public_access)

    customer_managed_key = attrs.get("customer_managed_key")
    key_type = "CUSTOMER_MANAGED" if customer_managed_key else "PLATFORM_MANAGED"

    return DiscoveredResource(
        cloud_provider="azure",
        account_id="unknown",
        region=region,
        resource_id=f"terraform:azurerm_storage_account.{resource_name}",
        resource_type="azure_blob_container",
        name=name,
        granularity="dataset",
        is_publicly_accessible=is_public,
        encryption_enabled=True,
        encryption_key_type=key_type,
        tags=tags,
    )


def _parse_azurerm_vm(resource_type: str, resource_name: str, attrs: dict) -> DiscoveredResource:
    """
    Azure managed disks are encrypted at rest by platform default
    (Server-Side Encryption, always on) -- same reasoning as Azure
    Storage above, NOT a fail-cautious default in this specific case,
    it's a genuine platform guarantee. Overridden to CUSTOMER_MANAGED
    only if a disk_encryption_set_id is explicitly present.
    """
    name = attrs.get("name", resource_name)
    region = attrs.get("location", "unknown")
    tags = dict(_unwrap(attrs.get("tags", {})) or {})

    # Public IP resolution across network_interface -> public_ip
    # references is out of scope (see module docstring) -- fail
    # cautious. network_interface_ids being present at all doesn't
    # tell us public-vs-private without following the reference.
    is_public = True

    os_disk = _unwrap(attrs.get("os_disk", {}))
    disk_encryption_set_id = os_disk.get("disk_encryption_set_id") if os_disk else None
    key_type = "CUSTOMER_MANAGED" if disk_encryption_set_id else "PLATFORM_MANAGED"

    return DiscoveredResource(
        cloud_provider="azure",
        account_id="unknown",
        region=region,
        resource_id=f"terraform:{resource_type}.{resource_name}",
        resource_type="azure_vm",
        name=name,
        granularity="workload",
        is_publicly_accessible=is_public,
        encryption_enabled=True,
        encryption_key_type=key_type,
        tags=tags,
    )


def parse_terraform_file(path: Path) -> list[DiscoveredResource]:
    """
    Never raises. A malformed file returns []; a per-resource
    extraction error is caught individually so one bad resource block
    doesn't discard every other resource in the same file -- same
    per-item try/except discipline used in every cloud connector
    since Step 13.
    """
    parsed = _load_hcl_file(path)
    if parsed is None:
        return []

    all_resources = _flatten_resource_blocks(parsed)
    default_region = _default_region_from_providers(parsed)

    discovered: list[DiscoveredResource] = []
    for resource_type, resource_name, attrs in all_resources:
        if resource_type not in _RELEVANT_RESOURCE_TYPES:
            continue
        try:
            if resource_type == "aws_s3_bucket":
                discovered.append(_parse_aws_s3_bucket(resource_name, attrs, all_resources, default_region))
            elif resource_type == "aws_instance":
                discovered.append(_parse_aws_instance(resource_name, attrs, default_region))
            elif resource_type == "azurerm_storage_account":
                discovered.append(_parse_azurerm_storage_account(resource_name, attrs))
            elif resource_type in ("azurerm_linux_virtual_machine", "azurerm_windows_virtual_machine"):
                discovered.append(_parse_azurerm_vm(resource_type, resource_name, attrs))
        except Exception as exc:  # noqa: BLE001 -- one malformed resource block must not abort the file
            logger.error(
                "Unexpected error parsing %s.%s in %s: %s -- skipping this resource.",
                resource_type, resource_name, path, exc,
            )
            continue

    return discovered


def scan_terraform_files(root: Path) -> list[DiscoveredResource]:
    """
    Walks the repository for .tf files. Skips .terraform/ (the
    provider plugin cache directory Terraform generates locally --
    can contain vendored .tf-adjacent files that aren't the user's
    actual infrastructure declarations and can be large).
    """
    resources: list[DiscoveredResource] = []
    for tf_file in root.rglob("*.tf"):
        if ".terraform" in tf_file.parts:
            continue
        resources.extend(parse_terraform_file(tf_file))
    return resources
    