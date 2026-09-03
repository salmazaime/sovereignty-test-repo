"""
S3 discovery, extended with:
  - multi-format sampling (text/PDF/image) via content_detectors
  - "smart fallback": if a bucket has findings from an external DLP
    export (Macie), those are used INSTEAD of local sampling for
    that bucket -- local regex/OCR only runs for buckets Macie
    hasn't scanned or wasn't configured for. This is per-bucket, not
    a global on/off switch: a Macie export covering half your
    buckets means the other half still get local sampling.
"""

import logging

from botocore.exceptions import ClientError

from app.connectors.aws.client import AWSClientFactory
from app.connectors.base import DiscoveredResource
from app.connectors.content_detectors import (
    MAX_OBJECTS_PER_CONTAINER,
    detect_content_findings,
    extract_text_by_extension,
    get_sample_byte_range,
    is_sampleable,
)

logger = logging.getLogger(__name__)


def _bucket_region(s3_client, bucket_name: str, default_region: str) -> str:
    try:
        loc = s3_client.get_bucket_location(Bucket=bucket_name)["LocationConstraint"]
        return loc or "us-east-1"
    except ClientError as exc:
        logger.warning("Could not get region for bucket %s: %s", bucket_name, exc)
        return default_region


def _is_publicly_accessible(s3_client, bucket_name: str) -> bool:
    try:
        config = s3_client.get_public_access_block(Bucket=bucket_name)["PublicAccessBlockConfiguration"]
        return not all(config.values())
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
            return True
        logger.warning("Could not check public access block for %s: %s", bucket_name, exc)
        return True


def _encryption_info(s3_client, bucket_name: str) -> tuple[bool, str | None]:
    try:
        rules = s3_client.get_bucket_encryption(Bucket=bucket_name)
        rule = rules["ServerSideEncryptionConfiguration"]["Rules"][0]
        algo = rule["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        key_type = "AWS_KMS" if algo == "aws:kms" else "AWS_MANAGED"
        return True, key_type
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return False, None
        logger.warning("Could not check encryption for %s: %s", bucket_name, exc)
        return False, None


def _sample_content_findings_locally(s3_client, bucket_name: str) -> list[dict]:
    """
    Renamed from the Step 13 version to make the "local" (as opposed
    to "external DLP-provided") nature explicit at the call site --
    this distinction is the crux of the smart-fallback logic.
    """
    findings: list[dict] = []
    try:
        objects = s3_client.list_objects_v2(
            Bucket=bucket_name, MaxKeys=MAX_OBJECTS_PER_CONTAINER
        ).get("Contents", [])
    except ClientError as exc:
        logger.warning("Could not list objects in %s: %s", bucket_name, exc)
        return findings

    for obj in objects:
        key = obj["Key"]
        if not is_sampleable(key):
            continue
        try:
            byte_range = get_sample_byte_range(key)
            body = s3_client.get_object(
                Bucket=bucket_name, Key=key, Range=f"bytes=0-{byte_range - 1}"
            )["Body"].read()
            text = extract_text_by_extension(key, body)
            if text:
                findings.extend(detect_content_findings(text))
        except (ClientError, UnicodeDecodeError) as exc:
            logger.warning("Could not sample object %s/%s: %s", bucket_name, key, exc)
            continue
    return findings


def discover_s3_buckets(
    factory: AWSClientFactory,
    dlp_findings_by_resource: dict[str, list[dict]] | None = None,
) -> list[DiscoveredResource]:
    """
    dlp_findings_by_resource: optional dict, keyed by bucket name,
    of pre-computed ContentFinding dicts from an external DLP tool
    (see macie_connector.load_macie_findings_file). Defaults to {},
    meaning EVERY call site from before this change (Step 13's tests,
    runner.py before 13.17's update) still works unmodified -- same
    backward-compatible-optional-parameter discipline used throughout
    this project.
    """
    dlp_findings_by_resource = dlp_findings_by_resource or {}
    s3 = factory.client("s3")
    account_id = factory.account_id() or "unknown"
    resources: list[DiscoveredResource] = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as exc:
        logger.error("Could not list S3 buckets: %s -- skipping S3 discovery entirely.", exc)
        return resources

    for bucket in buckets:
        name = bucket["Name"]
        try:
            region = _bucket_region(s3, name, factory.region)
            public = _is_publicly_accessible(s3, name)
            enc_enabled, key_type = _encryption_info(s3, name)

            if name in dlp_findings_by_resource:
                findings = dlp_findings_by_resource[name]
                logger.info("Using %d Macie finding(s) for bucket %s (skipping local sampling).", len(findings), name)
            else:
                findings = _sample_content_findings_locally(s3, name)

            try:
                tags_resp = s3.get_bucket_tagging(Bucket=name)
                tags = {t["Key"]: t["Value"] for t in tags_resp.get("TagSet", [])}
            except ClientError:
                tags = {}

            resources.append(DiscoveredResource(
                cloud_provider="aws",
                account_id=account_id,
                region=region,
                resource_id=f"arn:aws:s3:::{name}",
                resource_type="s3_bucket",
                name=name,
                granularity="dataset",
                is_publicly_accessible=public,
                encryption_enabled=enc_enabled,
                encryption_key_type=key_type,
                content_findings=findings,
                tags=tags,
            ))
        except Exception as exc:  # noqa: BLE001
            logger.error("Unexpected error processing bucket %s: %s -- skipping.", name, exc)
            continue

    return resources
    