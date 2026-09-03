"""
Blob discovery, extended identically to the S3 connector: multi-
format sampling + Purview-aware smart fallback keyed by
"{account}/{container}".
"""

import logging

from azure.core.exceptions import HttpResponseError
from azure.storage.blob import BlobServiceClient

from app.connectors.azure.client import AzureClientFactory
from app.connectors.base import DiscoveredResource
from app.connectors.content_detectors import (
    MAX_OBJECTS_PER_CONTAINER,
    detect_content_findings,
    extract_text_by_extension,
    get_sample_byte_range,
    is_sampleable,
)

logger = logging.getLogger(__name__)


def _sample_blob_findings_locally(container_client) -> list[dict]:
    findings: list[dict] = []
    try:
        blobs = list(container_client.list_blobs(results_per_page=MAX_OBJECTS_PER_CONTAINER))
    except HttpResponseError as exc:
        logger.warning("Could not list blobs: %s", exc)
        return findings

    for blob in blobs[:MAX_OBJECTS_PER_CONTAINER]:
        if not is_sampleable(blob.name):
            continue
        try:
            byte_range = get_sample_byte_range(blob.name)
            downloader = container_client.download_blob(blob.name, offset=0, length=byte_range)
            raw_bytes = downloader.readall()
            text = extract_text_by_extension(blob.name, raw_bytes)
            if text:
                findings.extend(detect_content_findings(text))
        except (HttpResponseError, UnicodeDecodeError) as exc:
            logger.warning("Could not sample blob %s: %s", blob.name, exc)
            continue
    return findings


def discover_blob_containers(
    factory: AzureClientFactory,
    resource_group: str,
    dlp_findings_by_resource: dict[str, list[dict]] | None = None,
) -> list[DiscoveredResource]:
    dlp_findings_by_resource = dlp_findings_by_resource or {}
    storage_client = factory.storage_client()
    resources: list[DiscoveredResource] = []
    if storage_client is None:
        return resources

    try:
        accounts = list(storage_client.storage_accounts.list_by_resource_group(resource_group))
    except HttpResponseError as exc:
        logger.error("Could not list storage accounts in %s: %s -- skipping.", resource_group, exc)
        return resources

    for account in accounts:
        try:
            account_url = f"https://{account.name}.blob.core.windows.net"
            blob_service = BlobServiceClient(account_url=account_url, credential=factory.credential())

            tls_enforced = getattr(account, "minimum_tls_version", None) not in (None, "TLS1_0")
            allow_public = getattr(account, "allow_blob_public_access", True)

            try:
                containers = list(blob_service.list_containers())
            except HttpResponseError as exc:
                logger.warning("Could not list containers in %s: %s", account.name, exc)
                continue

            for container in containers:
                try:
                    resource_key = f"{account.name}/{container.name}"
                    container_client = blob_service.get_container_client(container.name)
                    public_access = getattr(container, "public_access", None) is not None

                    if resource_key in dlp_findings_by_resource:
                        findings = dlp_findings_by_resource[resource_key]
                        logger.info(
                            "Using %d Purview finding(s) for %s (skipping local sampling).",
                            len(findings), resource_key,
                        )
                    else:
                        findings = _sample_blob_findings_locally(container_client)

                    resources.append(DiscoveredResource(
                        cloud_provider="azure",
                        account_id=factory.subscription_id,
                        region=account.location,
                        resource_id=account.id + f"/blobServices/default/containers/{container.name}",
                        resource_type="azure_blob_container",
                        name=resource_key,
                        granularity="dataset",
                        is_publicly_accessible=allow_public and public_access,
                        encryption_enabled=True,
                        encryption_key_type="PLATFORM_MANAGED" if tls_enforced else "UNKNOWN",
                        content_findings=findings,
                        tags=dict(account.tags or {}),
                    ))
                except Exception as exc:  # noqa: BLE001
                    logger.error("Unexpected error on container %s: %s -- skipping.", container.name, exc)
                    continue
        except Exception as exc:  # noqa: BLE001
            logger.error("Unexpected error on storage account %s: %s -- skipping.", account.name, exc)
            continue

    return resources
    