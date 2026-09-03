"""
Parses Azure Purview scan result exports (JSON) and translates them
into ContentFinding-shaped dicts, mirroring macie_connector.py's
structure exactly -- same reasoning: reading an exported/retrieved
scan result set here, live Purview API integration (via
azure-purview-scanning / azure-purview-catalog SDKs) is a clean,
separate extension later that wouldn't change this file's output
shape or anything downstream of it.
"""

import json
import logging
from pathlib import Path

from app.connectors.dlp_mapping import map_purview_classification

logger = logging.getLogger(__name__)

PURVIEW_CONFIDENCE = 0.97  # per requirement: DLP vendor findings are high-confidence


def _asset_to_content_findings(asset: dict) -> list[dict]:
    results: list[dict] = []
    asset_name = asset.get("assetName", "unknown-asset")

    for classification in asset.get("classifications", []):
        classification_name = classification.get("classificationName", "")
        if not classification_name:
            continue
        category = map_purview_classification(classification_name)
        results.append({
            "category": category.value,
            "field_or_location": asset_name,
            "confidence": PURVIEW_CONFIDENCE,
            "detector": "azure_purview",
        })
    return results


def load_purview_scan_file(path: Path) -> dict[str, list[dict]]:
    """
    Returns a dict keyed by "{storage_account}/{container}" (matching
    the `name` field blob_connector.discover_blob_containers already
    produces, see 13.14) -> list of ContentFinding dicts.

    Same never-raise contract as load_macie_findings_file: a missing
    or malformed export degrades to "no DLP data", never a crash.
    """
    if not path.exists():
        logger.warning("Purview scan file not found at %s -- DLP fallback will be regex/OCR-only.", path)
        return {}

    try:
        raw = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Could not parse Purview scan file %s: %s -- skipping.", path, exc)
        return {}

    assets = raw if isinstance(raw, list) else raw.get("assets", [])

    findings_by_container: dict[str, list[dict]] = {}
    for asset in assets:
        try:
            # Expected assetName convention: "<account>/<container>"
            # or "<account>/<container>/<blob path>" -- we key on the
            # first two path segments to aggregate at container level,
            # matching our resource granularity for Azure Blob.
            asset_name = asset.get("assetName", "")
            parts = asset_name.split("/")
            if len(parts) < 2:
                logger.warning("Purview asset '%s' doesn't match <account>/<container> pattern -- skipping.", asset_name)
                continue
            container_key = f"{parts[0]}/{parts[1]}"

            content_findings = _asset_to_content_findings(asset)
            findings_by_container.setdefault(container_key, []).extend(content_findings)
        except Exception as exc:  # noqa: BLE001
            logger.error("Could not parse individual Purview asset: %s -- skipping.", exc)
            continue

    logger.info("Loaded Purview findings for %d container(s) from %s.", len(findings_by_container), path)
    return findings_by_container
    