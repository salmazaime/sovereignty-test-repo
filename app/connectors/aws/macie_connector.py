"""
Parses AWS Macie finding exports (JSON, as produced by Macie's
export-to-S3 feature or the GetFindings API) and translates them
into ContentFinding-shaped dicts our pipeline already understands.

Deliberately does NOT call the Macie API directly in this version --
it reads an exported findings file. Calling GetFindings live would
need its own boto3 client (mirroring AWSClientFactory from Step 13)
and its own permission scope (macie2:GetFindings), which is a real,
separate integration step. Parsing an export is the honest MVP: it
proves the mapping logic works and is a small, clean extension to
live-call later without changing anything downstream of this file.
"""

import json
import logging
from pathlib import Path

from app.connectors.dlp_mapping import map_macie_detection

logger = logging.getLogger(__name__)

MACIE_CONFIDENCE = 0.97  # per requirement: DLP vendor findings are high-confidence


def _findings_to_content_findings(finding: dict) -> list[dict]:
    """
    One Macie 'finding' can report MULTIPLE detection types (e.g. a
    file with both an email address and a credit card number). We
    fan that out into multiple ContentFinding dicts, matching the
    multi-label design decided back when we first built the schema
    -- one object can trigger several categories at once.
    """
    results: list[dict] = []
    s3_object = finding.get("resourcesAffected", {}).get("s3Object", {})
    object_key = s3_object.get("key", "bucket-level")

    sensitive_data_blocks = (
        finding.get("classificationDetails", {})
        .get("result", {})
        .get("sensitiveData", [])
    )
    for block in sensitive_data_blocks:
        top_level_category = block.get("category", "UNKNOWN")
        for detection in block.get("detections", []):
            detection_type = detection.get("type", "UNKNOWN")
            category = map_macie_detection(detection_type, top_level_category)
            results.append({
                "category": category.value,
                "field_or_location": object_key,
                "confidence": MACIE_CONFIDENCE,
                "detector": "aws_macie",
            })
    return results


def load_macie_findings_file(path: Path) -> dict[str, list[dict]]:
    """
    Reads a Macie findings export and returns a dict keyed by S3
    bucket name -> list of ContentFinding dicts, aggregated across
    every finding for that bucket. This is the exact shape
    s3_connector.discover_s3_buckets expects for its
    dlp_findings_by_resource parameter (see 13.14).

    Returns an empty dict (never raises) if the file is missing or
    malformed -- per the "never crash the service" guardrail, a bad
    or absent Macie export should degrade to "no DLP data available",
    triggering local regex fallback for every bucket, not a crash.
    """
    if not path.exists():
        logger.warning("Macie findings file not found at %s -- DLP fallback will be regex-only.", path)
        return {}

    try:
        raw = json.loads(path.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        logger.error("Could not parse Macie findings file %s: %s -- skipping.", path, exc)
        return {}

    # Macie exports are typically a JSON array of finding objects,
    # or {"findings": [...]} depending on export configuration --
    # handle both shapes defensively.
    findings = raw if isinstance(raw, list) else raw.get("findings", [])

    findings_by_bucket: dict[str, list[dict]] = {}
    for finding in findings:
        try:
            bucket_name = finding.get("resourcesAffected", {}).get("s3Bucket", {}).get("name")
            if not bucket_name:
                logger.warning("Macie finding %s has no bucket name -- skipping.", finding.get("id", "unknown"))
                continue
            content_findings = _findings_to_content_findings(finding)
            findings_by_bucket.setdefault(bucket_name, []).extend(content_findings)
        except Exception as exc:  # noqa: BLE001 -- one malformed finding must not break the whole load
            logger.error("Could not parse individual Macie finding: %s -- skipping.", exc)
            continue

    logger.info("Loaded Macie findings for %d bucket(s) from %s.", len(findings_by_bucket), path)
    return findings_by_bucket
    