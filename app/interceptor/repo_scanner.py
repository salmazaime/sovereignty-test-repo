# app/interceptor/repo_scanner.py
"""
Walks the repository for non-IaC data files and reuses the EXACT
same content_detectors module built in Step 13 for cloud storage
sampling -- one detection layer, three entry points now (cloud
discovery, CI diff scan, and this full-repo walk).

Scope boundary stated directly: findings here are INFORMATIONAL,
attached to a synthetic resource for audit visibility. They are not
run through the sovereignty decision engine, because that engine
answers "can this data go to destination X" -- a file sitting in a
git repo with no declared destination isn't a transfer event. If a
CIN number is hardcoded into a committed file, that's a secrets-in-
git problem, which is what dedicated secret scanners (gitleaks,
trufflehog) exist for -- genuinely a different, real tool, not a gap
being papered over here.
"""

import logging
from pathlib import Path

from app.connectors.base import DiscoveredResource
from app.connectors.content_detectors import (
    detect_content_findings,
    extract_text_by_extension,
    is_sampleable,
)

logger = logging.getLogger(__name__)

MAX_REPO_FILES_SAMPLED = 200
MAX_LOCAL_READ_BYTES = 2_000_000  # mirrors MAX_BINARY_SAMPLE_BYTES's cap philosophy from Step 13

_EXCLUDED_DIR_NAMES = {".git", "node_modules", "vendor", ".terraform", "__pycache__", ".venv", "venv"}


def _walk_sampleable_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(excluded in path.parts for excluded in _EXCLUDED_DIR_NAMES):
            continue
        if not is_sampleable(path.name):
            continue
        files.append(path)
        if len(files) >= MAX_REPO_FILES_SAMPLED:
            logger.warning(
                "Reached MAX_REPO_FILES_SAMPLED (%d) -- remaining repo files were not scanned. "
                "Consider narrowing the scan path for large repositories.", MAX_REPO_FILES_SAMPLED,
            )
            break
    return files


def scan_repository_content(root: Path, repo_identifier: str) -> DiscoveredResource | None:
    """
    Returns a single synthetic DiscoveredResource aggregating every
    finding across the whole repo walk, or None if nothing was found
    -- avoids sending an empty, meaningless ingestion record when a
    repo simply has no flaggable content.
    """
    files = _walk_sampleable_files(root)
    all_findings: list[dict] = []

    for file_path in files:
        try:
            raw_bytes = file_path.read_bytes()[:MAX_LOCAL_READ_BYTES]
            text = extract_text_by_extension(file_path.name, raw_bytes)
            if not text:
                continue
            findings = detect_content_findings(text)
            relative_path = str(file_path.relative_to(root))
            for finding in findings:
                finding["field_or_location"] = relative_path
            all_findings.extend(findings)
        except (OSError, PermissionError) as exc:
            logger.warning("Could not read repository file %s: %s -- skipping.", file_path, exc)
            continue
        except Exception as exc:  # noqa: BLE001 -- last-resort safety net per file
            logger.error("Unexpected error scanning %s: %s -- skipping.", file_path, exc)
            continue

    if not all_findings:
        logger.info("Repository content scan found no flaggable content across %d file(s).", len(files))
        return None

    logger.warning(
        "Repository content scan found %d flaggable item(s) across the repo -- "
        "reviewed as informational audit findings, not a transfer decision "
        "(see repo_scanner.py module docstring).", len(all_findings),
    )

    return DiscoveredResource(
        cloud_provider="github",
        account_id=repo_identifier,
        region="unknown",
        resource_id=f"git:{repo_identifier}",
        resource_type="git_repository_content",
        name=repo_identifier,
        granularity="dataset",
        is_publicly_accessible=False,  # a private repo scan context; genuinely unknown otherwise, but not a cloud exposure question
        encryption_enabled=False,
        content_findings=all_findings,
    )
    