# scripts/run_pipeline_interceptor.py
"""
Real entry point. Does the actual filesystem walk and constructs the
real HTTP client, then calls the pure, tested run_gate() from
app/interceptor/cli.py. This file is deliberately thin and untested
directly -- everything worth unit-testing lives in cli.py, which IS
tested (see tests/test_interceptor_cli.py). This script itself is
exercised end-to-end via the GitHub Actions workflow (14.18) against
a real running API, which is the appropriate level to verify actual
filesystem + network wiring, not a unit test.

Zero imports from app.db or app.graph anywhere in this file or
anything it imports -- satisfies "must NOT import PostgreSQL or
Neo4j repositories directly" by construction, not by convention.
"""

import logging
import os
import sys
from pathlib import Path

from app.connectors.region_lookup import RegionCountryTable
from app.interceptor.api_client import SovereigntyAPIClient
from app.interceptor.cli import run_gate
from app.interceptor.iac.k8s_parser import scan_k8s_files
from app.interceptor.iac.terraform_parser import scan_terraform_files
from app.interceptor.repo_scanner import scan_repository_content
from app.logging_setup import configure_logging

logger = logging.getLogger(__name__)


def main() -> int:
    configure_logging()

    api_url = os.environ.get("SOVEREIGNTY_API_URL", "http://localhost:8000")
    company_name = os.environ.get("SOVEREIGNTY_COMPANY_NAME")
    company_sector = os.environ.get("SOVEREIGNTY_COMPANY_SECTOR")
    repo_root = Path(os.environ.get("SOVEREIGNTY_SCAN_ROOT", "."))
    repo_identifier = os.environ.get("GITHUB_REPOSITORY", str(repo_root.resolve()))
    actor = os.environ.get("GITHUB_ACTOR", "unknown")
    api_key = os.environ.get("SOVEREIGNTY_API_KEY")
    if not api_key:
        logger.error("SOVEREIGNTY_API_KEY not set -- blocking by default.")
        return 1

    if not company_name or not company_sector:
        # Fail closed: without company context we cannot correctly
        # evaluate residency_lock/qualified_provider_required at all
        # -- same "missing required config -> block, don't guess"
        # principle as the original deploy-target.yml design.
        logger.error(
            "SOVEREIGNTY_COMPANY_NAME and SOVEREIGNTY_COMPANY_SECTOR must both be set -- blocking by default."
        )
        return 1

    region_table = RegionCountryTable.load(Path("config/region_country_map.json"))

    logger.info("Scanning Terraform files under %s ...", repo_root)
    terraform_resources = scan_terraform_files(repo_root)
    logger.info("Found %d Terraform-declared resource(s).", len(terraform_resources))

    logger.info("Scanning Kubernetes manifests under %s ...", repo_root)
    k8s_resources = scan_k8s_files(repo_root)
    logger.info("Found %d Kubernetes-declared resource(s).", len(k8s_resources))

    logger.info("Scanning repository content files under %s ...", repo_root)
    repo_content_resource = scan_repository_content(repo_root, repo_identifier)

    all_resources = terraform_resources + k8s_resources
    if repo_content_resource is not None:
        all_resources.append(repo_content_resource)

    if not all_resources:
        logger.info("No infrastructure or content resources discovered in this repository. Passing.")
        return 0

    with SovereigntyAPIClient(base_url=api_url, api_key=api_key) as api_client:
        return run_gate(
            resources=all_resources,
            api_client=api_client,
            company_name=company_name,
            company_sector=company_sector,
            region_table=region_table,
            initiated_by=actor,
            initiating_application=f"github_actions_iac_gate:{repo_identifier}",
        )


if __name__ == "__main__":
    sys.exit(main())
    
    