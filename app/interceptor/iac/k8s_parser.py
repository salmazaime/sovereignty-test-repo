# app/interceptor/iac/k8s_parser.py
"""
Parses Kubernetes manifests for two things:

1. PersistentVolumeClaims -- infrastructure facts, via a DECLARED
   annotation convention (see below). Kubernetes has no built-in,
   universal way to express "which cloud region backs this volume"
   at the manifest level -- that's determined by the StorageClass's
   underlying provisioner, resolved only at cluster runtime. Rather
   than guess, we require an explicit annotation on PVCs that should
   be sovereignty-tracked. This is the same "declare, don't infer"
   principle used for the CI/CD destination file in the original
   Step 14 design -- a reliable, explicit contract beats a clever,
   fragile inference.

2. ConfigMaps -- their `data` values are scanned as text for
   sensitive content (test fixtures, seed data, and connection
   strings often end up in ConfigMaps in practice), reusing the
   SAME detectors as every other content scan in this project.

Everything else (Deployments, Services, generic CRDs) is
deliberately out of scope for this step -- named here rather than
silently ignored.
"""

import logging
from pathlib import Path

import yaml

from app.connectors.base import DiscoveredResource
from app.connectors.content_detectors import detect_content_findings

logger = logging.getLogger(__name__)

# Declared annotation convention a repo must use on a PVC for it to
# be picked up here. Undeclared PVCs are silently skipped -- absence
# of the convention means "not tracked", not "assume worst case",
# because an untracked PVC isn't a discovered infrastructure fact at
# all, it's simply outside this parser's declared contract.
ANNOTATION_CLOUD = "sovereignty.acme.io/cloud"
ANNOTATION_REGION = "sovereignty.acme.io/region"
ANNOTATION_BUCKET = "sovereignty.acme.io/backing-bucket"


def _parse_pvc(doc: dict) -> DiscoveredResource | None:
    metadata = doc.get("metadata", {})
    annotations = metadata.get("annotations", {}) or {}

    cloud = annotations.get(ANNOTATION_CLOUD)
    if not cloud:
        return None  # untracked PVC, outside this parser's declared contract

    region = annotations.get(ANNOTATION_REGION, "unknown")
    backing_name = annotations.get(ANNOTATION_BUCKET, metadata.get("name", "unknown-pvc"))
    storage_class = doc.get("spec", {}).get("storageClassName", "")

    # No live encryption signal is available from a PVC manifest --
    # fail cautious unless the storage class name itself signals
    # encryption (a common, if informal, naming convention).
    encrypted = "encrypted" in storage_class.lower()

    return DiscoveredResource(
        cloud_provider=cloud,
        account_id="unknown",
        region=region,
        resource_id=f"k8s:PersistentVolumeClaim/{metadata.get('namespace', 'default')}/{metadata.get('name')}",
        resource_type="k8s_persistent_volume_claim",
        name=backing_name,
        granularity="dataset",
        is_publicly_accessible=True,  # no signal available -> fail cautious
        encryption_enabled=encrypted,
        encryption_key_type="UNKNOWN" if encrypted else None,
        tags={"storage_class": storage_class} if storage_class else {},
    )


def _parse_configmap(doc: dict) -> DiscoveredResource | None:
    metadata = doc.get("metadata", {})
    data = doc.get("data", {}) or {}
    if not data:
        return None

    combined_text = "\n".join(str(v) for v in data.values())
    findings = detect_content_findings(combined_text)
    if not findings:
        return None  # nothing sensitive found -- no need to create a resource record at all

    for finding in findings:
        finding["field_or_location"] = f"configmap:{metadata.get('name', 'unknown')}"

    return DiscoveredResource(
        cloud_provider="kubernetes",
        account_id="unknown",
        region="unknown",
        resource_id=f"k8s:ConfigMap/{metadata.get('namespace', 'default')}/{metadata.get('name')}",
        resource_type="k8s_configmap",
        name=metadata.get("name", "unknown-configmap"),
        granularity="dataset",
        is_publicly_accessible=False,  # ConfigMaps aren't network-exposed by nature
        encryption_enabled=False,      # etcd-at-rest encryption is a cluster-level setting, not visible here
        content_findings=findings,
    )


def parse_k8s_file(path: Path) -> list[DiscoveredResource]:
    """
    Never raises. Handles multi-document YAML files (--- separated),
    which is the norm for Kubernetes manifests. Uses safe_load_all
    for the same untrusted-input reasoning as every other YAML
    parse in this project (Step 14's original deploy-target config).
    """
    try:
        raw_docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    except (yaml.YAMLError, UnicodeDecodeError) as exc:
        logger.warning("Could not parse Kubernetes manifest %s: %s -- skipping.", path, exc)
        return []

    discovered: list[DiscoveredResource] = []
    for doc in raw_docs:
        if not isinstance(doc, dict):
            continue  # empty document from a stray '---', or non-manifest YAML
        try:
            kind = doc.get("kind", "")
            if kind == "PersistentVolumeClaim":
                resource = _parse_pvc(doc)
            elif kind == "ConfigMap":
                resource = _parse_configmap(doc)
            else:
                continue  # out of scope, see module docstring
            if resource is not None:
                discovered.append(resource)
        except Exception as exc:  # noqa: BLE001 -- one malformed document must not abort the file
            logger.error("Unexpected error parsing a document in %s: %s -- skipping.", path, exc)
            continue

    return discovered


def scan_k8s_files(root: Path) -> list[DiscoveredResource]:
    """
    Walks for .yaml/.yml files. Deliberately EXCLUDES anything under
    .github/ -- GitHub Actions workflow files are also YAML but are
    not Kubernetes manifests, and parsing them here would produce
    meaningless "kind"-less documents (harmless, but wasted work and
    noisy logs at scale).
    """
    resources: list[DiscoveredResource] = []
    for pattern in ("*.yaml", "*.yml"):
        for yaml_file in root.rglob(pattern):
            if ".github" in yaml_file.parts:
                continue
            resources.extend(parse_k8s_file(yaml_file))
    return resources
    