# app/connectors/aws/ec2_connector.py
"""
EC2 discovery: instances -> networking (VPC, subnet, public IP,
security groups), attached IAM instance profile, attached EBS
volume encryption status.
"""

import logging

from botocore.exceptions import ClientError

from app.connectors.aws.client import AWSClientFactory
from app.connectors.base import DiscoveredResource

logger = logging.getLogger(__name__)


def _volume_encryption(ec2_client, volume_ids: list[str]) -> tuple[bool, str | None]:
    if not volume_ids:
        return False, None
    try:
        volumes = ec2_client.describe_volumes(VolumeIds=volume_ids)["Volumes"]
    except ClientError as exc:
        logger.warning("Could not describe volumes %s: %s", volume_ids, exc)
        return False, None

    all_encrypted = all(v.get("Encrypted", False) for v in volumes)
    key_type = None
    if all_encrypted and volumes:
        key_type = "AWS_KMS" if volumes[0].get("KmsKeyId") else "AWS_MANAGED"
    return all_encrypted, key_type


def discover_ec2_instances(factory: AWSClientFactory) -> list[DiscoveredResource]:
    ec2 = factory.client("ec2")
    account_id = factory.account_id() or "unknown"
    resources: list[DiscoveredResource] = []

    try:
        paginator = ec2.get_paginator("describe_instances")
        reservations = []
        for page in paginator.paginate():
            reservations.extend(page.get("Reservations", []))
    except ClientError as exc:
        logger.error("Could not describe EC2 instances: %s — skipping EC2 discovery entirely.", exc)
        return resources

    for reservation in reservations:
        for instance in reservation.get("Instances", []):
            instance_id = instance["InstanceId"]
            try:
                public_ip = instance.get("PublicIpAddress")
                security_groups = [sg["GroupId"] for sg in instance.get("SecurityGroups", [])]
                volume_ids = [
                    m["Ebs"]["VolumeId"]
                    for m in instance.get("BlockDeviceMappings", [])
                    if "Ebs" in m
                ]
                enc_enabled, key_type = _volume_encryption(ec2, volume_ids)
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}

                resources.append(DiscoveredResource(
                    cloud_provider="aws",
                    account_id=account_id,
                    region=factory.region,
                    resource_id=f"arn:aws:ec2:{factory.region}:{account_id}:instance/{instance_id}",
                    resource_type="ec2_instance",
                    name=tags.get("Name", instance_id),
                    granularity="workload",
                    is_publicly_accessible=public_ip is not None,
                    allowed_ip_ranges=[public_ip] if public_ip else [],
                    vpc_or_vnet_id=instance.get("VpcId"),
                    security_group_ids=security_groups,
                    encryption_enabled=enc_enabled,
                    encryption_key_type=key_type,
                    tags=tags,
                ))
            except Exception as exc:  # noqa: BLE001
                logger.error("Unexpected error processing instance %s: %s — skipping.", instance_id, exc)
                continue

    return resources
    