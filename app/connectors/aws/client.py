# app/connectors/aws/client.py
"""
Thin AWS session wrapper. Region-scoped because most describe_*
calls are region-scoped in AWS's API design : a connector run always
targets one region at a time, iterated by the orchestrator (13.8).
"""

import logging

import boto3
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError

logger = logging.getLogger(__name__)


class AWSClientFactory:
    def __init__(self, region: str) -> None:
        self.region = region
        self._session = boto3.Session(region_name=region)

    def client(self, service_name: str):
        return self._session.client(service_name)

    def account_id(self) -> str | None:
        try:
            return self.client("sts").get_caller_identity()["Account"]
        except (ClientError, NoCredentialsError, EndpointConnectionError) as exc:
            logger.warning("Could not resolve AWS account id in %s: %s", self.region, exc)
            return None

