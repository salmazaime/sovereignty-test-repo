# app/connectors/azure/client.py
"""
Azure auth via DefaultAzureCredential — picks up managed identity,
CLI login, env vars, etc. automatically, following Azure SDK's own
recommended pattern rather than hand-rolling credential resolution.
"""

import logging

from azure.core.exceptions import ClientAuthenticationError, HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient

logger = logging.getLogger(__name__)


class AzureClientFactory:
    def __init__(self, subscription_id: str) -> None:
        self.subscription_id = subscription_id
        self._credential = DefaultAzureCredential()

    def storage_client(self) -> StorageManagementClient | None:
        try:
            return StorageManagementClient(self._credential, self.subscription_id)
        except ClientAuthenticationError as exc:
            logger.error("Azure auth failed for storage client: %s", exc)
            return None

    def compute_client(self) -> ComputeManagementClient | None:
        try:
            return ComputeManagementClient(self._credential, self.subscription_id)
        except ClientAuthenticationError as exc:
            logger.error("Azure auth failed for compute client: %s", exc)
            return None

    def network_client(self) -> NetworkManagementClient | None:
        try:
            return NetworkManagementClient(self._credential, self.subscription_id)
        except ClientAuthenticationError as exc:
            logger.error("Azure auth failed for network client: %s", exc)
            return None

    def credential(self):
        return self._credential
        