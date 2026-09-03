# app/connectors/azure/vm_connector.py
"""
VM discovery: VMs -> attached NICs -> public IP, subnet/VNet, NSG.
Azure's VM object doesn't embed networking info directly — it holds
NIC references that must be separately resolved via the network
client, which is why this connector needs BOTH compute and network
clients, unlike the single-client AWS EC2 connector.
"""

import logging

from azure.core.exceptions import HttpResponseError

from app.connectors.azure.client import AzureClientFactory
from app.connectors.base import DiscoveredResource

logger = logging.getLogger(__name__)


def _resource_group_from_id(resource_id: str) -> str:
    # Azure resource IDs embed the resource group: .../resourceGroups/<rg>/...
    parts = resource_id.split("/")
    return parts[parts.index("resourceGroups") + 1]


def _nic_details(network_client, nic_id: str) -> dict:
    rg = _resource_group_from_id(nic_id)
    nic_name = nic_id.split("/")[-1]
    try:
        nic = network_client.network_interfaces.get(rg, nic_name)
    except HttpResponseError as exc:
        logger.warning("Could not get NIC %s: %s", nic_name, exc)
        return {}

    public_ip = None
    subnet_id = None
    for ip_config in nic.ip_configurations or []:
        if ip_config.public_ip_address:
            public_ip = ip_config.public_ip_address.id  # resolving the actual IP needs a further call; ID is enough to flag "has one"
        if ip_config.subnet:
            subnet_id = ip_config.subnet.id

    nsg_ids = [nic.network_security_group.id] if nic.network_security_group else []
    return {"public_ip_present": public_ip is not None, "subnet_id": subnet_id, "nsg_ids": nsg_ids}


def discover_virtual_machines(
    factory: AzureClientFactory, resource_group: str
) -> list[DiscoveredResource]:
    compute_client = factory.compute_client()
    network_client = factory.network_client()
    resources: list[DiscoveredResource] = []
    if compute_client is None or network_client is None:
        return resources

    try:
        vms = list(compute_client.virtual_machines.list(resource_group))
    except HttpResponseError as exc:
        logger.error("Could not list VMs in %s: %s — skipping.", resource_group, exc)
        return resources

    for vm in vms:
        try:
            nic_refs = vm.network_profile.network_interfaces if vm.network_profile else []
            is_public = False
            subnet_id = None
            nsg_ids: list[str] = []
            for nic_ref in nic_refs:
                details = _nic_details(network_client, nic_ref.id)
                is_public = is_public or details.get("public_ip_present", False)
                subnet_id = subnet_id or details.get("subnet_id")
                nsg_ids.extend(details.get("nsg_ids", []))

            managed_identity = bool(vm.identity and vm.identity.type != "None")
            os_disk_encrypted = bool(
                vm.storage_profile
                and vm.storage_profile.os_disk
                and vm.storage_profile.os_disk.encryption_settings
                and vm.storage_profile.os_disk.encryption_settings.enabled
            )

            resources.append(DiscoveredResource(
                cloud_provider="azure",
                account_id=factory.subscription_id,
                region=vm.location,
                resource_id=vm.id,
                resource_type="azure_vm",
                name=vm.name,
                granularity="workload",
                is_publicly_accessible=is_public,
                vpc_or_vnet_id=subnet_id,
                security_group_ids=nsg_ids,
                encryption_enabled=os_disk_encrypted,
                encryption_key_type="PLATFORM_MANAGED" if os_disk_encrypted else None,
                tags=dict(vm.tags or {}),
                dependencies=[],  # managed_identity is metadata, not yet a graph edge — see note below
            ))
        except Exception as exc:  # noqa: BLE001
            logger.error("Unexpected error processing VM %s: %s — skipping.", vm.name, exc)
            continue

    return resources
    