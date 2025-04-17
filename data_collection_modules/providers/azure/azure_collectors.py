"""
Azure-specific data collectors for the Cloud Forensics AI Agent.

This module provides collectors for gathering evidence from Azure cloud resources
while maintaining forensic integrity and chain of custody.
"""

import datetime
import json
import logging
import os
from typing import Any, Dict, List, Optional, Union

from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.monitor import MonitorManagementClient
from azure.storage.blob import BlobServiceClient
from azure.mgmt.resource import ResourceManagementClient

from ...core.base_collector import BaseCollector
from ...utils import evidence_utils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AzureBaseCollector(BaseCollector):
    """Base class for all Azure-specific collectors."""
    
    def __init__(self, case_id: str, evidence_storage_path: str, 
                subscription_id: str, tenant_id: Optional[str] = None,
                client_id: Optional[str] = None, client_secret: Optional[str] = None):
        """
        Initialize the Azure collector.
        
        Args:
            case_id: Unique identifier for the forensic case
            evidence_storage_path: Path where collected evidence will be stored
            subscription_id: Azure subscription ID
            tenant_id: Optional Azure tenant ID
            client_id: Optional Azure client ID
            client_secret: Optional Azure client secret
        """
        super().__init__(case_id, evidence_storage_path)
        self.subscription_id = subscription_id
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.credential = self._get_credential()
        
        logger.info(f"Initialized Azure collector for subscription {subscription_id}")
    
    def _get_credential(self) -> DefaultAzureCredential:
        """
        Get Azure credential object.
        
        Returns:
            Azure credential object
        """
        # If specific credentials are provided, use them
        # Otherwise, use DefaultAzureCredential which tries multiple authentication methods
        return DefaultAzureCredential(
            tenant_id=self.tenant_id,
            client_id=self.client_id,
            client_secret=self.client_secret
        )
    
    def collect(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Collect evidence from Azure resources.
        
        This method must be implemented by specific Azure collector subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")


class AzureVMCollector(AzureBaseCollector):
    """Collector for Azure Virtual Machine evidence."""
    
    def collect(self, resource_group: str, vm_name: str) -> Dict[str, Any]:
        """
        Collect evidence from an Azure Virtual Machine.
        
        Args:
            resource_group: Name of the resource group containing the VM
            vm_name: Name of the virtual machine
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            # Create compute client
            compute_client = ComputeManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
            
            # Get VM details
            vm = compute_client.virtual_machines.get(
                resource_group_name=resource_group,
                vm_name=vm_name,
                expand='instanceView'
            )
            
            # Convert VM object to dict for serialization
            vm_dict = vm.as_dict()
            
            # Save VM metadata
            metadata_path = self.save_evidence(
                vm_dict,
                'azure_vm_metadata',
                vm_name
            )
            
            # Get VM status
            status_dict = {
                'statuses': [status.as_dict() for status in vm.instance_view.statuses],
                'vm_agent': vm.instance_view.vm_agent.as_dict() if vm.instance_view.vm_agent else None,
                'maintenance_redeploy_status': vm.instance_view.maintenance_redeploy_status.as_dict() 
                    if vm.instance_view.maintenance_redeploy_status else None
            }
            
            status_path = self.save_evidence(
                status_dict,
                'azure_vm_status',
                vm_name
            )
            
            # Create disk snapshots
            disk_snapshots = []
            
            # Get OS disk
            if vm.storage_profile.os_disk:
                os_disk_name = vm.storage_profile.os_disk.name
                try:
                    # Create snapshot
                    snapshot_name = f"{os_disk_name}-forensic-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                    
                    # Get the OS disk
                    os_disk = compute_client.disks.get(
                        resource_group_name=resource_group,
                        disk_name=os_disk_name
                    )
                    
                    # Create the snapshot
                    snapshot_creation = compute_client.snapshots.begin_create_or_update(
                        resource_group_name=resource_group,
                        snapshot_name=snapshot_name,
                        snapshot={
                            'location': vm.location,
                            'creation_data': {
                                'create_option': 'Copy',
                                'source_uri': os_disk.id
                            }
                        }
                    )
                    
                    # Wait for snapshot creation to complete
                    snapshot = snapshot_creation.result()
                    
                    # Save snapshot metadata
                    snapshot_path = self.save_evidence(
                        snapshot.as_dict(),
                        'azure_disk_snapshot',
                        os_disk_name
                    )
                    
                    disk_snapshots.append({
                        'disk_name': os_disk_name,
                        'disk_type': 'OS',
                        'snapshot_name': snapshot_name,
                        'snapshot_id': snapshot.id,
                        'metadata_path': snapshot_path
                    })
                    
                except Exception as e:
                    logger.error(f"Error creating snapshot for OS disk {os_disk_name}: {str(e)}")
            
            # Get data disks
            for data_disk in vm.storage_profile.data_disks:
                data_disk_name = data_disk.name
                try:
                    # Create snapshot
                    snapshot_name = f"{data_disk_name}-forensic-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                    
                    # Get the data disk
                    data_disk_obj = compute_client.disks.get(
                        resource_group_name=resource_group,
                        disk_name=data_disk_name
                    )
                    
                    # Create the snapshot
                    snapshot_creation = compute_client.snapshots.begin_create_or_update(
                        resource_group_name=resource_group,
                        snapshot_name=snapshot_name,
                        snapshot={
                            'location': vm.location,
                            'creation_data': {
                                'create_option': 'Copy',
                                'source_uri': data_disk_obj.id
                            }
                        }
                    )
                    
                    # Wait for snapshot creation to complete
                    snapshot = snapshot_creation.result()
                    
                    # Save snapshot metadata
                    snapshot_path = self.save_evidence(
                        snapshot.as_dict(),
                        'azure_disk_snapshot',
                        data_disk_name
                    )
                    
                    disk_snapshots.append({
                        'disk_name': data_disk_name,
                        'disk_type': 'Data',
                        'lun': data_disk.lun,
                        'snapshot_name': snapshot_name,
                        'snapshot_id': snapshot.id,
                        'metadata_path': snapshot_path
                    })
                    
                except Exception as e:
                    logger.error(f"Error creating snapshot for data disk {data_disk_name}: {str(e)}")
            
            # Get network interfaces
            network_interfaces = []
            for nic_ref in vm.network_profile.network_interfaces:
                nic_id = nic_ref.id
                nic_name = nic_id.split('/')[-1]
                
                try:
                    # Create network client
                    from azure.mgmt.network import NetworkManagementClient
                    network_client = NetworkManagementClient(
                        credential=self.credential,
                        subscription_id=self.subscription_id
                    )
                    
                    # Get network interface details
                    nic = network_client.network_interfaces.get(
                        resource_group_name=resource_group,
                        network_interface_name=nic_name
                    )
                    
                    # Save NIC metadata
                    nic_path = self.save_evidence(
                        nic.as_dict(),
                        'azure_network_interface',
                        nic_name
                    )
                    
                    network_interfaces.append({
                        'nic_name': nic_name,
                        'nic_id': nic_id,
                        'metadata_path': nic_path
                    })
                    
                    # Get NSG if attached
                    if nic.network_security_group:
                        nsg_id = nic.network_security_group.id
                        nsg_name = nsg_id.split('/')[-1]
                        
                        nsg = network_client.network_security_groups.get(
                            resource_group_name=resource_group,
                            network_security_group_name=nsg_name
                        )
                        
                        # Save NSG metadata
                        nsg_path = self.save_evidence(
                            nsg.as_dict(),
                            'azure_network_security_group',
                            nsg_name
                        )
                        
                        network_interfaces[-1]['nsg'] = {
                            'nsg_name': nsg_name,
                            'nsg_id': nsg_id,
                            'metadata_path': nsg_path
                        }
                    
                except Exception as e:
                    logger.error(f"Error collecting network interface {nic_name}: {str(e)}")
            
            # Get VM diagnostic settings and logs
            diagnostic_logs = []
            try:
                # Create monitor client
                monitor_client = MonitorManagementClient(
                    credential=self.credential,
                    subscription_id=self.subscription_id
                )
                
                # Get diagnostic settings
                diagnostic_settings = monitor_client.diagnostic_settings.list(
                    resource_uri=vm.id
                )
                
                for setting in diagnostic_settings:
                    setting_dict = setting.as_dict()
                    
                    # Save diagnostic setting metadata
                    setting_path = self.save_evidence(
                        setting_dict,
                        'azure_diagnostic_setting',
                        f"{vm_name}_{setting.name}"
                    )
                    
                    diagnostic_logs.append({
                        'setting_name': setting.name,
                        'metadata_path': setting_path
                    })
                    
                    # If logs go to storage account, try to collect them
                    if setting.storage_account_id:
                        storage_account_id = setting.storage_account_id
                        storage_account_name = storage_account_id.split('/')[-1]
                        
                        # Get storage account key
                        storage_client = StorageManagementClient(
                            credential=self.credential,
                            subscription_id=self.subscription_id
                        )
                        
                        keys = storage_client.storage_accounts.list_keys(
                            resource_group_name=resource_group,
                            account_name=storage_account_name
                        )
                        
                        storage_key = keys.keys[0].value
                        
                        # Connect to blob storage
                        blob_service_client = BlobServiceClient(
                            account_url=f"https://{storage_account_name}.blob.core.windows.net",
                            credential=storage_key
                        )
                        
                        # Look for diagnostic logs container
                        containers = blob_service_client.list_containers(
                            name_starts_with="insights-logs-"
                        )
                        
                        for container in containers:
                            container_client = blob_service_client.get_container_client(container.name)
                            
                            # List blobs (limited to recent ones)
                            blobs = list(container_client.list_blobs(max_results=10))
                            
                            for blob in blobs:
                                # Download blob content
                                blob_client = container_client.get_blob_client(blob.name)
                                blob_data = blob_client.download_blob().readall()
                                
                                # Save blob content
                                blob_path = self.save_evidence(
                                    blob_data,
                                    'azure_diagnostic_log',
                                    f"{vm_name}_{container.name}_{blob.name}"
                                )
                                
                                diagnostic_logs.append({
                                    'container': container.name,
                                    'blob_name': blob.name,
                                    'metadata_path': blob_path
                                })
                
            except Exception as e:
                logger.error(f"Error collecting diagnostic logs: {str(e)}")
            
            # Compile collection results
            collection_results = {
                'vm_name': vm_name,
                'resource_group': resource_group,
                'metadata_path': metadata_path,
                'status_path': status_path,
                'disk_snapshots': disk_snapshots,
                'network_interfaces': network_interfaces,
                'diagnostic_logs': diagnostic_logs
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting Azure VM evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()


class AzureActivityLogCollector(AzureBaseCollector):
    """Collector for Azure Activity Log evidence."""
    
    def collect(self, start_time: datetime.datetime, 
               end_time: Optional[datetime.datetime] = None,
               filter_str: Optional[str] = None) -> Dict[str, Any]:
        """
        Collect Azure Activity Logs for a specified time period.
        
        Args:
            start_time: Start time for log collection
            end_time: Optional end time (defaults to current time)
            filter_str: Optional filter string for the logs
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            # Set end time to now if not provided
            if not end_time:
                end_time = datetime.datetime.utcnow()
            
            # Create monitor client
            monitor_client = MonitorManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
            
            # Format datetime objects for Azure API
            filter_params = f"eventTimestamp ge '{start_time.isoformat()}' and eventTimestamp le '{end_time.isoformat()}'"
            
            if filter_str:
                filter_params = f"{filter_params} and {filter_str}"
            
            # Get activity logs
            logs = monitor_client.activity_logs.list(
                filter=filter_params
            )
            
            # Convert iterator to list for serialization
            log_entries = [log.as_dict() for log in logs]
            
            # Save activity logs
            logs_path = self.save_evidence(
                log_entries,
                'azure_activity_logs',
                f"subscription_{self.subscription_id}"
            )
            
            # Group logs by resource groups for easier analysis
            resource_group_logs = {}
            for log in log_entries:
                # Extract resource group from resource ID if available
                resource_id = log.get('resource_id', '')
                if '/resourceGroups/' in resource_id:
                    parts = resource_id.split('/')
                    rg_index = parts.index('resourceGroups')
                    if rg_index + 1 < len(parts):
                        resource_group = parts[rg_index + 1]
                        
                        if resource_group not in resource_group_logs:
                            resource_group_logs[resource_group] = []
                        
                        resource_group_logs[resource_group].append(log)
            
            # Save resource group specific logs
            rg_log_paths = {}
            for rg, rg_logs in resource_group_logs.items():
                if rg_logs:
                    rg_log_path = self.save_evidence(
                        rg_logs,
                        'azure_activity_logs',
                        f"resourcegroup_{rg}"
                    )
                    rg_log_paths[rg] = rg_log_path
            
            # Compile collection results
            collection_results = {
                'time_period': {
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat()
                },
                'filter': filter_params,
                'logs_path': logs_path,
                'total_log_entries': len(log_entries),
                'resource_group_logs': [
                    {
                        'resource_group': rg,
                        'log_count': len(resource_group_logs[rg]),
                        'metadata_path': path
                    }
                    for rg, path in rg_log_paths.items()
                ]
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting Azure Activity Logs: {str(e)}")
            raise
        
        finally:
            self.end_collection()


class AzureStorageCollector(AzureBaseCollector):
    """Collector for Azure Storage Account evidence."""
    
    def collect(self, resource_group: str, storage_account_name: str,
               container_name: Optional[str] = None,
               blob_prefix: Optional[str] = None,
               max_blobs: int = 100) -> Dict[str, Any]:
        """
        Collect evidence from an Azure Storage Account.
        
        Args:
            resource_group: Name of the resource group
            storage_account_name: Name of the storage account
            container_name: Optional specific container to collect from
            blob_prefix: Optional prefix to filter blobs
            max_blobs: Maximum number of blobs to collect
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            # Create storage management client
            storage_client = StorageManagementClient(
                credential=self.credential,
                subscription_id=self.subscription_id
            )
            
            # Get storage account details
            storage_account = storage_client.storage_accounts.get_properties(
                resource_group_name=resource_group,
                account_name=storage_account_name
            )
            
            # Save storage account metadata
            account_path = self.save_evidence(
                storage_account.as_dict(),
                'azure_storage_account',
                storage_account_name
            )
            
            # Get storage account keys
            keys = storage_client.storage_accounts.list_keys(
                resource_group_name=resource_group,
                account_name=storage_account_name
            )
            
            storage_key = keys.keys[0].value
            
            # Connect to blob storage
            blob_service_client = BlobServiceClient(
                account_url=f"https://{storage_account_name}.blob.core.windows.net",
                credential=storage_key
            )
            
            collected_containers = []
            
            # If specific container is specified, only collect from that one
            if container_name:
                containers_to_check = [container_name]
            else:
                # List all containers
                containers = blob_service_client.list_containers()
                containers_to_check = [container.name for container in containers]
            
            for container in containers_to_check:
                try:
                    container_client = blob_service_client.get_container_client(container)
                    
                    # Get container properties
                    container_properties = container_client.get_container_properties()
                    
                    # Save container metadata
                    container_path = self.save_evidence(
                        {
                            'name': container,
                            'properties': {
                                k: str(v) for k, v in container_properties.items()
                                if k not in ['lease', 'copy']  # These contain non-serializable objects
                            }
                        },
                        'azure_storage_container',
                        f"{storage_account_name}_{container}"
                    )
                    
                    # List blobs in the container
                    blob_list_params = {'max_results': max_blobs}
                    if blob_prefix:
                        blob_list_params['name_starts_with'] = blob_prefix
                    
                    blobs = list(container_client.list_blobs(**blob_list_params))
                    
                    # Save blob listing
                    blobs_path = self.save_evidence(
                        [blob.as_dict() for blob in blobs],
                        'azure_storage_blob_listing',
                        f"{storage_account_name}_{container}"
                    )
                    
                    # Download a sample of blobs (first 5)
                    collected_blobs = []
                    for i, blob in enumerate(blobs[:5]):
                        try:
                            blob_client = container_client.get_blob_client(blob.name)
                            blob_data = blob_client.download_blob().readall()
                            
                            # Save blob content
                            blob_path = self.save_evidence(
                                blob_data,
                                'azure_storage_blob',
                                f"{storage_account_name}_{container}_{i}"
                            )
                            
                            collected_blobs.append({
                                'name': blob.name,
                                'size': blob.size,
                                'metadata_path': blob_path
                            })
                            
                        except Exception as e:
                            logger.error(f"Error downloading blob {blob.name}: {str(e)}")
                    
                    collected_containers.append({
                        'name': container,
                        'metadata_path': container_path,
                        'blobs_listing_path': blobs_path,
                        'blob_count': len(blobs),
                        'collected_blobs': collected_blobs
                    })
                    
                except Exception as e:
                    logger.error(f"Error collecting container {container}: {str(e)}")
            
            # Compile collection results
            collection_results = {
                'storage_account_name': storage_account_name,
                'resource_group': resource_group,
                'metadata_path': account_path,
                'containers': collected_containers
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting Azure Storage evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()
