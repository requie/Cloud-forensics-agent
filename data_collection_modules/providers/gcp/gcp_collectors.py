"""
Google Cloud Platform-specific data collectors for the Cloud Forensics AI Agent.

This module provides collectors for gathering evidence from GCP resources
while maintaining forensic integrity and chain of custody.
"""

import datetime
import json
import logging
import os
from typing import Any, Dict, List, Optional, Union

from google.oauth2 import service_account
from google.cloud import compute_v1
from google.cloud import storage
from google.cloud import logging as gcp_logging
from google.cloud.logging_v2.types import LogEntry

from ...core.base_collector import BaseCollector
from ...utils import evidence_utils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class GCPBaseCollector(BaseCollector):
    """Base class for all GCP-specific collectors."""
    
    def __init__(self, case_id: str, evidence_storage_path: str, 
                project_id: str, credentials_file: Optional[str] = None):
        """
        Initialize the GCP collector.
        
        Args:
            case_id: Unique identifier for the forensic case
            evidence_storage_path: Path where collected evidence will be stored
            project_id: GCP project ID
            credentials_file: Optional path to service account credentials file
        """
        super().__init__(case_id, evidence_storage_path)
        self.project_id = project_id
        self.credentials_file = credentials_file
        self.credentials = self._get_credentials()
        
        logger.info(f"Initialized GCP collector for project {project_id}")
    
    def _get_credentials(self) -> Optional[service_account.Credentials]:
        """
        Get GCP credentials.
        
        Returns:
            GCP credentials object or None if using default credentials
        """
        if self.credentials_file:
            return service_account.Credentials.from_service_account_file(
                self.credentials_file
            )
        return None
    
    def collect(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Collect evidence from GCP resources.
        
        This method must be implemented by specific GCP collector subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")


class GCPComputeInstanceCollector(GCPBaseCollector):
    """Collector for GCP Compute Engine instance evidence."""
    
    def collect(self, zone: str, instance_name: str) -> Dict[str, Any]:
        """
        Collect evidence from a GCP Compute Engine instance.
        
        Args:
            zone: Zone where the instance is located
            instance_name: Name of the compute instance
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            # Create Compute Engine clients
            instance_client = compute_v1.InstancesClient(credentials=self.credentials)
            disk_client = compute_v1.DisksClient(credentials=self.credentials)
            snapshot_client = compute_v1.SnapshotsClient(credentials=self.credentials)
            
            # Get instance details
            instance = instance_client.get(
                project=self.project_id,
                zone=zone,
                instance=instance_name
            )
            
            # Convert instance object to dict for serialization
            instance_dict = {
                'id': instance.id,
                'name': instance.name,
                'machine_type': instance.machine_type,
                'status': instance.status,
                'zone': instance.zone,
                'creation_timestamp': instance.creation_timestamp,
                'network_interfaces': [
                    {
                        'network': ni.network,
                        'subnetwork': ni.subnetwork,
                        'network_ip': ni.network_ip,
                        'access_configs': [
                            {
                                'nat_ip': ac.nat_ip,
                                'type': ac.type_,
                                'name': ac.name
                            }
                            for ac in ni.access_configs
                        ]
                    }
                    for ni in instance.network_interfaces
                ],
                'disks': [
                    {
                        'boot': disk.boot,
                        'auto_delete': disk.auto_delete,
                        'device_name': disk.device_name,
                        'source': disk.source,
                        'interface': disk.interface,
                        'mode': disk.mode,
                        'type': disk.type_
                    }
                    for disk in instance.disks
                ],
                'metadata': {
                    'items': [
                        {
                            'key': item.key,
                            'value': item.value
                        }
                        for item in instance.metadata.items
                    ]
                } if instance.metadata and instance.metadata.items else {},
                'service_accounts': [
                    {
                        'email': sa.email,
                        'scopes': list(sa.scopes)
                    }
                    for sa in instance.service_accounts
                ]
            }
            
            # Save instance metadata
            metadata_path = self.save_evidence(
                instance_dict,
                'gcp_instance_metadata',
                instance_name
            )
            
            # Get serial port output
            try:
                serial_output = instance_client.get_serial_port_output(
                    project=self.project_id,
                    zone=zone,
                    instance=instance_name
                )
                
                serial_path = self.save_evidence(
                    serial_output.contents,
                    'gcp_serial_output',
                    instance_name
                )
            except Exception as e:
                logger.error(f"Error collecting serial port output: {str(e)}")
                serial_path = None
            
            # Create disk snapshots
            disk_snapshots = []
            for disk_info in instance_dict['disks']:
                disk_source = disk_info['source']
                disk_name = disk_source.split('/')[-1]
                
                try:
                    # Create snapshot name
                    snapshot_name = f"{disk_name}-forensic-{datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
                    
                    # Create snapshot
                    snapshot_request = compute_v1.Snapshot(
                        name=snapshot_name,
                        description=f"Forensic snapshot for case {self.case_id}"
                    )
                    
                    operation = disk_client.create_snapshot(
                        project=self.project_id,
                        zone=zone,
                        disk=disk_name,
                        snapshot_resource=snapshot_request
                    )
                    
                    # Wait for the operation to complete
                    while not operation.done():
                        import time
                        time.sleep(5)
                    
                    # Get snapshot details
                    snapshot = snapshot_client.get(
                        project=self.project_id,
                        snapshot=snapshot_name
                    )
                    
                    # Convert snapshot to dict for serialization
                    snapshot_dict = {
                        'id': snapshot.id,
                        'name': snapshot.name,
                        'status': snapshot.status,
                        'disk_size_gb': snapshot.disk_size_gb,
                        'storage_bytes': snapshot.storage_bytes,
                        'creation_timestamp': snapshot.creation_timestamp,
                        'source_disk': snapshot.source_disk
                    }
                    
                    # Save snapshot metadata
                    snapshot_path = self.save_evidence(
                        snapshot_dict,
                        'gcp_disk_snapshot',
                        disk_name
                    )
                    
                    disk_snapshots.append({
                        'disk_name': disk_name,
                        'disk_type': 'boot' if disk_info['boot'] else 'data',
                        'snapshot_name': snapshot_name,
                        'snapshot_id': snapshot.id,
                        'metadata_path': snapshot_path
                    })
                    
                except Exception as e:
                    logger.error(f"Error creating snapshot for disk {disk_name}: {str(e)}")
            
            # Get firewall rules applicable to the instance
            firewall_rules = []
            try:
                firewall_client = compute_v1.FirewallsClient(credentials=self.credentials)
                
                # Get all firewall rules in the project
                all_firewalls = firewall_client.list(project=self.project_id)
                
                # Filter for rules that might apply to this instance
                # This is a simplification - in a real implementation, you'd need to check
                # network tags, service accounts, and network details more thoroughly
                for firewall in all_firewalls:
                    # Check if the firewall applies to the instance's network
                    instance_networks = [ni.network.split('/')[-1] for ni in instance.network_interfaces]
                    firewall_network = firewall.network.split('/')[-1]
                    
                    if firewall_network in instance_networks:
                        # Check if the firewall targets this instance's tags
                        if firewall.target_tags:
                            if any(tag in instance.tags.items for tag in firewall.target_tags):
                                applicable = True
                            else:
                                applicable = False
                        else:
                            # If no target tags, the rule applies to all instances in the network
                            applicable = True
                        
                        if applicable:
                            firewall_dict = {
                                'id': firewall.id,
                                'name': firewall.name,
                                'description': firewall.description,
                                'network': firewall.network,
                                'direction': firewall.direction,
                                'priority': firewall.priority,
                                'source_ranges': list(firewall.source_ranges) if firewall.source_ranges else [],
                                'destination_ranges': list(firewall.destination_ranges) if firewall.destination_ranges else [],
                                'allowed': [
                                    {
                                        'protocol': allowed.protocol,
                                        'ports': list(allowed.ports) if allowed.ports else []
                                    }
                                    for allowed in firewall.allowed
                                ] if firewall.allowed else [],
                                'denied': [
                                    {
                                        'protocol': denied.protocol,
                                        'ports': list(denied.ports) if denied.ports else []
                                    }
                                    for denied in firewall.denied
                                ] if firewall.denied else [],
                                'target_tags': list(firewall.target_tags) if firewall.target_tags else []
                            }
                            
                            # Save firewall rule metadata
                            firewall_path = self.save_evidence(
                                firewall_dict,
                                'gcp_firewall_rule',
                                firewall.name
                            )
                            
                            firewall_rules.append({
                                'name': firewall.name,
                                'metadata_path': firewall_path
                            })
            
            except Exception as e:
                logger.error(f"Error collecting firewall rules: {str(e)}")
            
            # Collect instance logs
            instance_logs = []
            try:
                logging_client = gcp_logging.Client(
                    project=self.project_id,
                    credentials=self.credentials
                )
                
                # Define log filters for the instance
                filters = [
                    f'resource.type="gce_instance"',
                    f'resource.labels.instance_id="{instance.id}"',
                    f'timestamp>="{(datetime.datetime.utcnow() - datetime.timedelta(days=7)).isoformat()}"'
                ]
                
                # Get logs
                entries = logging_client.list_entries(
                    filter_=' AND '.join(filters),
                    page_size=1000
                )
                
                # Convert log entries to dict for serialization
                log_entries = []
                for entry in entries:
                    entry_dict = {
                        'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                        'severity': entry.severity,
                        'log_name': entry.log_name,
                        'resource': {
                            'type': entry.resource.type,
                            'labels': dict(entry.resource.labels)
                        },
                        'labels': dict(entry.labels) if entry.labels else {},
                        'text_payload': entry.payload if isinstance(entry.payload, str) else None,
                        'json_payload': entry.payload if isinstance(entry.payload, dict) else None
                    }
                    log_entries.append(entry_dict)
                
                if log_entries:
                    # Save log entries
                    logs_path = self.save_evidence(
                        log_entries,
                        'gcp_instance_logs',
                        instance_name
                    )
                    
                    instance_logs.append({
                        'log_count': len(log_entries),
                        'metadata_path': logs_path
                    })
            
            except Exception as e:
                logger.error(f"Error collecting instance logs: {str(e)}")
            
            # Compile collection results
            collection_results = {
                'instance_name': instance_name,
                'zone': zone,
                'metadata_path': metadata_path,
                'serial_output_path': serial_path,
                'disk_snapshots': disk_snapshots,
                'firewall_rules': firewall_rules,
                'instance_logs': instance_logs
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting GCP Compute Engine instance evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()


class GCPCloudLoggingCollector(GCPBaseCollector):
    """Collector for GCP Cloud Logging evidence."""
    
    def collect(self, start_time: datetime.datetime, 
               end_time: Optional[datetime.datetime] = None,
               filter_str: Optional[str] = None) -> Dict[str, Any]:
        """
        Collect GCP Cloud Logging logs for a specified time period.
        
        Args:
            start_time: Start time for log collection
            end_time: Optional end time (defaults to current time)
            filter_str: Optional additional filter string for the logs
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            # Set end time to now if not provided
            if not end_time:
                end_time = datetime.datetime.utcnow()
            
            # Create logging client
            logging_client = gcp_logging.Client(
                project=self.project_id,
                credentials=self.credentials
            )
            
            # Build filter string
            filters = [
                f'timestamp>="{start_time.isoformat()}"',
                f'timestamp<="{end_time.isoformat()}"'
            ]
            
            if filter_str:
                filters.append(filter_str)
            
            filter_string = ' AND '.join(filters)
            
            # Get logs
            entries = logging_client.list_entries(
                filter_=filter_string,
                page_size=1000  # Adjust as needed
            )
            
            # Convert log entries to dict for serialization
            log_entries = []
            for entry in entries:
                entry_dict = {
                    'timestamp': entry.timestamp.isoformat() if entry.timestamp else None,
                    'severity': entry.severity,
                    'log_name': entry.log_name,
                    'resource': {
                        'type': entry.resource.type,
                        'labels': dict(entry.resource.labels)
                    },
                    'labels': dict(entry.labels) if entry.labels else {},
                    'text_payload': entry.payload if isinstance(entry.payload, str) else None,
                    'json_payload': entry.payload if isinstance(entry.payload, dict) else None
                }
                log_entries.append(entry_dict)
            
            # Save all logs
            all_logs_path = self.save_evidence(
                log_entries,
                'gcp_cloud_logs',
                f"project_{self.project_id}"
            )
            
            # Group logs by resource type for easier analysis
            resource_type_logs = {}
            for log in log_entries:
                resource_type = log['resource']['type']
                
                if resource_type not in resource_type_logs:
                    resource_type_logs[resource_type] = []
                
                resource_type_logs[resource_type].append(log)
            
            # Save resource type specific logs
            resource_log_paths = {}
            for resource_type, logs in resource_type_logs.items():
                if logs:
                    resource_log_path = self.save_evidence(
                        logs,
                        'gcp_cloud_logs',
                        f"resource_{resource_type}"
                    )
                    resource_log_paths[resource_type] = resource_log_path
            
            # Compile collection results
            collection_results = {
                'time_period': {
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat()
                },
                'filter': filter_string,
                'all_logs_path': all_logs_path,
                'total_log_entries': len(log_entries),
                'resource_type_logs': [
                    {
                        'resource_type': resource_type,
                        'log_count': len(resource_type_logs[resource_type]),
                        'metadata_path': path
                    }
                    for resource_type, path in resource_log_paths.items()
                ]
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting GCP Cloud Logging logs: {str(e)}")
            raise
        
        finally:
            self.end_collection()


class GCPStorageCollector(GCPBaseCollector):
    """Collector for GCP Cloud Storage evidence."""
    
    def collect(self, bucket_name: str, prefix: Optional[str] = None,
               max_objects: int = 100) -> Dict[str, Any]:
        """
        Collect evidence from a GCP Cloud Storage bucket.
        
        Args:
            bucket_name: Name of the storage bucket
            prefix: Optional prefix to filter objects
            max_objects: Maximum number of objects to collect
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            # Create storage client
            storage_client = storage.Client(
                project=self.project_id,
                credentials=self.credentials
            )
            
            # Get bucket
            bucket = storage_client.get_bucket(bucket_name)
            
            # Get bucket metadata
            bucket_metadata = {
                'name': bucket.name,
                'id': bucket.id,
                'project_number': bucket.project_number,
                'location': bucket.location,
                'location_type': bucket.location_type,
                'storage_class': bucket.storage_class,
                'time_created': bucket.time_created.isoformat() if bucket.time_created else None,
                'versioning_enabled': bucket.versioning_enabled,
                'labels': bucket.labels,
                'lifecycle_rules': bucket.lifecycle_rules,
                'cors': bucket.cors,
                'default_event_based_hold': bucket.default_event_based_hold,
                'requester_pays': bucket.requester_pays,
                'retention_policy': {
                    'retention_period': bucket.retention_period,
                    'effective_time': bucket.effective_time.isoformat() if bucket.effective_time else None,
                    'locked': bucket.locked
                } if bucket.retention_period else None,
                'iam_policy': bucket.get_iam_policy().to_api_repr() if bucket.get_iam_policy() else None
            }
            
            # Save bucket metadata
            metadata_path = self.save_evidence(
                bucket_metadata,
                'gcp_storage_bucket_metadata',
                bucket_name
            )
            
            # List objects in the bucket
            blobs = list(bucket.list_blobs(prefix=prefix, max_results=max_objects))
            
            # Save object listing
            blob_listing = [
                {
                    'name': blob.name,
                    'size': blob.size,
                    'updated': blob.updated.isoformat() if blob.updated else None,
                    'storage_class': blob.storage_class,
                    'content_type': blob.content_type,
                    'time_created': blob.time_created.isoformat() if blob.time_created else None,
                    'md5_hash': blob.md5_hash,
                    'metadata': blob.metadata,
                    'cache_control': blob.cache_control,
                    'content_disposition': blob.content_disposition,
                    'content_encoding': blob.content_encoding,
                    'content_language': blob.content_language,
                    'etag': blob.etag,
                    'generation': blob.generation,
                    'metageneration': blob.metageneration,
                    'temporary_hold': blob.temporary_hold,
                    'event_based_hold': blob.event_based_hold,
                    'retention_expiration_time': blob.retention_expiration_time.isoformat() if blob.retention_expiration_time else None,
                    'custom_time': blob.custom_time.isoformat() if blob.custom_time else None,
                    'kms_key_name': blob.kms_key_name
                }
                for blob in blobs
            ]
            
            objects_path = self.save_evidence(
                blob_listing,
                'gcp_storage_object_listing',
                bucket_name
            )
            
            # Download a sample of objects (first 5)
            collected_objects = []
            for i, blob in enumerate(blobs[:5]):
                try:
                    # Download object
                    content = blob.download_as_bytes()
                    
                    # Save object content
                    object_path = self.save_evidence(
                        content,
                        'gcp_storage_object',
                        f"{bucket_name}_{i}"
                    )
                    
                    collected_objects.append({
                        'name': blob.name,
                        'size': blob.size,
                        'metadata_path': object_path
                    })
                    
                except Exception as e:
                    logger.error(f"Error downloading object {blob.name}: {str(e)}")
            
            # Get bucket access logs if available
            access_logs = []
            try:
                # Check if logging is enabled for this bucket
                logging_config = bucket.get_logging()
                
                if logging_config and logging_config.get('logBucket'):
                    log_bucket_name = logging_config.get('logBucket')
                    log_prefix = logging_config.get('logObjectPrefix', '')
                    
                    # Get the logging bucket
                    log_bucket = storage_client.get_bucket(log_bucket_name)
                    
                    # List log objects
                    log_blobs = list(log_bucket.list_blobs(prefix=log_prefix, max_results=100))
                    
                    # Save log listing
                    logs_path = self.save_evidence(
                        [
                            {
                                'name': blob.name,
                                'size': blob.size,
                                'updated': blob.updated.isoformat() if blob.updated else None
                            }
                            for blob in log_blobs
                        ],
                        'gcp_storage_access_logs_listing',
                        bucket_name
                    )
                    
                    # Download a sample of log files
                    for i, log_blob in enumerate(log_blobs[:5]):
                        try:
                            # Download log
                            log_content = log_blob.download_as_string().decode('utf-8')
                            
                            # Save log content
                            log_path = self.save_evidence(
                                log_content,
                                'gcp_storage_access_log',
                                f"{bucket_name}_{i}"
                            )
                            
                            access_logs.append({
                                'name': log_blob.name,
                                'metadata_path': log_path
                            })
                            
                        except Exception as e:
                            logger.error(f"Error downloading log file {log_blob.name}: {str(e)}")
                
            except Exception as e:
                logger.error(f"Error collecting access logs for {bucket_name}: {str(e)}")
            
            # Compile collection results
            collection_results = {
                'bucket_name': bucket_name,
                'metadata_path': metadata_path,
                'objects_path': objects_path,
                'object_count': len(blobs),
                'collected_objects': collected_objects,
                'access_logs': access_logs
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting GCP Storage evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()
