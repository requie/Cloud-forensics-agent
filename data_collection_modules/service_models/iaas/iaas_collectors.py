"""
Service model-specific collectors for IaaS environments in the Cloud Forensics AI Agent.

This module provides collectors for gathering evidence from Infrastructure as a Service
environments across different cloud providers while maintaining forensic integrity.
"""

import datetime
import json
import logging
import os
from typing import Any, Dict, List, Optional, Union

from ...core.base_collector import BaseCollector
from ...providers.aws import aws_collectors
from ...providers.azure import azure_collectors
from ...providers.gcp import gcp_collectors
from ...utils import evidence_utils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class IaaSCollector(BaseCollector):
    """Collector for Infrastructure as a Service evidence across cloud providers."""
    
    def __init__(self, case_id: str, evidence_storage_path: str, 
                cloud_provider: str, **provider_kwargs):
        """
        Initialize the IaaS collector.
        
        Args:
            case_id: Unique identifier for the forensic case
            evidence_storage_path: Path where collected evidence will be stored
            cloud_provider: Cloud provider name ('aws', 'azure', or 'gcp')
            **provider_kwargs: Provider-specific arguments
        """
        super().__init__(case_id, evidence_storage_path)
        self.cloud_provider = cloud_provider.lower()
        self.provider_kwargs = provider_kwargs
        self.provider_collector = self._get_provider_collector()
        
        logger.info(f"Initialized IaaS collector for {cloud_provider}")
    
    def _get_provider_collector(self) -> BaseCollector:
        """
        Get the appropriate provider-specific collector.
        
        Returns:
            Provider-specific collector instance
        """
        if self.cloud_provider == 'aws':
            return aws_collectors.EC2InstanceCollector(
                case_id=self.case_id,
                evidence_storage_path=self.evidence_storage_path,
                **self.provider_kwargs
            )
        elif self.cloud_provider == 'azure':
            return azure_collectors.AzureVMCollector(
                case_id=self.case_id,
                evidence_storage_path=self.evidence_storage_path,
                **self.provider_kwargs
            )
        elif self.cloud_provider == 'gcp':
            return gcp_collectors.GCPComputeInstanceCollector(
                case_id=self.case_id,
                evidence_storage_path=self.evidence_storage_path,
                **self.provider_kwargs
            )
        else:
            raise ValueError(f"Unsupported cloud provider: {self.cloud_provider}")
    
    def collect(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Collect evidence from IaaS resources.
        
        This method delegates to the appropriate provider-specific collector.
        
        Args:
            *args: Arguments to pass to the provider-specific collector
            **kwargs: Keyword arguments to pass to the provider-specific collector
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            # Delegate to provider-specific collector
            provider_results = self.provider_collector.collect(*args, **kwargs)
            
            # Add service model information
            collection_results = {
                'service_model': 'IaaS',
                'cloud_provider': self.cloud_provider,
                'provider_results': provider_results
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting IaaS evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()


class VirtualMachineCollector(IaaSCollector):
    """Specialized collector for virtual machine evidence across cloud providers."""
    
    def collect_vm_evidence(self, **vm_params) -> Dict[str, Any]:
        """
        Collect evidence from a virtual machine.
        
        Args:
            **vm_params: Provider-specific VM parameters:
                - AWS: instance_id
                - Azure: resource_group, vm_name
                - GCP: zone, instance_name
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        if self.cloud_provider == 'aws':
            if 'instance_id' not in vm_params:
                raise ValueError("AWS VM collection requires 'instance_id' parameter")
            
            return self.collect(vm_params['instance_id'])
            
        elif self.cloud_provider == 'azure':
            if 'resource_group' not in vm_params or 'vm_name' not in vm_params:
                raise ValueError("Azure VM collection requires 'resource_group' and 'vm_name' parameters")
            
            return self.collect(
                resource_group=vm_params['resource_group'],
                vm_name=vm_params['vm_name']
            )
            
        elif self.cloud_provider == 'gcp':
            if 'zone' not in vm_params or 'instance_name' not in vm_params:
                raise ValueError("GCP VM collection requires 'zone' and 'instance_name' parameters")
            
            return self.collect(
                zone=vm_params['zone'],
                instance_name=vm_params['instance_name']
            )
            
        else:
            raise ValueError(f"Unsupported cloud provider: {self.cloud_provider}")


class NetworkCollector(IaaSCollector):
    """Specialized collector for network evidence across cloud providers."""
    
    def collect_network_evidence(self, **network_params) -> Dict[str, Any]:
        """
        Collect network-related evidence.
        
        This method collects network-specific evidence like VPC configurations,
        security groups, firewall rules, etc.
        
        Args:
            **network_params: Provider-specific network parameters
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            network_evidence = {}
            
            if self.cloud_provider == 'aws':
                # Create boto3 session
                import boto3
                session = boto3.Session(
                    region_name=self.provider_kwargs.get('region'),
                    aws_access_key_id=self.provider_kwargs.get('credentials', {}).get('access_key'),
                    aws_secret_access_key=self.provider_kwargs.get('credentials', {}).get('secret_key')
                )
                
                # Collect VPC information
                vpc_id = network_params.get('vpc_id')
                if vpc_id:
                    ec2_client = session.client('ec2')
                    
                    # Get VPC details
                    vpc_response = ec2_client.describe_vpcs(VpcIds=[vpc_id])
                    
                    if vpc_response['Vpcs']:
                        vpc_data = vpc_response['Vpcs'][0]
                        
                        # Save VPC metadata
                        vpc_path = self.save_evidence(
                            vpc_data,
                            'aws_vpc_metadata',
                            vpc_id
                        )
                        
                        network_evidence['vpc'] = {
                            'vpc_id': vpc_id,
                            'metadata_path': vpc_path
                        }
                        
                        # Get subnets
                        subnet_response = ec2_client.describe_subnets(
                            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                        )
                        
                        if subnet_response['Subnets']:
                            # Save subnet metadata
                            subnet_path = self.save_evidence(
                                subnet_response['Subnets'],
                                'aws_subnet_metadata',
                                vpc_id
                            )
                            
                            network_evidence['subnets'] = {
                                'count': len(subnet_response['Subnets']),
                                'metadata_path': subnet_path
                            }
                        
                        # Get route tables
                        route_response = ec2_client.describe_route_tables(
                            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                        )
                        
                        if route_response['RouteTables']:
                            # Save route table metadata
                            route_path = self.save_evidence(
                                route_response['RouteTables'],
                                'aws_route_table_metadata',
                                vpc_id
                            )
                            
                            network_evidence['route_tables'] = {
                                'count': len(route_response['RouteTables']),
                                'metadata_path': route_path
                            }
                        
                        # Get security groups
                        sg_response = ec2_client.describe_security_groups(
                            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                        )
                        
                        if sg_response['SecurityGroups']:
                            # Save security group metadata
                            sg_path = self.save_evidence(
                                sg_response['SecurityGroups'],
                                'aws_security_group_metadata',
                                vpc_id
                            )
                            
                            network_evidence['security_groups'] = {
                                'count': len(sg_response['SecurityGroups']),
                                'metadata_path': sg_path
                            }
                        
                        # Get network ACLs
                        acl_response = ec2_client.describe_network_acls(
                            Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
                        )
                        
                        if acl_response['NetworkAcls']:
                            # Save network ACL metadata
                            acl_path = self.save_evidence(
                                acl_response['NetworkAcls'],
                                'aws_network_acl_metadata',
                                vpc_id
                            )
                            
                            network_evidence['network_acls'] = {
                                'count': len(acl_response['NetworkAcls']),
                                'metadata_path': acl_path
                            }
                
            elif self.cloud_provider == 'azure':
                # Create Azure network client
                from azure.identity import DefaultAzureCredential
                from azure.mgmt.network import NetworkManagementClient
                
                credential = DefaultAzureCredential(
                    tenant_id=self.provider_kwargs.get('tenant_id'),
                    client_id=self.provider_kwargs.get('client_id'),
                    client_secret=self.provider_kwargs.get('client_secret')
                )
                
                network_client = NetworkManagementClient(
                    credential=credential,
                    subscription_id=self.provider_kwargs.get('subscription_id')
                )
                
                # Collect virtual network information
                resource_group = network_params.get('resource_group')
                vnet_name = network_params.get('vnet_name')
                
                if resource_group and vnet_name:
                    # Get virtual network details
                    vnet = network_client.virtual_networks.get(
                        resource_group_name=resource_group,
                        virtual_network_name=vnet_name
                    )
                    
                    # Save virtual network metadata
                    vnet_path = self.save_evidence(
                        vnet.as_dict(),
                        'azure_vnet_metadata',
                        vnet_name
                    )
                    
                    network_evidence['virtual_network'] = {
                        'vnet_name': vnet_name,
                        'metadata_path': vnet_path
                    }
                    
                    # Get subnets
                    subnets = []
                    for subnet in vnet.subnets:
                        subnet_obj = network_client.subnets.get(
                            resource_group_name=resource_group,
                            virtual_network_name=vnet_name,
                            subnet_name=subnet.name
                        )
                        
                        subnets.append(subnet_obj.as_dict())
                    
                    if subnets:
                        # Save subnet metadata
                        subnet_path = self.save_evidence(
                            subnets,
                            'azure_subnet_metadata',
                            vnet_name
                        )
                        
                        network_evidence['subnets'] = {
                            'count': len(subnets),
                            'metadata_path': subnet_path
                        }
                    
                    # Get network security groups
                    nsgs = list(network_client.network_security_groups.list(
                        resource_group_name=resource_group
                    ))
                    
                    nsg_list = [nsg.as_dict() for nsg in nsgs]
                    
                    if nsg_list:
                        # Save NSG metadata
                        nsg_path = self.save_evidence(
                            nsg_list,
                            'azure_nsg_metadata',
                            resource_group
                        )
                        
                        network_evidence['network_security_groups'] = {
                            'count': len(nsg_list),
                            'metadata_path': nsg_path
                        }
                    
                    # Get route tables
                    route_tables = list(network_client.route_tables.list(
                        resource_group_name=resource_group
                    ))
                    
                    route_table_list = [rt.as_dict() for rt in route_tables]
                    
                    if route_table_list:
                        # Save route table metadata
                        rt_path = self.save_evidence(
                            route_table_list,
                            'azure_route_table_metadata',
                            resource_group
                        )
                        
                        network_evidence['route_tables'] = {
                            'count': len(route_table_list),
                            'metadata_path': rt_path
                        }
                
            elif self.cloud_provider == 'gcp':
                # Create GCP compute client
                from google.oauth2 import service_account
                from google.cloud import compute_v1
                
                if self.provider_kwargs.get('credentials_file'):
                    credentials = service_account.Credentials.from_service_account_file(
                        self.provider_kwargs.get('credentials_file')
                    )
                else:
                    credentials = None
                
                # Collect VPC information
                project_id = self.provider_kwargs.get('project_id')
                network_name = network_params.get('network_name')
                
                if project_id and network_name:
                    # Get network details
                    network_client = compute_v1.NetworksClient(credentials=credentials)
                    
                    network = network_client.get(
                        project=project_id,
                        network=network_name
                    )
                    
                    # Convert network object to dict for serialization
                    network_dict = {
                        'id': network.id,
                        'name': network.name,
                        'description': network.description,
                        'self_link': network.self_link,
                        'auto_create_subnetworks': network.auto_create_subnetworks,
                        'subnetworks': list(network.subnetworks) if network.subnetworks else [],
                        'routing_config': {
                            'routing_mode': network.routing_config.routing_mode
                        } if network.routing_config else None,
                        'mtu': network.mtu
                    }
                    
                    # Save network metadata
                    network_path = self.save_evidence(
                        network_dict,
                        'gcp_network_metadata',
                        network_name
                    )
                    
                    network_evidence['network'] = {
                        'network_name': network_name,
                        'metadata_path': network_path
                    }
                    
                    # Get subnetworks
                    subnetwork_client = compute_v1.SubnetworksClient(credentials=credentials)
                    
                    # List all regions
                    region_client = compute_v1.RegionsClient(credentials=credentials)
                    regions = region_client.list(project=project_id)
                    
                    subnetworks = []
                    for region in regions:
                        region_name = region.name
                        
                        # List subnetworks in this region
                        try:
                            region_subnetworks = subnetwork_client.list(
                                project=project_id,
                                region=region_name
                            )
                            
                            # Filter for subnetworks in our network
                            for subnetwork in region_subnetworks:
                                if network_name in subnetwork.network:
                                    subnetworks.append({
                                        'id': subnetwork.id,
                                        'name': subnetwork.name,
                                        'description': subnetwork.description,
                                        'region': subnetwork.region,
                                        'network': subnetwork.network,
                                        'ip_cidr_range': subnetwork.ip_cidr_range,
                                        'gateway_address': subnetwork.gateway_address,
                                        'private_ip_google_access': subnetwork.private_ip_google_access,
                                        'self_link': subnetwork.self_link
                                    })
                        
                        except Exception as e:
                            logger.error(f"Error listing subnetworks in region {region_name}: {str(e)}")
                    
                    if subnetworks:
                        # Save subnetwork metadata
                        subnetwork_path = self.save_evidence(
                            subnetworks,
                            'gcp_subnetwork_metadata',
                            network_name
                        )
                        
                        network_evidence['subnetworks'] = {
                            'count': len(subnetworks),
                            'metadata_path': subnetwork_path
                        }
                    
                    # Get firewall rules
                    firewall_client = compute_v1.FirewallsClient(credentials=credentials)
                    
                    firewalls = firewall_client.list(project=project_id)
                    
                    # Filter for firewalls in our network
                    network_firewalls = []
                    for firewall in firewalls:
                        if network_name in firewall.network:
                            network_firewalls.append({
                                'id': firewall.id,
                                'name': firewall.name,
                                'description': firewall.description,
                                'network': firewall.network,
                                'priority': firewall.priority,
                                'direction': firewall.direction,
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
                                'source_tags': list(firewall.source_tags) if firewall.source_tags else [],
                                'target_tags': list(firewall.target_tags) if firewall.target_tags else [],
                                'self_link': firewall.self_link
                            })
                    
                    if network_firewalls:
                        # Save firewall metadata
                        firewall_path = self.save_evidence(
                            network_firewalls,
                            'gcp_firewall_metadata',
                            network_name
                        )
                        
                        network_evidence['firewalls'] = {
                            'count': len(network_firewalls),
                            'metadata_path': firewall_path
                        }
                    
                    # Get routes
                    route_client = compute_v1.RoutesClient(credentials=credentials)
                    
                    routes = route_client.list(project=project_id)
                    
                    # Filter for routes in our network
                    network_routes = []
                    for route in routes:
                        if network_name in route.network:
                            network_routes.append({
                                'id': route.id,
                                'name': route.name,
                                'description': route.description,
                                'network': route.network,
                                'dest_range': route.dest_range,
                                'priority': route.priority,
                                'next_hop_gateway': route.next_hop_gateway,
                                'next_hop_ip': route.next_hop_ip,
                                'next_hop_instance': route.next_hop_instance,
                                'next_hop_network': route.next_hop_network,
                                'next_hop_peering': route.next_hop_peering,
                                'self_link': route.self_link
                            })
                    
                    if network_routes:
                        # Save route metadata
                        route_path = self.save_evidence(
                            network_routes,
                            'gcp_route_metadata',
                            network_name
                        )
                        
                        network_evidence['routes'] = {
                            'count': len(network_routes),
                            'metadata_path': route_path
                        }
            
            # Compile collection results
            collection_results = {
                'service_model': 'IaaS',
                'cloud_provider': self.cloud_provider,
                'network_evidence': network_evidence
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting network evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()


class StorageCollector(IaaSCollector):
    """Specialized collector for storage evidence across cloud providers."""
    
    def collect_storage_evidence(self, **storage_params) -> Dict[str, Any]:
        """
        Collect storage-related evidence.
        
        This method delegates to the appropriate provider-specific storage collector.
        
        Args:
            **storage_params: Provider-specific storage parameters:
                - AWS: bucket_name, prefix
                - Azure: resource_group, storage_account_name, container_name
                - GCP: bucket_name, prefix
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            if self.cloud_provider == 'aws':
                # Create AWS S3 collector
                s3_collector = aws_collectors.S3BucketCollector(
                    case_id=self.case_id,
                    evidence_storage_path=self.evidence_storage_path,
                    region=self.provider_kwargs.get('region'),
                    credentials=self.provider_kwargs.get('credentials')
                )
                
                bucket_name = storage_params.get('bucket_name')
                prefix = storage_params.get('prefix')
                
                if not bucket_name:
                    raise ValueError("AWS storage collection requires 'bucket_name' parameter")
                
                # Collect S3 bucket evidence
                s3_results = s3_collector.collect(
                    bucket_name=bucket_name,
                    prefix=prefix
                )
                
                storage_evidence = {
                    'type': 's3_bucket',
                    'results': s3_results
                }
                
            elif self.cloud_provider == 'azure':
                # Create Azure Storage collector
                azure_storage_collector = azure_collectors.AzureStorageCollector(
                    case_id=self.case_id,
                    evidence_storage_path=self.evidence_storage_path,
                    subscription_id=self.provider_kwargs.get('subscription_id'),
                    tenant_id=self.provider_kwargs.get('tenant_id'),
                    client_id=self.provider_kwargs.get('client_id'),
                    client_secret=self.provider_kwargs.get('client_secret')
                )
                
                resource_group = storage_params.get('resource_group')
                storage_account_name = storage_params.get('storage_account_name')
                container_name = storage_params.get('container_name')
                
                if not resource_group or not storage_account_name:
                    raise ValueError("Azure storage collection requires 'resource_group' and 'storage_account_name' parameters")
                
                # Collect Azure Storage evidence
                azure_results = azure_storage_collector.collect(
                    resource_group=resource_group,
                    storage_account_name=storage_account_name,
                    container_name=container_name
                )
                
                storage_evidence = {
                    'type': 'azure_storage',
                    'results': azure_results
                }
                
            elif self.cloud_provider == 'gcp':
                # Create GCP Storage collector
                gcp_storage_collector = gcp_collectors.GCPStorageCollector(
                    case_id=self.case_id,
                    evidence_storage_path=self.evidence_storage_path,
                    project_id=self.provider_kwargs.get('project_id'),
                    credentials_file=self.provider_kwargs.get('credentials_file')
                )
                
                bucket_name = storage_params.get('bucket_name')
                prefix = storage_params.get('prefix')
                
                if not bucket_name:
                    raise ValueError("GCP storage collection requires 'bucket_name' parameter")
                
                # Collect GCP Storage evidence
                gcp_results = gcp_storage_collector.collect(
                    bucket_name=bucket_name,
                    prefix=prefix
                )
                
                storage_evidence = {
                    'type': 'gcp_storage',
                    'results': gcp_results
                }
                
            else:
                raise ValueError(f"Unsupported cloud provider: {self.cloud_provider}")
            
            # Compile collection results
            collection_results = {
                'service_model': 'IaaS',
                'cloud_provider': self.cloud_provider,
                'storage_evidence': storage_evidence
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting storage evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()
