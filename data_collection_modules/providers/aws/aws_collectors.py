"""
AWS-specific data collectors for the Cloud Forensics AI Agent.

This module provides collectors for gathering evidence from AWS cloud resources
while maintaining forensic integrity and chain of custody.
"""

import boto3
import datetime
import json
import logging
import os
from typing import Any, Dict, List, Optional, Union

from ...core.base_collector import BaseCollector
from ...utils import evidence_utils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AWSBaseCollector(BaseCollector):
    """Base class for all AWS-specific collectors."""
    
    def __init__(self, case_id: str, evidence_storage_path: str, 
                region: str, credentials: Optional[Dict[str, str]] = None):
        """
        Initialize the AWS collector.
        
        Args:
            case_id: Unique identifier for the forensic case
            evidence_storage_path: Path where collected evidence will be stored
            region: AWS region to collect from
            credentials: Optional AWS credentials (access key, secret key)
        """
        super().__init__(case_id, evidence_storage_path)
        self.region = region
        self.credentials = credentials
        self.session = self._create_boto3_session()
        
        logger.info(f"Initialized AWS collector for region {region}")
    
    def _create_boto3_session(self) -> boto3.Session:
        """
        Create a boto3 session with the provided credentials.
        
        Returns:
            Configured boto3 Session object
        """
        if self.credentials:
            session = boto3.Session(
                aws_access_key_id=self.credentials.get('access_key'),
                aws_secret_access_key=self.credentials.get('secret_key'),
                region_name=self.region
            )
        else:
            # Use default credentials from environment or instance profile
            session = boto3.Session(region_name=self.region)
        
        return session
    
    def collect(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Collect evidence from AWS resources.
        
        This method must be implemented by specific AWS collector subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")


class EC2InstanceCollector(AWSBaseCollector):
    """Collector for EC2 instance evidence."""
    
    def collect(self, instance_id: str) -> Dict[str, Any]:
        """
        Collect evidence from an EC2 instance.
        
        Args:
            instance_id: ID of the EC2 instance to collect from
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            # Create EC2 client
            ec2_client = self.session.client('ec2')
            
            # Collect instance metadata
            instance_response = ec2_client.describe_instances(InstanceIds=[instance_id])
            
            if not instance_response['Reservations']:
                raise ValueError(f"Instance {instance_id} not found")
            
            instance_data = instance_response['Reservations'][0]['Instances'][0]
            
            # Save instance metadata
            metadata_path = self.save_evidence(
                instance_data,
                'ec2_metadata',
                instance_id
            )
            
            # Collect instance console output
            try:
                console_output = ec2_client.get_console_output(InstanceId=instance_id)
                if 'Output' in console_output:
                    console_path = self.save_evidence(
                        console_output['Output'],
                        'ec2_console',
                        instance_id
                    )
                else:
                    console_path = None
                    logger.warning(f"No console output available for instance {instance_id}")
            except Exception as e:
                console_path = None
                logger.error(f"Error collecting console output: {str(e)}")
            
            # Create EBS volume snapshots if the instance has volumes
            volume_snapshots = []
            for device in instance_data.get('BlockDeviceMappings', []):
                if 'Ebs' in device and 'VolumeId' in device['Ebs']:
                    volume_id = device['Ebs']['VolumeId']
                    try:
                        # Create snapshot
                        snapshot_response = ec2_client.create_snapshot(
                            VolumeId=volume_id,
                            Description=f"Forensic snapshot for case {self.case_id}"
                        )
                        
                        snapshot_id = snapshot_response['SnapshotId']
                        
                        # Wait for snapshot to complete
                        waiter = ec2_client.get_waiter('snapshot_completed')
                        waiter.wait(SnapshotIds=[snapshot_id])
                        
                        # Get snapshot details
                        snapshot_details = ec2_client.describe_snapshots(
                            SnapshotIds=[snapshot_id]
                        )
                        
                        # Save snapshot metadata
                        snapshot_path = self.save_evidence(
                            snapshot_details['Snapshots'][0],
                            'ebs_snapshot',
                            volume_id
                        )
                        
                        volume_snapshots.append({
                            'volume_id': volume_id,
                            'snapshot_id': snapshot_id,
                            'device_name': device.get('DeviceName'),
                            'metadata_path': snapshot_path
                        })
                        
                    except Exception as e:
                        logger.error(f"Error creating snapshot for volume {volume_id}: {str(e)}")
            
            # Collect security group information
            security_groups = []
            for sg in instance_data.get('SecurityGroups', []):
                try:
                    sg_response = ec2_client.describe_security_groups(
                        GroupIds=[sg['GroupId']]
                    )
                    
                    sg_path = self.save_evidence(
                        sg_response['SecurityGroups'][0],
                        'security_group',
                        sg['GroupId']
                    )
                    
                    security_groups.append({
                        'group_id': sg['GroupId'],
                        'metadata_path': sg_path
                    })
                    
                except Exception as e:
                    logger.error(f"Error collecting security group {sg['GroupId']}: {str(e)}")
            
            # Collect VPC flow logs if available
            vpc_id = instance_data.get('VpcId')
            vpc_flow_logs = []
            
            if vpc_id:
                try:
                    logs_client = self.session.client('logs')
                    ec2_client = self.session.client('ec2')
                    
                    # Find flow logs for this VPC
                    flow_logs_response = ec2_client.describe_flow_logs(
                        Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                    )
                    
                    for flow_log in flow_logs_response.get('FlowLogs', []):
                        if 'LogGroupName' in flow_log:
                            # Get log streams
                            log_group_name = flow_log['LogGroupName']
                            
                            streams_response = logs_client.describe_log_streams(
                                logGroupName=log_group_name,
                                orderBy='LastEventTime',
                                descending=True,
                                limit=5  # Get the 5 most recent streams
                            )
                            
                            for stream in streams_response.get('logStreams', []):
                                # Get log events
                                events_response = logs_client.get_log_events(
                                    logGroupName=log_group_name,
                                    logStreamName=stream['logStreamName'],
                                    limit=1000  # Adjust as needed
                                )
                                
                                if events_response.get('events'):
                                    log_path = self.save_evidence(
                                        events_response,
                                        'vpc_flow_logs',
                                        f"{vpc_id}_{stream['logStreamName']}"
                                    )
                                    
                                    vpc_flow_logs.append({
                                        'vpc_id': vpc_id,
                                        'log_group': log_group_name,
                                        'log_stream': stream['logStreamName'],
                                        'metadata_path': log_path
                                    })
                    
                except Exception as e:
                    logger.error(f"Error collecting VPC flow logs for {vpc_id}: {str(e)}")
            
            # Compile collection results
            collection_results = {
                'instance_id': instance_id,
                'metadata_path': metadata_path,
                'console_path': console_path,
                'volume_snapshots': volume_snapshots,
                'security_groups': security_groups,
                'vpc_flow_logs': vpc_flow_logs
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting EC2 instance evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()


class CloudTrailCollector(AWSBaseCollector):
    """Collector for AWS CloudTrail logs."""
    
    def collect(self, start_time: datetime.datetime, 
               end_time: Optional[datetime.datetime] = None,
               trail_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Collect CloudTrail logs for a specified time period.
        
        Args:
            start_time: Start time for log collection
            end_time: Optional end time (defaults to current time)
            trail_name: Optional specific trail to collect from
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            # Set end time to now if not provided
            if not end_time:
                end_time = datetime.datetime.utcnow()
            
            # Create CloudTrail client
            cloudtrail_client = self.session.client('cloudtrail')
            
            # Get available trails
            trails_response = cloudtrail_client.describe_trails()
            
            trails_to_collect = []
            if trail_name:
                # Find the specified trail
                for trail in trails_response.get('trailList', []):
                    if trail.get('Name') == trail_name:
                        trails_to_collect.append(trail)
                        break
                
                if not trails_to_collect:
                    raise ValueError(f"Trail {trail_name} not found")
            else:
                # Collect from all available trails
                trails_to_collect = trails_response.get('trailList', [])
            
            # Save trails metadata
            trails_metadata_path = self.save_evidence(
                trails_response,
                'cloudtrail_metadata',
                'all_trails'
            )
            
            collected_events = []
            
            for trail in trails_to_collect:
                trail_name = trail.get('Name')
                
                # Look up events from this trail
                try:
                    events_response = cloudtrail_client.lookup_events(
                        StartTime=start_time,
                        EndTime=end_time,
                        MaxResults=1000  # Adjust as needed
                    )
                    
                    if events_response.get('Events'):
                        events_path = self.save_evidence(
                            events_response,
                            'cloudtrail_events',
                            trail_name
                        )
                        
                        collected_events.append({
                            'trail_name': trail_name,
                            'event_count': len(events_response.get('Events', [])),
                            'metadata_path': events_path
                        })
                    
                    # Handle pagination if there are more events
                    while events_response.get('NextToken'):
                        events_response = cloudtrail_client.lookup_events(
                            StartTime=start_time,
                            EndTime=end_time,
                            MaxResults=1000,
                            NextToken=events_response['NextToken']
                        )
                        
                        if events_response.get('Events'):
                            events_path = self.save_evidence(
                                events_response,
                                'cloudtrail_events',
                                f"{trail_name}_continued"
                            )
                            
                            collected_events.append({
                                'trail_name': trail_name,
                                'event_count': len(events_response.get('Events', [])),
                                'metadata_path': events_path
                            })
                
                except Exception as e:
                    logger.error(f"Error collecting events from trail {trail_name}: {str(e)}")
            
            # Compile collection results
            collection_results = {
                'time_period': {
                    'start_time': start_time.isoformat(),
                    'end_time': end_time.isoformat()
                },
                'trails_metadata_path': trails_metadata_path,
                'collected_events': collected_events
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting CloudTrail logs: {str(e)}")
            raise
        
        finally:
            self.end_collection()


class S3BucketCollector(AWSBaseCollector):
    """Collector for S3 bucket evidence."""
    
    def collect(self, bucket_name: str, prefix: Optional[str] = None, 
               max_keys: int = 1000) -> Dict[str, Any]:
        """
        Collect evidence from an S3 bucket.
        
        Args:
            bucket_name: Name of the S3 bucket
            prefix: Optional prefix to filter objects
            max_keys: Maximum number of keys to collect
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            # Create S3 client
            s3_client = self.session.client('s3')
            
            # Get bucket metadata
            try:
                bucket_metadata = {
                    'name': bucket_name,
                    'region': self.region,
                    'creation_date': None  # S3 doesn't provide creation date via API
                }
                
                # Get bucket location
                location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                bucket_metadata['location'] = location_response.get('LocationConstraint')
                
                # Get bucket policy if exists
                try:
                    policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                    bucket_metadata['policy'] = json.loads(policy_response.get('Policy', '{}'))
                except s3_client.exceptions.NoSuchBucketPolicy:
                    bucket_metadata['policy'] = None
                
                # Get bucket ACL
                acl_response = s3_client.get_bucket_acl(Bucket=bucket_name)
                bucket_metadata['acl'] = acl_response
                
                # Get bucket versioning status
                versioning_response = s3_client.get_bucket_versioning(Bucket=bucket_name)
                bucket_metadata['versioning'] = versioning_response
                
                # Get bucket logging configuration
                try:
                    logging_response = s3_client.get_bucket_logging(Bucket=bucket_name)
                    bucket_metadata['logging'] = logging_response.get('LoggingEnabled')
                except Exception:
                    bucket_metadata['logging'] = None
                
                # Save bucket metadata
                metadata_path = self.save_evidence(
                    bucket_metadata,
                    's3_bucket_metadata',
                    bucket_name
                )
                
            except Exception as e:
                logger.error(f"Error collecting bucket metadata for {bucket_name}: {str(e)}")
                metadata_path = None
            
            # List objects in the bucket
            list_params = {
                'Bucket': bucket_name,
                'MaxKeys': max_keys
            }
            
            if prefix:
                list_params['Prefix'] = prefix
            
            objects_response = s3_client.list_objects_v2(**list_params)
            
            # Save object listing
            if 'Contents' in objects_response:
                objects_path = self.save_evidence(
                    objects_response,
                    's3_object_listing',
                    bucket_name
                )
            else:
                objects_path = None
                logger.warning(f"No objects found in bucket {bucket_name}")
            
            # Get bucket access logs if available
            access_logs = []
            if bucket_metadata.get('logging'):
                target_bucket = bucket_metadata['logging'].get('TargetBucket')
                target_prefix = bucket_metadata['logging'].get('TargetPrefix')
                
                if target_bucket and target_prefix:
                    try:
                        # List log objects
                        logs_response = s3_client.list_objects_v2(
                            Bucket=target_bucket,
                            Prefix=target_prefix,
                            MaxKeys=100  # Adjust as needed
                        )
                        
                        if 'Contents' in logs_response:
                            logs_path = self.save_evidence(
                                logs_response,
                                's3_access_logs_listing',
                                bucket_name
                            )
                            
                            # Download a sample of log files
                            for i, log_obj in enumerate(logs_response.get('Contents', [])[:5]):
                                try:
                                    log_key = log_obj['Key']
                                    log_response = s3_client.get_object(
                                        Bucket=target_bucket,
                                        Key=log_key
                                    )
                                    
                                    log_content = log_response['Body'].read().decode('utf-8')
                                    
                                    log_file_path = self.save_evidence(
                                        log_content,
                                        's3_access_log',
                                        f"{bucket_name}_{i}"
                                    )
                                    
                                    access_logs.append({
                                        'key': log_key,
                                        'metadata_path': log_file_path
                                    })
                                    
                                except Exception as e:
                                    logger.error(f"Error downloading log file {log_key}: {str(e)}")
                        
                    except Exception as e:
                        logger.error(f"Error collecting access logs for {bucket_name}: {str(e)}")
            
            # Compile collection results
            collection_results = {
                'bucket_name': bucket_name,
                'metadata_path': metadata_path,
                'objects_path': objects_path,
                'access_logs': access_logs
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting S3 bucket evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()
