"""
Service model-specific collectors for PaaS environments in the Cloud Forensics AI Agent.

This module provides collectors for gathering evidence from Platform as a Service
environments across different cloud providers while maintaining forensic integrity.
"""

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

class PaaSCollector(BaseCollector):
    """Collector for Platform as a Service evidence across cloud providers."""
    
    def __init__(self, case_id: str, evidence_storage_path: str, 
                cloud_provider: str, **provider_kwargs):
        """
        Initialize the PaaS collector.
        
        Args:
            case_id: Unique identifier for the forensic case
            evidence_storage_path: Path where collected evidence will be stored
            cloud_provider: Cloud provider name ('aws', 'azure', or 'gcp')
            **provider_kwargs: Provider-specific arguments
        """
        super().__init__(case_id, evidence_storage_path)
        self.cloud_provider = cloud_provider.lower()
        self.provider_kwargs = provider_kwargs
        
        logger.info(f"Initialized PaaS collector for {cloud_provider}")
    
    def collect(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Collect evidence from PaaS resources.
        
        This method must be implemented by specific PaaS collector subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")


class AppServiceCollector(PaaSCollector):
    """Collector for application service evidence across cloud providers."""
    
    def collect_app_service_evidence(self, **app_params) -> Dict[str, Any]:
        """
        Collect evidence from application services.
        
        Args:
            **app_params: Provider-specific app service parameters:
                - AWS: service_name, function_name (Lambda)
                - Azure: resource_group, app_service_name
                - GCP: project_id, service_name (App Engine)
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            app_evidence = {}
            
            if self.cloud_provider == 'aws':
                # Collect AWS Lambda evidence
                service_name = app_params.get('service_name')
                function_name = app_params.get('function_name')
                
                if service_name == 'lambda' and function_name:
                    import boto3
                    
                    # Create Lambda client
                    lambda_client = boto3.client(
                        'lambda',
                        region_name=self.provider_kwargs.get('region'),
                        aws_access_key_id=self.provider_kwargs.get('credentials', {}).get('access_key'),
                        aws_secret_access_key=self.provider_kwargs.get('credentials', {}).get('secret_key')
                    )
                    
                    # Get function details
                    function_response = lambda_client.get_function(
                        FunctionName=function_name
                    )
                    
                    # Save function metadata
                    function_path = self.save_evidence(
                        function_response,
                        'aws_lambda_metadata',
                        function_name
                    )
                    
                    app_evidence['lambda_function'] = {
                        'function_name': function_name,
                        'metadata_path': function_path
                    }
                    
                    # Get function logs
                    logs_client = boto3.client(
                        'logs',
                        region_name=self.provider_kwargs.get('region'),
                        aws_access_key_id=self.provider_kwargs.get('credentials', {}).get('access_key'),
                        aws_secret_access_key=self.provider_kwargs.get('credentials', {}).get('secret_key')
                    )
                    
                    # Get log group name for the Lambda function
                    log_group_name = f"/aws/lambda/{function_name}"
                    
                    try:
                        # Get log streams
                        streams_response = logs_client.describe_log_streams(
                            logGroupName=log_group_name,
                            orderBy='LastEventTime',
                            descending=True,
                            limit=5  # Get the 5 most recent streams
                        )
                        
                        function_logs = []
                        
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
                                    'aws_lambda_logs',
                                    f"{function_name}_{stream['logStreamName']}"
                                )
                                
                                function_logs.append({
                                    'stream_name': stream['logStreamName'],
                                    'event_count': len(events_response.get('events', [])),
                                    'metadata_path': log_path
                                })
                        
                        if function_logs:
                            app_evidence['lambda_function']['logs'] = function_logs
                    
                    except Exception as e:
                        logger.error(f"Error collecting Lambda logs: {str(e)}")
                
                elif service_name == 'elastic-beanstalk':
                    # Collect Elastic Beanstalk evidence
                    environment_name = app_params.get('environment_name')
                    
                    if environment_name:
                        import boto3
                        
                        # Create Elastic Beanstalk client
                        eb_client = boto3.client(
                            'elasticbeanstalk',
                            region_name=self.provider_kwargs.get('region'),
                            aws_access_key_id=self.provider_kwargs.get('credentials', {}).get('access_key'),
                            aws_secret_access_key=self.provider_kwargs.get('credentials', {}).get('secret_key')
                        )
                        
                        # Get environment details
                        env_response = eb_client.describe_environments(
                            EnvironmentNames=[environment_name]
                        )
                        
                        if env_response['Environments']:
                            env_data = env_response['Environments'][0]
                            
                            # Save environment metadata
                            env_path = self.save_evidence(
                                env_data,
                                'aws_elasticbeanstalk_metadata',
                                environment_name
                            )
                            
                            app_evidence['elastic_beanstalk'] = {
                                'environment_name': environment_name,
                                'metadata_path': env_path
                            }
                            
                            # Get configuration settings
                            config_response = eb_client.describe_configuration_settings(
                                ApplicationName=env_data['ApplicationName'],
                                EnvironmentName=environment_name
                            )
                            
                            if 'ConfigurationSettings' in config_response:
                                # Save configuration settings
                                config_path = self.save_evidence(
                                    config_response,
                                    'aws_elasticbeanstalk_config',
                                    environment_name
                                )
                                
                                app_evidence['elastic_beanstalk']['config_path'] = config_path
                            
                            # Get environment resources
                            resources_response = eb_client.describe_environment_resources(
                                EnvironmentName=environment_name
                            )
                            
                            if 'EnvironmentResources' in resources_response:
                                # Save resources metadata
                                resources_path = self.save_evidence(
                                    resources_response,
                                    'aws_elasticbeanstalk_resources',
                                    environment_name
                                )
                                
                                app_evidence['elastic_beanstalk']['resources_path'] = resources_path
                
            elif self.cloud_provider == 'azure':
                # Collect Azure App Service evidence
                resource_group = app_params.get('resource_group')
                app_service_name = app_params.get('app_service_name')
                
                if resource_group and app_service_name:
                    from azure.identity import DefaultAzureCredential
                    from azure.mgmt.web import WebSiteManagementClient
                    
                    credential = DefaultAzureCredential(
                        tenant_id=self.provider_kwargs.get('tenant_id'),
                        client_id=self.provider_kwargs.get('client_id'),
                        client_secret=self.provider_kwargs.get('client_secret')
                    )
                    
                    web_client = WebSiteManagementClient(
                        credential=credential,
                        subscription_id=self.provider_kwargs.get('subscription_id')
                    )
                    
                    # Get app service details
                    app_service = web_client.web_apps.get(
                        resource_group_name=resource_group,
                        name=app_service_name
                    )
                    
                    # Save app service metadata
                    app_path = self.save_evidence(
                        app_service.as_dict(),
                        'azure_app_service_metadata',
                        app_service_name
                    )
                    
                    app_evidence['app_service'] = {
                        'app_service_name': app_service_name,
                        'metadata_path': app_path
                    }
                    
                    # Get app service configuration
                    config = web_client.web_apps.get_configuration(
                        resource_group_name=resource_group,
                        name=app_service_name
                    )
                    
                    # Save configuration
                    config_path = self.save_evidence(
                        config.as_dict(),
                        'azure_app_service_config',
                        app_service_name
                    )
                    
                    app_evidence['app_service']['config_path'] = config_path
                    
                    # Get app settings
                    app_settings = web_client.web_apps.list_application_settings(
                        resource_group_name=resource_group,
                        name=app_service_name
                    )
                    
                    # Save app settings
                    settings_path = self.save_evidence(
                        app_settings.as_dict(),
                        'azure_app_service_settings',
                        app_service_name
                    )
                    
                    app_evidence['app_service']['settings_path'] = settings_path
                    
                    # Get deployment logs
                    try:
                        deployments = web_client.web_apps.list_deployments(
                            resource_group_name=resource_group,
                            name=app_service_name
                        )
                        
                        deployment_list = [d.as_dict() for d in deployments]
                        
                        if deployment_list:
                            # Save deployment metadata
                            deployment_path = self.save_evidence(
                                deployment_list,
                                'azure_app_service_deployments',
                                app_service_name
                            )
                            
                            app_evidence['app_service']['deployments_path'] = deployment_path
                    
                    except Exception as e:
                        logger.error(f"Error collecting deployment logs: {str(e)}")
                    
                    # Get application logs
                    try:
                        from azure.mgmt.monitor import MonitorManagementClient
                        
                        monitor_client = MonitorManagementClient(
                            credential=credential,
                            subscription_id=self.provider_kwargs.get('subscription_id')
                        )
                        
                        # Get app service resource ID
                        resource_id = app_service.id
                        
                        # Define time range for logs
                        end_time = datetime.datetime.utcnow()
                        start_time = end_time - datetime.timedelta(days=1)
                        
                        # Get diagnostic settings
                        diagnostic_settings = monitor_client.diagnostic_settings.list(
                            resource_uri=resource_id
                        )
                        
                        app_logs = []
                        
                        for setting in diagnostic_settings:
                            setting_dict = setting.as_dict()
                            
                            # Save diagnostic setting metadata
                            setting_path = self.save_evidence(
                                setting_dict,
                                'azure_app_service_diagnostic',
                                f"{app_service_name}_{setting.name}"
                            )
                            
                            app_logs.append({
                                'setting_name': setting.name,
                                'metadata_path': setting_path
                            })
                        
                        if app_logs:
                            app_evidence['app_service']['logs'] = app_logs
                    
                    except Exception as e:
                        logger.error(f"Error collecting application logs: {str(e)}")
                
            elif self.cloud_provider == 'gcp':
                # Collect GCP App Engine evidence
                project_id = self.provider_kwargs.get('project_id')
                service_name = app_params.get('service_name')
                
                if project_id and service_name:
                    from google.oauth2 import service_account
                    from google.cloud import appengine_admin_v1
                    
                    if self.provider_kwargs.get('credentials_file'):
                        credentials = service_account.Credentials.from_service_account_file(
                            self.provider_kwargs.get('credentials_file')
                        )
                    else:
                        credentials = None
                    
                    # Create App Engine client
                    services_client = appengine_admin_v1.ServicesClient(credentials=credentials)
                    versions_client = appengine_admin_v1.VersionsClient(credentials=credentials)
                    instances_client = appengine_admin_v1.InstancesClient(credentials=credentials)
                    
                    # Get service details
                    service_path = services_client.service_path(project_id, service_name)
                    service = services_client.get_service(name=service_path)
                    
                    # Convert service object to dict for serialization
                    service_dict = {
                        'name': service.name,
                        'id': service.id,
                        'split': {
                            'allocations': dict(service.split.allocations)
                        } if service.split else None
                    }
                    
                    # Save service metadata
                    service_path = self.save_evidence(
                        service_dict,
                        'gcp_appengine_service_metadata',
                        service_name
                    )
                    
                    app_evidence['app_engine'] = {
                        'service_name': service_name,
                        'metadata_path': service_path
                    }
                    
                    # Get versions for this service
                    parent = f"apps/{project_id}/services/{service_name}"
                    versions = versions_client.list_versions(parent=parent)
                    
                    version_list = []
                    for version in versions:
                        version_dict = {
                            'name': version.name,
                            'id': version.id,
                            'runtime': version.runtime,
                            'env': version.env,
                            'serving_status': version.serving_status,
                            'created_by': version.created_by,
                            'create_time': version.create_time.isoformat() if version.create_time else None,
                            'handlers': [
                                {
                                    'url_regex': handler.url_regex,
                                    'script': handler.script,
                                    'security_level': handler.security_level
                                }
                                for handler in version.handlers
                            ] if version.handlers else []
                        }
                        version_list.append(version_dict)
                    
                    if version_list:
                        # Save version metadata
                        versions_path = self.save_evidence(
                            version_list,
                            'gcp_appengine_versions',
                            service_name
                        )
                        
                        app_evidence['app_engine']['versions_path'] = versions_path
                    
                    # Get instances for the latest version
                    if version_list:
                        latest_version = version_list[0]['id']
                        parent = f"apps/{project_id}/services/{service_name}/versions/{latest_version}"
                        
                        try:
                            instances = instances_client.list_instances(parent=parent)
                            
                            instance_list = []
                            for instance in instances:
                                instance_dict = {
                                    'name': instance.name,
                                    'id': instance.id,
                                    'vm_name': instance.vm_name,
                                    'vm_zone_name': instance.vm_zone_name,
                                    'vm_id': instance.vm_id,
                                    'start_time': instance.start_time.isoformat() if instance.start_time else None,
                                    'availability': instance.availability
                                }
                                instance_list.append(instance_dict)
                            
                            if instance_list:
                                # Save instance metadata
                                instances_path = self.save_evidence(
                                    instance_list,
                                    'gcp_appengine_instances',
                                    f"{service_name}_{latest_version}"
                                )
                                
                                app_evidence['app_engine']['instances_path'] = instances_path
                        
                        except Exception as e:
                            logger.error(f"Error collecting instance details: {str(e)}")
                    
                    # Get App Engine logs
                    try:
                        from google.cloud import logging as gcp_logging
                        
                        logging_client = gcp_logging.Client(
                            project=project_id,
                            credentials=credentials
                        )
                        
                        # Define log filters for App Engine
                        filters = [
                            f'resource.type="gae_app"',
                            f'resource.labels.module_id="{service_name}"',
                            f'timestamp>="{(datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat()}"'
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
                                'gcp_appengine_logs',
                                service_name
                            )
                            
                            app_evidence['app_engine']['logs_path'] = logs_path
                    
                    except Exception as e:
                        logger.error(f"Error collecting App Engine logs: {str(e)}")
            
            # Compile collection results
            collection_results = {
                'service_model': 'PaaS',
                'cloud_provider': self.cloud_provider,
                'app_evidence': app_evidence
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting app service evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()


class DatabaseServiceCollector(PaaSCollector):
    """Collector for database service evidence across cloud providers."""
    
    def collect_database_evidence(self, **db_params) -> Dict[str, Any]:
        """
        Collect evidence from database services.
        
        Args:
            **db_params: Provider-specific database parameters:
                - AWS: db_type, db_identifier (RDS, DynamoDB)
                - Azure: resource_group, server_name, database_name
                - GCP: project_id, instance_id (Cloud SQL)
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            db_evidence = {}
            
            if self.cloud_provider == 'aws':
                db_type = db_params.get('db_type')
                db_identifier = db_params.get('db_identifier')
                
                if db_type == 'rds' and db_identifier:
                    import boto3
                    
                    # Create RDS client
                    rds_client = boto3.client(
                        'rds',
                        region_name=self.provider_kwargs.get('region'),
                        aws_access_key_id=self.provider_kwargs.get('credentials', {}).get('access_key'),
                        aws_secret_access_key=self.provider_kwargs.get('credentials', {}).get('secret_key')
                    )
                    
                    # Get DB instance details
                    db_response = rds_client.describe_db_instances(
                        DBInstanceIdentifier=db_identifier
                    )
                    
                    if db_response['DBInstances']:
                        db_data = db_response['DBInstances'][0]
                        
                        # Save DB instance metadata
                        db_path = self.save_evidence(
                            db_data,
                            'aws_rds_metadata',
                            db_identifier
                        )
                        
                        db_evidence['rds'] = {
                            'db_identifier': db_identifier,
                            'metadata_path': db_path
                        }
                        
                        # Get DB snapshots
                        snapshots_response = rds_client.describe_db_snapshots(
                            DBInstanceIdentifier=db_identifier
                        )
                        
                        if snapshots_response['DBSnapshots']:
                            # Save snapshot metadata
                            snapshots_path = self.save_evidence(
                                snapshots_response['DBSnapshots'],
                                'aws_rds_snapshots',
                                db_identifier
                            )
                            
                            db_evidence['rds']['snapshots_path'] = snapshots_path
                        
                        # Get DB logs
                        try:
                            logs_response = rds_client.describe_db_log_files(
                                DBInstanceIdentifier=db_identifier
                            )
                            
                            if 'DescribeDBLogFiles' in logs_response:
                                # Save log file list
                                log_list_path = self.save_evidence(
                                    logs_response['DescribeDBLogFiles'],
                                    'aws_rds_log_files',
                                    db_identifier
                                )
                                
                                db_evidence['rds']['log_list_path'] = log_list_path
                                
                                # Download a sample of log files
                                log_files = []
                                for i, log_file in enumerate(logs_response['DescribeDBLogFiles'][:5]):
                                    try:
                                        log_response = rds_client.download_db_log_file_portion(
                                            DBInstanceIdentifier=db_identifier,
                                            LogFileName=log_file['LogFileName'],
                                            NumberOfLines=1000
                                        )
                                        
                                        if 'LogFileData' in log_response:
                                            log_path = self.save_evidence(
                                                log_response['LogFileData'],
                                                'aws_rds_log',
                                                f"{db_identifier}_{i}"
                                            )
                                            
                                            log_files.append({
                                                'file_name': log_file['LogFileName'],
                                                'metadata_path': log_path
                                            })
                                    
                                    except Exception as e:
                                        logger.error(f"Error downloading log file {log_file['LogFileName']}: {str(e)}")
                                
                                if log_files:
                                    db_evidence['rds']['log_files'] = log_files
                        
                        except Exception as e:
                            logger.error(f"Error collecting RDS logs: {str(e)}")
                
                elif db_type == 'dynamodb' and db_identifier:
                    import boto3
                    
                    # Create DynamoDB client
                    dynamodb_client = boto3.client(
                        'dynamodb',
                        region_name=self.provider_kwargs.get('region'),
                        aws_access_key_id=self.provider_kwargs.get('credentials', {}).get('access_key'),
                        aws_secret_access_key=self.provider_kwargs.get('credentials', {}).get('secret_key')
                    )
                    
                    # Get table details
                    table_response = dynamodb_client.describe_table(
                        TableName=db_identifier
                    )
                    
                    if 'Table' in table_response:
                        table_data = table_response['Table']
                        
                        # Save table metadata
                        table_path = self.save_evidence(
                            table_data,
                            'aws_dynamodb_metadata',
                            db_identifier
                        )
                        
                        db_evidence['dynamodb'] = {
                            'table_name': db_identifier,
                            'metadata_path': table_path
                        }
                        
                        # Get continuous backups status
                        try:
                            backup_response = dynamodb_client.describe_continuous_backups(
                                TableName=db_identifier
                            )
                            
                            if 'ContinuousBackupsDescription' in backup_response:
                                # Save backup metadata
                                backup_path = self.save_evidence(
                                    backup_response['ContinuousBackupsDescription'],
                                    'aws_dynamodb_backups',
                                    db_identifier
                                )
                                
                                db_evidence['dynamodb']['backups_path'] = backup_path
                        
                        except Exception as e:
                            logger.error(f"Error collecting DynamoDB backup info: {str(e)}")
            
            elif self.cloud_provider == 'azure':
                resource_group = db_params.get('resource_group')
                server_name = db_params.get('server_name')
                database_name = db_params.get('database_name')
                db_type = db_params.get('db_type', 'sql')  # Default to SQL
                
                if resource_group and server_name:
                    from azure.identity import DefaultAzureCredential
                    
                    credential = DefaultAzureCredential(
                        tenant_id=self.provider_kwargs.get('tenant_id'),
                        client_id=self.provider_kwargs.get('client_id'),
                        client_secret=self.provider_kwargs.get('client_secret')
                    )
                    
                    if db_type == 'sql':
                        from azure.mgmt.sql import SqlManagementClient
                        
                        sql_client = SqlManagementClient(
                            credential=credential,
                            subscription_id=self.provider_kwargs.get('subscription_id')
                        )
                        
                        # Get server details
                        server = sql_client.servers.get(
                            resource_group_name=resource_group,
                            server_name=server_name
                        )
                        
                        # Save server metadata
                        server_path = self.save_evidence(
                            server.as_dict(),
                            'azure_sql_server_metadata',
                            server_name
                        )
                        
                        db_evidence['azure_sql'] = {
                            'server_name': server_name,
                            'metadata_path': server_path
                        }
                        
                        # Get firewall rules
                        firewall_rules = list(sql_client.firewall_rules.list_by_server(
                            resource_group_name=resource_group,
                            server_name=server_name
                        ))
                        
                        if firewall_rules:
                            # Save firewall rules
                            rules_path = self.save_evidence(
                                [rule.as_dict() for rule in firewall_rules],
                                'azure_sql_firewall_rules',
                                server_name
                            )
                            
                            db_evidence['azure_sql']['firewall_rules_path'] = rules_path
                        
                        # Get database details if specified
                        if database_name:
                            database = sql_client.databases.get(
                                resource_group_name=resource_group,
                                server_name=server_name,
                                database_name=database_name
                            )
                            
                            # Save database metadata
                            db_path = self.save_evidence(
                                database.as_dict(),
                                'azure_sql_database_metadata',
                                database_name
                            )
                            
                            db_evidence['azure_sql']['database'] = {
                                'database_name': database_name,
                                'metadata_path': db_path
                            }
                            
                            # Get transparent data encryption status
                            try:
                                tde = sql_client.transparent_data_encryptions.get(
                                    resource_group_name=resource_group,
                                    server_name=server_name,
                                    database_name=database_name,
                                    transparent_data_encryption_name="current"
                                )
                                
                                # Save TDE status
                                tde_path = self.save_evidence(
                                    tde.as_dict(),
                                    'azure_sql_tde',
                                    database_name
                                )
                                
                                db_evidence['azure_sql']['database']['tde_path'] = tde_path
                            
                            except Exception as e:
                                logger.error(f"Error collecting TDE status: {str(e)}")
                    
                    elif db_type == 'cosmos':
                        from azure.mgmt.cosmosdb import CosmosDBManagementClient
                        
                        cosmos_client = CosmosDBManagementClient(
                            credential=credential,
                            subscription_id=self.provider_kwargs.get('subscription_id')
                        )
                        
                        # Get account details
                        account = cosmos_client.database_accounts.get(
                            resource_group_name=resource_group,
                            account_name=server_name
                        )
                        
                        # Save account metadata
                        account_path = self.save_evidence(
                            account.as_dict(),
                            'azure_cosmos_account_metadata',
                            server_name
                        )
                        
                        db_evidence['azure_cosmos'] = {
                            'account_name': server_name,
                            'metadata_path': account_path
                        }
                        
                        # Get database details if specified
                        if database_name:
                            try:
                                sql_resources = cosmos_client.sql_resources.get_sql_database(
                                    resource_group_name=resource_group,
                                    account_name=server_name,
                                    database_name=database_name
                                )
                                
                                # Save database metadata
                                db_path = self.save_evidence(
                                    sql_resources.as_dict(),
                                    'azure_cosmos_database_metadata',
                                    database_name
                                )
                                
                                db_evidence['azure_cosmos']['database'] = {
                                    'database_name': database_name,
                                    'metadata_path': db_path
                                }
                            
                            except Exception as e:
                                logger.error(f"Error collecting Cosmos DB database details: {str(e)}")
            
            elif self.cloud_provider == 'gcp':
                project_id = self.provider_kwargs.get('project_id')
                instance_id = db_params.get('instance_id')
                db_type = db_params.get('db_type', 'cloudsql')  # Default to Cloud SQL
                
                if project_id and instance_id:
                    from google.oauth2 import service_account
                    
                    if self.provider_kwargs.get('credentials_file'):
                        credentials = service_account.Credentials.from_service_account_file(
                            self.provider_kwargs.get('credentials_file')
                        )
                    else:
                        credentials = None
                    
                    if db_type == 'cloudsql':
                        from google.cloud import sql_v1
                        
                        # Create Cloud SQL client
                        sql_client = sql_v1.SqlInstancesServiceClient(credentials=credentials)
                        
                        # Get instance details
                        instance_path = f"projects/{project_id}/instances/{instance_id}"
                        instance = sql_client.get(name=instance_path)
                        
                        # Convert instance object to dict for serialization
                        instance_dict = {
                            'name': instance.name,
                            'database_version': instance.database_version,
                            'state': instance.state,
                            'region': instance.region,
                            'zone': instance.gce_zone,
                            'settings': {
                                'tier': instance.settings.tier,
                                'availability_type': instance.settings.availability_type,
                                'backup_configuration': {
                                    'enabled': instance.settings.backup_configuration.enabled,
                                    'start_time': instance.settings.backup_configuration.start_time,
                                    'binary_log_enabled': instance.settings.backup_configuration.binary_log_enabled
                                } if instance.settings.backup_configuration else None,
                                'ip_configuration': {
                                    'authorized_networks': [
                                        {
                                            'name': network.name,
                                            'value': network.value
                                        }
                                        for network in instance.settings.ip_configuration.authorized_networks
                                    ]
                                } if instance.settings.ip_configuration else None
                            }
                        }
                        
                        # Save instance metadata
                        instance_path = self.save_evidence(
                            instance_dict,
                            'gcp_cloudsql_metadata',
                            instance_id
                        )
                        
                        db_evidence['cloudsql'] = {
                            'instance_id': instance_id,
                            'metadata_path': instance_path
                        }
                        
                        # Get operations
                        operations_client = sql_v1.SqlOperationsServiceClient(credentials=credentials)
                        parent = f"projects/{project_id}/instances/{instance_id}"
                        
                        try:
                            operations = operations_client.list(parent=parent)
                            
                            operations_list = []
                            for operation in operations:
                                operations_list.append({
                                    'name': operation.name,
                                    'operation_type': operation.operation_type,
                                    'status': operation.status,
                                    'user': operation.user,
                                    'start_time': operation.start_time.isoformat() if operation.start_time else None,
                                    'end_time': operation.end_time.isoformat() if operation.end_time else None
                                })
                            
                            if operations_list:
                                # Save operations metadata
                                operations_path = self.save_evidence(
                                    operations_list,
                                    'gcp_cloudsql_operations',
                                    instance_id
                                )
                                
                                db_evidence['cloudsql']['operations_path'] = operations_path
                        
                        except Exception as e:
                            logger.error(f"Error collecting Cloud SQL operations: {str(e)}")
                        
                        # Get instance logs
                        try:
                            from google.cloud import logging as gcp_logging
                            
                            logging_client = gcp_logging.Client(
                                project=project_id,
                                credentials=credentials
                            )
                            
                            # Define log filters for Cloud SQL
                            filters = [
                                f'resource.type="cloudsql_database"',
                                f'resource.labels.database_id="{project_id}:{instance_id}"',
                                f'timestamp>="{(datetime.datetime.utcnow() - datetime.timedelta(days=1)).isoformat()}"'
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
                                    'gcp_cloudsql_logs',
                                    instance_id
                                )
                                
                                db_evidence['cloudsql']['logs_path'] = logs_path
                        
                        except Exception as e:
                            logger.error(f"Error collecting Cloud SQL logs: {str(e)}")
                    
                    elif db_type == 'firestore':
                        from google.cloud import firestore
                        
                        # Create Firestore client
                        db = firestore.Client(
                            project=project_id,
                            credentials=credentials
                        )
                        
                        # Get collection details
                        collection_id = instance_id  # In this case, instance_id is the collection ID
                        
                        try:
                            # Get collection metadata
                            collection_ref = db.collection(collection_id)
                            
                            # Get a sample of documents
                            docs = collection_ref.limit(10).stream()
                            
                            doc_list = []
                            for doc in docs:
                                doc_list.append({
                                    'id': doc.id,
                                    'data': doc.to_dict()
                                })
                            
                            # Save collection metadata
                            collection_path = self.save_evidence(
                                {
                                    'collection_id': collection_id,
                                    'sample_documents': doc_list
                                },
                                'gcp_firestore_metadata',
                                collection_id
                            )
                            
                            db_evidence['firestore'] = {
                                'collection_id': collection_id,
                                'metadata_path': collection_path
                            }
                        
                        except Exception as e:
                            logger.error(f"Error collecting Firestore collection details: {str(e)}")
            
            # Compile collection results
            collection_results = {
                'service_model': 'PaaS',
                'cloud_provider': self.cloud_provider,
                'database_evidence': db_evidence
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting database service evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()
