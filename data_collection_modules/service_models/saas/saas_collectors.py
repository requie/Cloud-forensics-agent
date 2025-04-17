"""
Service model-specific collectors for SaaS environments in the Cloud Forensics AI Agent.

This module provides collectors for gathering evidence from Software as a Service
environments while maintaining forensic integrity and chain of custody.
"""

import datetime
import json
import logging
import os
import requests
from typing import Any, Dict, List, Optional, Union

from ...core.base_collector import BaseCollector
from ...utils import evidence_utils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class SaaSCollector(BaseCollector):
    """Base collector for Software as a Service evidence."""
    
    def __init__(self, case_id: str, evidence_storage_path: str, 
                service_name: str, **service_kwargs):
        """
        Initialize the SaaS collector.
        
        Args:
            case_id: Unique identifier for the forensic case
            evidence_storage_path: Path where collected evidence will be stored
            service_name: Name of the SaaS service
            **service_kwargs: Service-specific arguments
        """
        super().__init__(case_id, evidence_storage_path)
        self.service_name = service_name.lower()
        self.service_kwargs = service_kwargs
        
        logger.info(f"Initialized SaaS collector for {service_name}")
    
    def collect(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Collect evidence from SaaS resources.
        
        This method must be implemented by specific SaaS collector subclasses.
        """
        raise NotImplementedError("Subclasses must implement this method")


class Office365Collector(SaaSCollector):
    """Collector for Microsoft Office 365 evidence."""
    
    def collect_tenant_evidence(self, **tenant_params) -> Dict[str, Any]:
        """
        Collect evidence from an Office 365 tenant.
        
        Args:
            **tenant_params: Office 365 tenant parameters:
                - tenant_id: Office 365 tenant ID
                - client_id: Application client ID
                - client_secret: Application client secret
                - user_upn: Optional user principal name to focus on
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            tenant_id = tenant_params.get('tenant_id')
            client_id = tenant_params.get('client_id')
            client_secret = tenant_params.get('client_secret')
            user_upn = tenant_params.get('user_upn')
            
            if not tenant_id or not client_id or not client_secret:
                raise ValueError("Office 365 collection requires tenant_id, client_id, and client_secret")
            
            # Get access token
            token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
            token_data = {
                'grant_type': 'client_credentials',
                'client_id': client_id,
                'client_secret': client_secret,
                'scope': 'https://graph.microsoft.com/.default'
            }
            
            token_response = requests.post(token_url, data=token_data)
            token_response.raise_for_status()
            
            access_token = token_response.json().get('access_token')
            
            if not access_token:
                raise ValueError("Failed to obtain access token")
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Collect tenant information
            tenant_url = "https://graph.microsoft.com/v1.0/organization"
            tenant_response = requests.get(tenant_url, headers=headers)
            tenant_response.raise_for_status()
            
            tenant_data = tenant_response.json().get('value', [])
            
            # Save tenant metadata
            tenant_path = self.save_evidence(
                tenant_data,
                'office365_tenant_metadata',
                tenant_id
            )
            
            tenant_evidence = {
                'tenant_id': tenant_id,
                'metadata_path': tenant_path
            }
            
            # Collect audit logs
            audit_logs = []
            try:
                # Note: This is a simplified approach. In a real implementation,
                # you would use the Office 365 Management API for audit logs
                audit_url = "https://graph.microsoft.com/v1.0/auditLogs/signIns"
                audit_response = requests.get(audit_url, headers=headers)
                audit_response.raise_for_status()
                
                audit_data = audit_response.json().get('value', [])
                
                # Save audit logs
                audit_path = self.save_evidence(
                    audit_data,
                    'office365_audit_logs',
                    tenant_id
                )
                
                audit_logs.append({
                    'log_type': 'signIns',
                    'metadata_path': audit_path
                })
                
                # Get directory audit logs
                dir_audit_url = "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits"
                dir_audit_response = requests.get(dir_audit_url, headers=headers)
                dir_audit_response.raise_for_status()
                
                dir_audit_data = dir_audit_response.json().get('value', [])
                
                # Save directory audit logs
                dir_audit_path = self.save_evidence(
                    dir_audit_data,
                    'office365_directory_audit_logs',
                    tenant_id
                )
                
                audit_logs.append({
                    'log_type': 'directoryAudits',
                    'metadata_path': dir_audit_path
                })
                
            except Exception as e:
                logger.error(f"Error collecting audit logs: {str(e)}")
            
            # Collect user information if specified
            user_evidence = None
            if user_upn:
                try:
                    # Get user details
                    user_url = f"https://graph.microsoft.com/v1.0/users/{user_upn}"
                    user_response = requests.get(user_url, headers=headers)
                    user_response.raise_for_status()
                    
                    user_data = user_response.json()
                    
                    # Save user metadata
                    user_path = self.save_evidence(
                        user_data,
                        'office365_user_metadata',
                        user_upn
                    )
                    
                    user_evidence = {
                        'user_upn': user_upn,
                        'metadata_path': user_path
                    }
                    
                    # Get user's recent emails
                    try:
                        mail_url = f"https://graph.microsoft.com/v1.0/users/{user_upn}/messages?$top=50"
                        mail_response = requests.get(mail_url, headers=headers)
                        mail_response.raise_for_status()
                        
                        mail_data = mail_response.json().get('value', [])
                        
                        # Save email metadata
                        mail_path = self.save_evidence(
                            mail_data,
                            'office365_user_emails',
                            user_upn
                        )
                        
                        user_evidence['emails_path'] = mail_path
                    
                    except Exception as e:
                        logger.error(f"Error collecting user emails: {str(e)}")
                    
                    # Get user's OneDrive files
                    try:
                        files_url = f"https://graph.microsoft.com/v1.0/users/{user_upn}/drive/root/children"
                        files_response = requests.get(files_url, headers=headers)
                        files_response.raise_for_status()
                        
                        files_data = files_response.json().get('value', [])
                        
                        # Save files metadata
                        files_path = self.save_evidence(
                            files_data,
                            'office365_user_files',
                            user_upn
                        )
                        
                        user_evidence['files_path'] = files_path
                    
                    except Exception as e:
                        logger.error(f"Error collecting user files: {str(e)}")
                
                except Exception as e:
                    logger.error(f"Error collecting user information: {str(e)}")
            
            # Compile collection results
            collection_results = {
                'service_model': 'SaaS',
                'service_name': 'Office365',
                'tenant_evidence': tenant_evidence,
                'audit_logs': audit_logs,
                'user_evidence': user_evidence
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting Office 365 evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()


class GSuiteCollector(SaaSCollector):
    """Collector for Google Workspace (formerly G Suite) evidence."""
    
    def collect_domain_evidence(self, **domain_params) -> Dict[str, Any]:
        """
        Collect evidence from a Google Workspace domain.
        
        Args:
            **domain_params: Google Workspace domain parameters:
                - domain: Domain name
                - credentials_file: Path to service account credentials file
                - admin_email: Admin email for delegated access
                - user_email: Optional user email to focus on
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            domain = domain_params.get('domain')
            credentials_file = domain_params.get('credentials_file')
            admin_email = domain_params.get('admin_email')
            user_email = domain_params.get('user_email')
            
            if not domain or not credentials_file or not admin_email:
                raise ValueError("Google Workspace collection requires domain, credentials_file, and admin_email")
            
            # Import Google API libraries
            from google.oauth2 import service_account
            from googleapiclient.discovery import build
            
            # Set up credentials with domain-wide delegation
            scopes = [
                'https://www.googleapis.com/auth/admin.directory.user.readonly',
                'https://www.googleapis.com/auth/admin.directory.domain.readonly',
                'https://www.googleapis.com/auth/admin.reports.audit.readonly',
                'https://www.googleapis.com/auth/gmail.readonly',
                'https://www.googleapis.com/auth/drive.readonly'
            ]
            
            credentials = service_account.Credentials.from_service_account_file(
                credentials_file, scopes=scopes
            )
            
            delegated_credentials = credentials.with_subject(admin_email)
            
            # Collect domain information
            directory_service = build('admin', 'directory_v1', credentials=delegated_credentials)
            
            # Get domain information
            domains_response = directory_service.domains().list(customer='my_customer').execute()
            
            # Save domain metadata
            domain_path = self.save_evidence(
                domains_response,
                'gsuite_domain_metadata',
                domain
            )
            
            domain_evidence = {
                'domain': domain,
                'metadata_path': domain_path
            }
            
            # Collect audit logs
            audit_logs = []
            try:
                reports_service = build('admin', 'reports_v1', credentials=delegated_credentials)
                
                # Get admin activity logs
                admin_logs_response = reports_service.activities().list(
                    userKey='all',
                    applicationName='admin',
                    maxResults=100
                ).execute()
                
                # Save admin logs
                admin_logs_path = self.save_evidence(
                    admin_logs_response,
                    'gsuite_admin_logs',
                    domain
                )
                
                audit_logs.append({
                    'log_type': 'admin',
                    'metadata_path': admin_logs_path
                })
                
                # Get login activity logs
                login_logs_response = reports_service.activities().list(
                    userKey='all',
                    applicationName='login',
                    maxResults=100
                ).execute()
                
                # Save login logs
                login_logs_path = self.save_evidence(
                    login_logs_response,
                    'gsuite_login_logs',
                    domain
                )
                
                audit_logs.append({
                    'log_type': 'login',
                    'metadata_path': login_logs_path
                })
                
            except Exception as e:
                logger.error(f"Error collecting audit logs: {str(e)}")
            
            # Collect user information if specified
            user_evidence = None
            if user_email:
                try:
                    # Get user details
                    user_response = directory_service.users().get(userKey=user_email).execute()
                    
                    # Save user metadata
                    user_path = self.save_evidence(
                        user_response,
                        'gsuite_user_metadata',
                        user_email
                    )
                    
                    user_evidence = {
                        'user_email': user_email,
                        'metadata_path': user_path
                    }
                    
                    # Get user's recent emails
                    try:
                        gmail_service = build('gmail', 'v1', credentials=delegated_credentials.with_subject(user_email))
                        
                        messages_response = gmail_service.users().messages().list(
                            userId='me',
                            maxResults=50
                        ).execute()
                        
                        # Get full message details for each message
                        messages = []
                        for msg in messages_response.get('messages', []):
                            msg_id = msg['id']
                            message = gmail_service.users().messages().get(userId='me', id=msg_id).execute()
                            messages.append(message)
                        
                        # Save email metadata
                        mail_path = self.save_evidence(
                            messages,
                            'gsuite_user_emails',
                            user_email
                        )
                        
                        user_evidence['emails_path'] = mail_path
                    
                    except Exception as e:
                        logger.error(f"Error collecting user emails: {str(e)}")
                    
                    # Get user's Drive files
                    try:
                        drive_service = build('drive', 'v3', credentials=delegated_credentials.with_subject(user_email))
                        
                        files_response = drive_service.files().list(
                            pageSize=100,
                            fields="files(id, name, mimeType, createdTime, modifiedTime, owners, sharingUser, shared)"
                        ).execute()
                        
                        # Save files metadata
                        files_path = self.save_evidence(
                            files_response,
                            'gsuite_user_files',
                            user_email
                        )
                        
                        user_evidence['files_path'] = files_path
                    
                    except Exception as e:
                        logger.error(f"Error collecting user files: {str(e)}")
                
                except Exception as e:
                    logger.error(f"Error collecting user information: {str(e)}")
            
            # Compile collection results
            collection_results = {
                'service_model': 'SaaS',
                'service_name': 'GoogleWorkspace',
                'domain_evidence': domain_evidence,
                'audit_logs': audit_logs,
                'user_evidence': user_evidence
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting Google Workspace evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()


class SalesforceCollector(SaaSCollector):
    """Collector for Salesforce evidence."""
    
    def collect_org_evidence(self, **org_params) -> Dict[str, Any]:
        """
        Collect evidence from a Salesforce organization.
        
        Args:
            **org_params: Salesforce organization parameters:
                - instance_url: Salesforce instance URL
                - client_id: Connected app client ID
                - client_secret: Connected app client secret
                - username: Salesforce username
                - password: Salesforce password
                - security_token: Salesforce security token
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            instance_url = org_params.get('instance_url')
            client_id = org_params.get('client_id')
            client_secret = org_params.get('client_secret')
            username = org_params.get('username')
            password = org_params.get('password')
            security_token = org_params.get('security_token')
            
            if not all([instance_url, client_id, client_secret, username, password]):
                raise ValueError("Salesforce collection requires instance_url, client_id, client_secret, username, and password")
            
            # Get access token using password flow
            token_url = f"{instance_url}/services/oauth2/token"
            token_data = {
                'grant_type': 'password',
                'client_id': client_id,
                'client_secret': client_secret,
                'username': username,
                'password': password + (security_token or '')
            }
            
            token_response = requests.post(token_url, data=token_data)
            token_response.raise_for_status()
            
            token_info = token_response.json()
            access_token = token_info.get('access_token')
            instance_url = token_info.get('instance_url')
            
            if not access_token or not instance_url:
                raise ValueError("Failed to obtain access token")
            
            headers = {
                'Authorization': f'Bearer {access_token}',
                'Content-Type': 'application/json'
            }
            
            # Collect organization information
            org_url = f"{instance_url}/services/data/v52.0/sobjects/Organization/describe"
            org_response = requests.get(org_url, headers=headers)
            org_response.raise_for_status()
            
            org_data = org_response.json()
            
            # Get organization ID
            org_id_url = f"{instance_url}/services/data/v52.0/query?q=SELECT+Id,+Name,+InstanceName,+OrganizationType+FROM+Organization"
            org_id_response = requests.get(org_id_url, headers=headers)
            org_id_response.raise_for_status()
            
            org_id_data = org_id_response.json()
            org_id = org_id_data.get('records', [{}])[0].get('Id', 'unknown')
            
            # Save organization metadata
            org_path = self.save_evidence(
                {
                    'org_describe': org_data,
                    'org_details': org_id_data
                },
                'salesforce_org_metadata',
                org_id
            )
            
            org_evidence = {
                'org_id': org_id,
                'metadata_path': org_path
            }
            
            # Collect setup audit trail
            audit_logs = []
            try:
                audit_url = f"{instance_url}/services/data/v52.0/query?q=SELECT+Id,+Action,+Section,+CreatedBy.Name,+CreatedBy.Username,+CreatedDate,+Display+FROM+SetupAuditTrail+ORDER+BY+CreatedDate+DESC+LIMIT+100"
                audit_response = requests.get(audit_url, headers=headers)
                audit_response.raise_for_status()
                
                audit_data = audit_response.json()
                
                # Save audit logs
                audit_path = self.save_evidence(
                    audit_data,
                    'salesforce_audit_trail',
                    org_id
                )
                
                audit_logs.append({
                    'log_type': 'setupAuditTrail',
                    'metadata_path': audit_path
                })
                
                # Get login history
                login_url = f"{instance_url}/services/data/v52.0/query?q=SELECT+Id,+UserId,+LoginTime,+LoginType,+SourceIp,+Status,+Application,+Browser,+Platform+FROM+LoginHistory+ORDER+BY+LoginTime+DESC+LIMIT+100"
                login_response = requests.get(login_url, headers=headers)
                login_response.raise_for_status()
                
                login_data = login_response.json()
                
                # Save login history
                login_path = self.save_evidence(
                    login_data,
                    'salesforce_login_history',
                    org_id
                )
                
                audit_logs.append({
                    'log_type': 'loginHistory',
                    'metadata_path': login_path
                })
                
            except Exception as e:
                logger.error(f"Error collecting audit logs: {str(e)}")
            
            # Collect user information
            try:
                users_url = f"{instance_url}/services/data/v52.0/query?q=SELECT+Id,+Username,+Email,+Name,+Profile.Name,+IsActive,+LastLoginDate+FROM+User+LIMIT+100"
                users_response = requests.get(users_url, headers=headers)
                users_response.raise_for_status()
                
                users_data = users_response.json()
                
                # Save users metadata
                users_path = self.save_evidence(
                    users_data,
                    'salesforce_users',
                    org_id
                )
                
                org_evidence['users_path'] = users_path
            
            except Exception as e:
                logger.error(f"Error collecting user information: {str(e)}")
            
            # Collect permission sets
            try:
                perm_url = f"{instance_url}/services/data/v52.0/query?q=SELECT+Id,+Name,+Label,+Description+FROM+PermissionSet+LIMIT+100"
                perm_response = requests.get(perm_url, headers=headers)
                perm_response.raise_for_status()
                
                perm_data = perm_response.json()
                
                # Save permission sets metadata
                perm_path = self.save_evidence(
                    perm_data,
                    'salesforce_permission_sets',
                    org_id
                )
                
                org_evidence['permission_sets_path'] = perm_path
            
            except Exception as e:
                logger.error(f"Error collecting permission sets: {str(e)}")
            
            # Compile collection results
            collection_results = {
                'service_model': 'SaaS',
                'service_name': 'Salesforce',
                'org_evidence': org_evidence,
                'audit_logs': audit_logs
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting Salesforce evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()


class GenericSaaSCollector(SaaSCollector):
    """Collector for generic SaaS services using API access."""
    
    def collect_api_evidence(self, **api_params) -> Dict[str, Any]:
        """
        Collect evidence from a generic SaaS service using its API.
        
        Args:
            **api_params: API parameters:
                - base_url: Base URL for the API
                - auth_type: Authentication type ('bearer', 'basic', 'api_key')
                - auth_credentials: Dict containing auth credentials
                - endpoints: List of API endpoints to collect from
            
        Returns:
            Dictionary containing metadata about the collected evidence
        """
        self.start_collection()
        
        try:
            base_url = api_params.get('base_url')
            auth_type = api_params.get('auth_type')
            auth_credentials = api_params.get('auth_credentials', {})
            endpoints = api_params.get('endpoints', [])
            
            if not base_url or not auth_type or not auth_credentials or not endpoints:
                raise ValueError("Generic SaaS collection requires base_url, auth_type, auth_credentials, and endpoints")
            
            # Prepare authentication
            headers = {}
            auth = None
            
            if auth_type == 'bearer':
                token = auth_credentials.get('token')
                if not token:
                    raise ValueError("Bearer authentication requires a token")
                headers['Authorization'] = f'Bearer {token}'
            
            elif auth_type == 'basic':
                username = auth_credentials.get('username')
                password = auth_credentials.get('password')
                if not username or not password:
                    raise ValueError("Basic authentication requires username and password")
                auth = (username, password)
            
            elif auth_type == 'api_key':
                key_name = auth_credentials.get('key_name')
                key_value = auth_credentials.get('key_value')
                key_location = auth_credentials.get('key_location', 'header')
                
                if not key_name or not key_value:
                    raise ValueError("API key authentication requires key_name and key_value")
                
                if key_location == 'header':
                    headers[key_name] = key_value
                # For query params, we'll add them to the URL later
            
            else:
                raise ValueError(f"Unsupported authentication type: {auth_type}")
            
            # Add common headers
            headers['Content-Type'] = 'application/json'
            
            # Collect evidence from each endpoint
            endpoint_results = []
            
            for endpoint in endpoints:
                endpoint_path = endpoint.get('path')
                endpoint_method = endpoint.get('method', 'GET')
                endpoint_params = endpoint.get('params', {})
                endpoint_data = endpoint.get('data')
                endpoint_name = endpoint.get('name', endpoint_path.replace('/', '_'))
                
                if not endpoint_path:
                    logger.warning(f"Skipping endpoint with no path: {endpoint}")
                    continue
                
                # Build URL
                url = f"{base_url.rstrip('/')}/{endpoint_path.lstrip('/')}"
                
                # Add API key to query params if needed
                if auth_type == 'api_key' and auth_credentials.get('key_location') == 'query':
                    endpoint_params[auth_credentials.get('key_name')] = auth_credentials.get('key_value')
                
                try:
                    # Make the request
                    if endpoint_method.upper() == 'GET':
                        response = requests.get(url, headers=headers, params=endpoint_params, auth=auth)
                    elif endpoint_method.upper() == 'POST':
                        response = requests.post(url, headers=headers, params=endpoint_params, json=endpoint_data, auth=auth)
                    elif endpoint_method.upper() == 'PUT':
                        response = requests.put(url, headers=headers, params=endpoint_params, json=endpoint_data, auth=auth)
                    elif endpoint_method.upper() == 'DELETE':
                        response = requests.delete(url, headers=headers, params=endpoint_params, auth=auth)
                    else:
                        logger.warning(f"Unsupported method {endpoint_method} for endpoint {endpoint_path}")
                        continue
                    
                    response.raise_for_status()
                    
                    # Try to parse as JSON
                    try:
                        response_data = response.json()
                    except ValueError:
                        # Not JSON, use text
                        response_data = response.text
                    
                    # Save response data
                    response_path = self.save_evidence(
                        response_data,
                        f'saas_{self.service_name}_api_response',
                        endpoint_name
                    )
                    
                    endpoint_results.append({
                        'endpoint': endpoint_path,
                        'method': endpoint_method,
                        'status_code': response.status_code,
                        'metadata_path': response_path
                    })
                
                except Exception as e:
                    logger.error(f"Error collecting from endpoint {endpoint_path}: {str(e)}")
            
            # Compile collection results
            collection_results = {
                'service_model': 'SaaS',
                'service_name': self.service_name,
                'base_url': base_url,
                'auth_type': auth_type,
                'endpoint_results': endpoint_results
            }
            
            return collection_results
            
        except Exception as e:
            logger.error(f"Error collecting generic SaaS evidence: {str(e)}")
            raise
        
        finally:
            self.end_collection()
