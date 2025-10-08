"""Synthetic incident scenarios for exercising the Cloud Forensics agent."""
from __future__ import annotations

import datetime as _dt
import logging
import uuid
from typing import Any, Dict

LOGGER = logging.getLogger(__name__)


def advanced_persistent_access_scenario() -> Dict[str, Any]:
    """Build a cross-cloud exfiltration scenario used for integration tests.

    The scenario models an attacker who compromises identities across AWS, Azure,
    and GCP to siphon sensitive data.  The structure matches the evidence format
    expected by the agent pipeline so it can be dropped directly into collection,
    analysis, and reporting workflows.
    """
    LOGGER.info("Generating synthetic multi-cloud incident dataset")

    case_id = f"TEST-{uuid.uuid4().hex[:8]}"
    now = _dt.datetime.utcnow().replace(tzinfo=_dt.timezone.utc)
    start_time = now - _dt.timedelta(hours=24)

    def iso(ts: _dt.datetime) -> str:
        return ts.isoformat().replace("+00:00", "Z")

    aws_cloudtrail_events = [
        {
            "eventTime": iso(start_time + _dt.timedelta(minutes=5)),
            "eventName": "ConsoleLogin",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "accountId": "123456789012",
                "userName": "alice",
            },
            "sourceIPAddress": "203.0.113.1",
            "userAgent": "Mozilla/5.0",
            "eventSource": "signin.amazonaws.com",
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsConsoleSignIn",
            "recipientAccountId": "123456789012",
        },
        {
            "eventTime": iso(start_time + _dt.timedelta(minutes=10)),
            "eventName": "CreateAccessKey",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "accountId": "123456789012",
                "userName": "alice",
            },
            "sourceIPAddress": "203.0.113.1",
            "userAgent": "Mozilla/5.0",
            "eventSource": "iam.amazonaws.com",
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
        },
        {
            "eventTime": iso(start_time + _dt.timedelta(minutes=15)),
            "eventName": "AttachUserPolicy",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "accountId": "123456789012",
                "userName": "alice",
            },
            "sourceIPAddress": "203.0.113.1",
            "userAgent": "Mozilla/5.0",
            "eventSource": "iam.amazonaws.com",
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "requestParameters": {
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "userName": "alice",
            },
            "recipientAccountId": "123456789012",
        },
        {
            "eventTime": iso(start_time + _dt.timedelta(minutes=20)),
            "eventName": "CreateUser",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "accountId": "123456789012",
                "userName": "alice",
            },
            "sourceIPAddress": "203.0.113.1",
            "userAgent": "Mozilla/5.0",
            "eventSource": "iam.amazonaws.com",
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "requestParameters": {"userName": "backdoor-admin"},
            "recipientAccountId": "123456789012",
        },
        {
            "eventTime": iso(start_time + _dt.timedelta(minutes=25)),
            "eventName": "AttachUserPolicy",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "accountId": "123456789012",
                "userName": "alice",
            },
            "sourceIPAddress": "203.0.113.1",
            "userAgent": "Mozilla/5.0",
            "eventSource": "iam.amazonaws.com",
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "requestParameters": {
                "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess",
                "userName": "backdoor-admin",
            },
            "recipientAccountId": "123456789012",
        },
        {
            "eventTime": iso(start_time + _dt.timedelta(minutes=30)),
            "eventName": "GetObject",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "accountId": "123456789012",
                "userName": "alice",
            },
            "sourceIPAddress": "203.0.113.1",
            "userAgent": "aws-cli/2.0.0",
            "eventSource": "s3.amazonaws.com",
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "requestParameters": {
                "bucketName": "company-financial-data",
                "key": "quarterly-results-2025-Q1.xlsx",
            },
            "recipientAccountId": "123456789012",
        },
        {
            "eventTime": iso(start_time + _dt.timedelta(minutes=35)),
            "eventName": "GetObject",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/alice",
                "accountId": "123456789012",
                "userName": "alice",
            },
            "sourceIPAddress": "203.0.113.1",
            "userAgent": "aws-cli/2.0.0",
            "eventSource": "s3.amazonaws.com",
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsApiCall",
            "requestParameters": {
                "bucketName": "company-financial-data",
                "key": "customer-database-backup.sql",
            },
            "recipientAccountId": "123456789012",
        },
        {
            "eventTime": iso(start_time + _dt.timedelta(minutes=40)),
            "eventName": "ConsoleLogin",
            "userIdentity": {
                "type": "IAMUser",
                "arn": "arn:aws:iam::123456789012:user/backdoor-admin",
                "accountId": "123456789012",
                "userName": "backdoor-admin",
            },
            "sourceIPAddress": "198.51.100.2",
            "userAgent": "Mozilla/5.0",
            "eventSource": "signin.amazonaws.com",
            "eventID": str(uuid.uuid4()),
            "eventType": "AwsConsoleSignIn",
            "recipientAccountId": "123456789012",
        },
    ]

    aws_s3_logs = [
        {
            "bucket_owner": "123456789012",
            "bucket": "company-financial-data",
            "time": (start_time + _dt.timedelta(minutes=30)).strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "remote_ip": "203.0.113.1",
            "requester": "arn:aws:iam::123456789012:user/alice",
            "request_id": str(uuid.uuid4()),
            "operation": "REST.GET.OBJECT",
            "key": "quarterly-results-2025-Q1.xlsx",
            "request_uri": "GET /quarterly-results-2025-Q1.xlsx HTTP/1.1",
            "http_status": 200,
            "bytes_sent": 1_048_576,
        },
        {
            "bucket_owner": "123456789012",
            "bucket": "company-financial-data",
            "time": (start_time + _dt.timedelta(minutes=35)).strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "remote_ip": "203.0.113.1",
            "requester": "arn:aws:iam::123456789012:user/alice",
            "request_id": str(uuid.uuid4()),
            "operation": "REST.GET.OBJECT",
            "key": "customer-database-backup.sql",
            "request_uri": "GET /customer-database-backup.sql HTTP/1.1",
            "http_status": 200,
            "bytes_sent": 524_288_000,
        },
        {
            "bucket_owner": "123456789012",
            "bucket": "company-financial-data",
            "time": (start_time + _dt.timedelta(minutes=45)).strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "remote_ip": "198.51.100.2",
            "requester": "arn:aws:iam::123456789012:user/backdoor-admin",
            "request_id": str(uuid.uuid4()),
            "operation": "REST.GET.BUCKET",
            "key": "",
            "request_uri": "GET / HTTP/1.1",
            "http_status": 200,
            "bytes_sent": 2_048,
        },
        {
            "bucket_owner": "123456789012",
            "bucket": "company-financial-data",
            "time": (start_time + _dt.timedelta(minutes=50)).strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "remote_ip": "198.51.100.2",
            "requester": "arn:aws:iam::123456789012:user/backdoor-admin",
            "request_id": str(uuid.uuid4()),
            "operation": "REST.GET.OBJECT",
            "key": "employee-salaries-2025.xlsx",
            "request_uri": "GET /employee-salaries-2025.xlsx HTTP/1.1",
            "http_status": 200,
            "bytes_sent": 2_097_152,
        },
        {
            "bucket_owner": "123456789012",
            "bucket": "company-financial-data",
            "time": (start_time + _dt.timedelta(minutes=55)).strftime("%d/%b/%Y:%H:%M:%S +0000"),
            "remote_ip": "198.51.100.2",
            "requester": "arn:aws:iam::123456789012:user/backdoor-admin",
            "request_id": str(uuid.uuid4()),
            "operation": "REST.GET.OBJECT",
            "key": "intellectual-property/product-roadmap-2025-2026.pdf",
            "request_uri": "GET /intellectual-property/product-roadmap-2025-2026.pdf HTTP/1.1",
            "http_status": 200,
            "bytes_sent": 4_194_304,
        },
    ]

    azure_activity_logs = [
        {
            "eventTimestamp": iso(start_time + _dt.timedelta(minutes=60)),
            "operationName": "Microsoft.AAD/SignIns",
            "caller": "bob@company.com",
            "resourceId": "/tenants/00000000-0000-0000-0000-000000000000/providers/Microsoft.AAD/SignIns",
            "callerIpAddress": "203.0.113.2",
            "level": "Informational",
            "resultType": "Success",
            "resultSignature": "Success",
            "category": "SignInLogs",
            "properties": {
                "userPrincipalName": "bob@company.com",
                "appId": "00000000-0000-0000-0000-000000000000",
                "appDisplayName": "Azure Portal",
            },
        },
        {
            "eventTimestamp": iso(start_time + _dt.timedelta(minutes=65)),
            "operationName": "Microsoft.Authorization/roleAssignments/write",
            "caller": "bob@company.com",
            "resourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleAssignments/00000000-0000-0000-0000-000000000000",
            "callerIpAddress": "203.0.113.2",
            "level": "Informational",
            "resultType": "Success",
            "resultSignature": "Success",
            "category": "Administrative",
            "properties": {
                "principalId": "00000000-0000-0000-0000-000000000000",
                "roleDefinitionId": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/00000000-0000-0000-0000-000000000000",
                "roleDefinitionName": "Owner",
            },
        },
        {
            "eventTimestamp": iso(start_time + _dt.timedelta(minutes=70)),
            "operationName": "Microsoft.Storage/storageAccounts/listKeys/action",
            "caller": "bob@company.com",
            "resourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/company-data/providers/Microsoft.Storage/storageAccounts/companydata",
            "callerIpAddress": "203.0.113.2",
            "level": "Informational",
            "resultType": "Success",
            "resultSignature": "Success",
            "category": "Administrative",
            "properties": {},
        },
        {
            "eventTimestamp": iso(start_time + _dt.timedelta(minutes=75)),
            "operationName": "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            "caller": "bob@company.com",
            "resourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/company-data/providers/Microsoft.Storage/storageAccounts/companydata/blobServices/default/containers/financial-data/blobs/merger-plans-2025.docx",
            "callerIpAddress": "203.0.113.2",
            "level": "Informational",
            "resultType": "Success",
            "resultSignature": "Success",
            "category": "DataAccess",
            "properties": {},
        },
        {
            "eventTimestamp": iso(start_time + _dt.timedelta(minutes=80)),
            "operationName": "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read",
            "caller": "bob@company.com",
            "resourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/company-data/providers/Microsoft.Storage/storageAccounts/companydata/blobServices/default/containers/financial-data/blobs/acquisition-targets-2025.xlsx",
            "callerIpAddress": "203.0.113.2",
            "level": "Informational",
            "resultType": "Success",
            "resultSignature": "Success",
            "category": "DataAccess",
            "properties": {},
        },
        {
            "eventTimestamp": iso(start_time + _dt.timedelta(minutes=85)),
            "operationName": "Microsoft.AAD/users/create",
            "caller": "bob@company.com",
            "resourceId": "/tenants/00000000-0000-0000-0000-000000000000/providers/Microsoft.AAD/users/00000000-0000-0000-0000-000000000000",
            "callerIpAddress": "203.0.113.2",
            "level": "Informational",
            "resultType": "Success",
            "resultSignature": "Success",
            "category": "Administrative",
            "properties": {
                "userPrincipalName": "backdoor-admin@company.com",
                "displayName": "System Administrator",
            },
        },
        {
            "eventTimestamp": iso(start_time + _dt.timedelta(minutes=90)),
            "operationName": "Microsoft.Authorization/roleAssignments/write",
            "caller": "bob@company.com",
            "resourceId": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleAssignments/00000000-0000-0000-0000-000000000001",
            "callerIpAddress": "203.0.113.2",
            "level": "Informational",
            "resultType": "Success",
            "resultSignature": "Success",
            "category": "Administrative",
            "properties": {
                "principalId": "00000000-0000-0000-0000-000000000000",
                "principalName": "backdoor-admin@company.com",
                "roleDefinitionId": "/subscriptions/00000000-0000-0000-0000-000000000000/providers/Microsoft.Authorization/roleDefinitions/00000000-0000-0000-0000-000000000000",
                "roleDefinitionName": "Owner",
            },
        },
    ]

    gcp_audit_logs = [
        {
            "timestamp": iso(start_time + _dt.timedelta(minutes=120)),
            "resource": {
                "type": "audited_resource",
                "labels": {"project_id": "company-project"},
            },
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "charlie@company.com"},
                "requestMetadata": {"callerIp": "203.0.113.3"},
                "serviceName": "login.googleapis.com",
                "methodName": "google.login.Login.login",
                "status": {},
            },
        },
        {
            "timestamp": iso(start_time + _dt.timedelta(minutes=135)),
            "resource": {
                "type": "project",
                "labels": {"project_id": "company-project"},
            },
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "charlie@company.com"},
                "requestMetadata": {"callerIp": "203.0.113.3"},
                "serviceName": "iam.googleapis.com",
                "methodName": "CreateServiceAccount",
                "resourceName": "projects/company-project",
                "request": {"accountId": "backdoor-admin"},
                "status": {},
            },
        },
        {
            "timestamp": iso(start_time + _dt.timedelta(minutes=150)),
            "resource": {
                "type": "project",
                "labels": {"project_id": "company-project"},
            },
            "protoPayload": {
                "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
                "authenticationInfo": {"principalEmail": "charlie@company.com"},
                "requestMetadata": {"callerIp": "203.0.113.3"},
                "serviceName": "iam.googleapis.com",
                "methodName": "SetIamPolicy",
                "resourceName": "projects/company-project",
                "request": {
                    "policy": {
                        "bindings": [
                            {
                                "role": "roles/owner",
                                "members": [
                                    "serviceAccount:backdoor-admin@company-project.iam.gserviceaccount.com"
                                ],
                            }
                        ]
                    }
                },
                "status": {},
            },
        },
    ]

    metadata = {
        "case_id": case_id,
        "collection_time": iso(now),
        "time_range": {"start": iso(start_time), "end": iso(now)},
        "sources": [
            {
                "name": "AWS CloudTrail",
                "type": "audit_logs",
                "collection_time": iso(now),
            },
            {
                "name": "AWS S3 Access Logs",
                "type": "access_logs",
                "collection_time": iso(now),
            },
            {
                "name": "Azure Activity Logs",
                "type": "audit_logs",
                "collection_time": iso(now),
            },
            {
                "name": "GCP Audit Logs",
                "type": "audit_logs",
                "collection_time": iso(now),
            },
        ],
        "statistics": {
            "aws_cloudtrail_events": len(aws_cloudtrail_events),
            "aws_s3_logs": len(aws_s3_logs),
            "azure_activity_logs": len(azure_activity_logs),
            "gcp_audit_logs": len(gcp_audit_logs),
        },
    }

    return {
        "aws_cloudtrail": aws_cloudtrail_events,
        "aws_s3_logs": aws_s3_logs,
        "azure_activity_logs": azure_activity_logs,
        "gcp_audit_logs": gcp_audit_logs,
        "metadata": metadata,
    }

__all__ = ["advanced_persistent_access_scenario"]
