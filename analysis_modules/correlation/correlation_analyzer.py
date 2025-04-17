"""
Correlation module for the Cloud Forensics AI Agent.

This module provides functionality for correlating evidence across different
cloud providers, services, and data sources to identify complex attack patterns.
"""

import datetime
import json
import logging
import os
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..core.base_analyzer import BaseAnalyzer
from ..utils import analysis_utils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CorrelationAnalyzer(BaseAnalyzer):
    """
    Analyzer for correlating evidence across different cloud providers and services.
    
    This analyzer identifies relationships between events from different sources
    to detect complex attack patterns that span multiple cloud environments.
    """
    
    def __init__(self, case_id: str, analysis_output_path: str):
        """
        Initialize the correlation analyzer.
        
        Args:
            case_id: Unique identifier for the forensic case
            analysis_output_path: Path where analysis results will be stored
        """
        super().__init__(case_id, analysis_output_path)
        logger.info(f"Initialized CorrelationAnalyzer for case {case_id}")
    
    def analyze(self, evidence_data: Dict[str, Any], 
               analysis_results: Dict[str, Any] = None,
               correlation_rules: List[Dict[str, Any]] = None,
               *args, **kwargs) -> Dict[str, Any]:
        """
        Analyze evidence data to correlate events across different sources.
        
        Args:
            evidence_data: Dictionary containing evidence data to analyze
            analysis_results: Optional results from other analyzers
            correlation_rules: Optional custom correlation rules
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
            
        Returns:
            Dictionary containing correlation analysis results
        """
        self.start_analysis()
        
        # Set analysis parameters
        parameters = {
            'has_analysis_results': analysis_results is not None,
            'has_custom_rules': correlation_rules is not None
        }
        self.set_parameters(parameters)
        
        try:
            # Load default correlation rules
            rules = self._load_correlation_rules()
            
            # Add custom rules if provided
            if correlation_rules:
                rules.extend(correlation_rules)
            
            # Extract all events with normalized timestamps
            events = self._extract_normalized_events(evidence_data)
            
            # Correlate events by time
            time_correlations = self._correlate_by_time(events)
            
            # Correlate events by entity (user, resource, IP)
            entity_correlations = self._correlate_by_entity(events)
            
            # Correlate events by attack pattern
            pattern_correlations = self._correlate_by_pattern(events, rules)
            
            # Correlate across cloud providers
            cross_cloud_correlations = self._correlate_cross_cloud(events)
            
            # Correlate with analysis results if available
            analysis_correlations = []
            if analysis_results:
                analysis_correlations = self._correlate_with_analysis(events, analysis_results)
            
            # Save results
            time_path = self.save_results(time_correlations, 'time_correlations')
            entity_path = self.save_results(entity_correlations, 'entity_correlations')
            pattern_path = self.save_results(pattern_correlations, 'pattern_correlations')
            cross_cloud_path = self.save_results(cross_cloud_correlations, 'cross_cloud_correlations')
            analysis_path = None
            if analysis_results:
                analysis_path = self.save_results(analysis_correlations, 'analysis_correlations')
            
            # Generate findings
            findings = []
            
            # Add findings for time correlations
            for correlation in time_correlations:
                findings.append({
                    'type': 'time_correlation',
                    'severity': correlation.get('severity', 'medium'),
                    'description': correlation.get('description'),
                    'confidence': correlation.get('confidence', 'medium'),
                    'event_count': correlation.get('event_count', 0),
                    'time_window': correlation.get('time_window')
                })
            
            # Add findings for entity correlations
            for correlation in entity_correlations:
                findings.append({
                    'type': 'entity_correlation',
                    'severity': correlation.get('severity', 'medium'),
                    'description': correlation.get('description'),
                    'confidence': correlation.get('confidence', 'medium'),
                    'entity_type': correlation.get('entity_type'),
                    'entity_value': correlation.get('entity_value'),
                    'event_count': correlation.get('event_count', 0)
                })
            
            # Add findings for pattern correlations
            for correlation in pattern_correlations:
                findings.append({
                    'type': 'pattern_correlation',
                    'severity': correlation.get('severity', 'high'),
                    'description': correlation.get('description'),
                    'confidence': correlation.get('confidence', 'medium'),
                    'pattern_name': correlation.get('pattern_name'),
                    'event_count': correlation.get('event_count', 0),
                    'mitre_techniques': correlation.get('mitre_techniques', [])
                })
            
            # Add findings for cross-cloud correlations
            for correlation in cross_cloud_correlations:
                findings.append({
                    'type': 'cross_cloud_correlation',
                    'severity': correlation.get('severity', 'high'),
                    'description': correlation.get('description'),
                    'confidence': correlation.get('confidence', 'medium'),
                    'cloud_providers': correlation.get('cloud_providers', []),
                    'event_count': correlation.get('event_count', 0)
                })
            
            # Add findings for analysis correlations
            for correlation in analysis_correlations:
                findings.append({
                    'type': 'analysis_correlation',
                    'severity': correlation.get('severity', 'high'),
                    'description': correlation.get('description'),
                    'confidence': correlation.get('confidence', 'high'),
                    'analysis_types': correlation.get('analysis_types', []),
                    'event_count': correlation.get('event_count', 0)
                })
            
            # Generate summary
            total_correlations = (
                len(time_correlations) + 
                len(entity_correlations) + 
                len(pattern_correlations) + 
                len(cross_cloud_correlations) + 
                len(analysis_correlations)
            )
            
            summary = (
                f"Correlation analysis identified {total_correlations} correlations across the evidence. "
                f"Analysis found {len(time_correlations)} time-based correlations, "
                f"{len(entity_correlations)} entity-based correlations, "
                f"{len(pattern_correlations)} pattern-based correlations, "
                f"{len(cross_cloud_correlations)} cross-cloud correlations, and "
                f"{len(analysis_correlations)} correlations with other analysis results."
            )
            
            # Generate report
            results_paths = [time_path, entity_path, pattern_path, cross_cloud_path]
            if analysis_path:
                results_paths.append(analysis_path)
                
            report = self.generate_analysis_report(results_paths, summary, findings)
            
            return {
                'time_correlations': time_correlations,
                'entity_correlations': entity_correlations,
                'pattern_correlations': pattern_correlations,
                'cross_cloud_correlations': cross_cloud_correlations,
                'analysis_correlations': analysis_correlations,
                'findings': findings,
                'summary': summary,
                'report': report
            }
            
        except Exception as e:
            logger.error(f"Error in correlation analysis: {str(e)}")
            raise
            
        finally:
            self.end_analysis()
    
    def _load_correlation_rules(self) -> List[Dict[str, Any]]:
        """
        Load built-in correlation rules.
        
        Returns:
            List of correlation rule dictionaries
        """
        # Define built-in rules for correlating events across different sources
        rules = [
            {
                'name': 'Authentication Followed by Privilege Escalation',
                'description': 'Authentication event followed by privilege escalation within a short time window',
                'severity': 'high',
                'confidence': 'medium',
                'time_window': 1800,  # 30 minutes
                'event_sequence': [
                    {
                        'type': 'authentication',
                        'patterns': [
                            {'evidence_type': 'aws_cloudtrail', 'field': 'eventName', 'value': 'ConsoleLogin'},
                            {'evidence_type': 'azure_activity_log', 'field': 'operationName', 'value': 'Microsoft.AAD/SignIns'},
                            {'evidence_type': 'gcp_audit_log', 'field': 'methodName', 'value': 'google.login.Login.login'}
                        ]
                    },
                    {
                        'type': 'privilege_escalation',
                        'patterns': [
                            {'evidence_type': 'aws_cloudtrail', 'field': 'eventName', 'value': ['AttachUserPolicy', 'AttachRolePolicy', 'PutUserPolicy']},
                            {'evidence_type': 'azure_activity_log', 'field': 'operationName', 'value': 'Microsoft.Authorization/roleAssignments/write'},
                            {'evidence_type': 'gcp_audit_log', 'field': 'methodName', 'value': 'SetIamPolicy'}
                        ]
                    }
                ],
                'mitre_techniques': ['T1078', 'T1098']
            },
            {
                'name': 'Data Access Followed by Data Exfiltration',
                'description': 'Data access event followed by potential data exfiltration within a short time window',
                'severity': 'high',
                'confidence': 'medium',
                'time_window': 3600,  # 60 minutes
                'event_sequence': [
                    {
                        'type': 'data_access',
                        'patterns': [
                            {'evidence_type': 'aws_cloudtrail', 'field': 'eventName', 'value': ['GetObject', 'SelectObjectContent']},
                            {'evidence_type': 'azure_activity_log', 'field': 'operationName', 'value': 'Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read'},
                            {'evidence_type': 'gcp_audit_log', 'field': 'methodName', 'value': 'storage.objects.get'}
                        ]
                    },
                    {
                        'type': 'data_transfer',
                        'patterns': [
                            {'evidence_type': 'aws_vpc_flow', 'field': 'bytes', 'value': {'type': 'threshold', 'threshold': 10000000}},
                            {'evidence_type': 'azure_nsg_flow', 'field': 'dataBytes', 'value': {'type': 'threshold', 'threshold': 10000000}},
                            {'evidence_type': 'gcp_vpc_flow', 'field': 'bytes_sent', 'value': {'type': 'threshold', 'threshold': 10000000}}
                        ]
                    }
                ],
                'mitre_techniques': ['T1530', 'T1048']
            },
            {
                'name': 'Security Control Modification Followed by Suspicious Activity',
                'description': 'Security control modification followed by suspicious activity within a short time window',
                'severity': 'high',
                'confidence': 'high',
                'time_window': 7200,  # 120 minutes
                'event_sequence': [
                    {
                        'type': 'security_control_modification',
                        'patterns': [
                            {'evidence_type': 'aws_cloudtrail', 'field': 'eventName', 'value': ['StopLogging', 'DeleteTrail', 'UpdateTrail']},
                            {'evidence_type': 'azure_activity_log', 'field': 'operationName', 'value': 'Microsoft.Insights/diagnosticSettings/delete'},
                            {'evidence_type': 'gcp_audit_log', 'field': 'methodName', 'value': 'DeleteSink'}
                        ]
                    },
                    {
                        'type': 'suspicious_activity',
                        'patterns': [
                            {'evidence_type': 'aws_guardduty', 'field': 'severity', 'value': {'type': 'threshold', 'threshold': 5}},
                            {'evidence_type': 'azure_security_alert', 'field': 'alertSeverity', 'value': ['High', 'Medium']},
                            {'evidence_type': 'gcp_security_center', 'field': 'severity', 'value': ['HIGH', 'MEDIUM']}
                        ]
                    }
                ],
                'mitre_techniques': ['T1562', 'T1089']
            },
            {
                'name': 'Cross-Cloud Attack Pattern',
                'description': 'Related suspicious activities detected across multiple cloud providers',
                'severity': 'high',
                'confidence': 'medium',
                'time_window': 14400,  # 240 minutes
                'event_providers': ['aws', 'azure', 'gcp'],
                'min_providers': 2,
                'event_types': ['authentication', 'privilege_escalation', 'data_access'],
                'mitre_techniques': ['T1078', 'T1098', 'T1530']
            }
        ]
        
        return rules
    
    def _extract_normalized_events(self, evidence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract events with normalized timestamps and metadata.
        
        Args:
            evidence_data: Dictionary containing evidence data
            
        Returns:
            List of normalized event dictionaries
        """
        normalized_events = []
        
        # Process each evidence type
        for evidence_type, evidence_items in evidence_data.items():
            if not isinstance(evidence_items, list):
                continue
            
            for item in evidence_items:
                if not isinstance(item, dict):
                    continue
                
                # Extract common fields based on evidence type
                timestamp = None
                user = None
                resource = None
                action = None
                source_ip = None
                cloud_provider = None
                event_type = None
                
                # AWS CloudTrail
                if 'aws_cloudtrail' in evidence_type:
                    timestamp = item.get('eventTime')
                    user = item.get('userIdentity', {}).get('arn')
                    resource = item.get('resources', [{}])[0].get('ARN') if item.get('resources') else None
                    action = item.get('eventName')
                    source_ip = item.get('sourceIPAddress')
                    cloud_provider = 'aws'
                    
                    # Determine event type
                    if 'ConsoleLogin' in str(action):
                        event_type = 'authentication'
                    elif any(x in str(action) for x in ['Policy', 'Role', 'User', 'Group']):
                        event_type = 'privilege_escalation'
                    elif any(x in str(action) for x in ['Get', 'List', 'Describe']):
                        event_type = 'data_access'
                    elif any(x in str(action) for x in ['Create', 'Update', 'Put']):
                        event_type = 'resource_modification'
                    elif any(x in str(action) for x in ['Delete', 'Remove']):
                        event_type = 'resource_deletion'
                    elif any(x in str(action) for x in ['Trail', 'Logging', 'Config']):
                        event_type = 'security_control_modification'
                
                # AWS GuardDuty
                elif 'aws_guardduty' in evidence_type:
                    timestamp = item.get('createdAt')
                    resource = item.get('resource', {}).get('resourceType')
                    action = item.get('type')
                    source_ip = item.get('service', {}).get('action', {}).get('networkConnectionAction', {}).get('remoteIpDetails', {}).get('ipAddressV4')
                    cloud_provider = 'aws'
                    event_type = 'security_alert'
                
                # AWS VPC Flow Logs
                elif 'aws_vpc_flow' in evidence_type:
                    timestamp = item.get('start')
                    source_ip = item.get('srcAddr')
                    resource = item.get('dstAddr')
                    action = f"{item.get('srcPort')}->{item.get('dstPort')}"
                    cloud_provider = 'aws'
                    event_type = 'network_flow'
                
                # Azure Activity Log
                elif 'azure_activity_log' in evidence_type:
                    timestamp = item.get('eventTimestamp')
                    user = item.get('caller')
                    resource = item.get('resourceId')
                    action = item.get('operationName')
                    source_ip = item.get('callerIpAddress')
                    cloud_provider = 'azure'
                    
                    # Determine event type
                    if 'Microsoft.AAD/SignIns' in str(action):
                        event_type = 'authentication'
                    elif 'Microsoft.Authorization/roleAssignments' in str(action):
                        event_type = 'privilege_escalation'
                    elif any(x in str(action) for x in ['/read', '/get']):
                        event_type = 'data_access'
                    elif any(x in str(action) for x in ['/write', '/create', '/update']):
                        event_type = 'resource_modification'
                    elif any(x in str(action) for x in ['/delete']):
                        event_type = 'resource_deletion'
                    elif any(x in str(action) for x in ['diagnosticSettings', 'activityLogAlerts']):
                        event_type = 'security_control_modification'
                
                # Azure Security Alerts
                elif 'azure_security_alert' in evidence_type:
                    timestamp = item.get('alertTimeStamp')
                    resource = item.get('compromisedEntity')
                    action = item.get('alertType')
                    cloud_provider = 'azure'
                    event_type = 'security_alert'
                
                # Azure NSG Flow Logs
                elif 'azure_nsg_flow' in evidence_type:
                    timestamp = item.get('startTime')
                    source_ip = item.get('sourceAddress')
                    resource = item.get('destinationAddress')
                    action = f"{item.get('sourcePort')}->{item.get('destinationPort')}"
                    cloud_provider = 'azure'
                    event_type = 'network_flow'
                
                # GCP Audit Log
                elif 'gcp_audit_log' in evidence_type:
                    timestamp = item.get('timestamp')
                    user = item.get('protoPayload', {}).get('authenticationInfo', {}).get('principalEmail')
                    resource = item.get('resource', {}).get('type')
                    action = item.get('protoPayload', {}).get('methodName')
                    source_ip = item.get('protoPayload', {}).get('requestMetadata', {}).get('callerIp')
                    cloud_provider = 'gcp'
                    
                    # Determine event type
                    if 'login' in str(action).lower():
                        event_type = 'authentication'
                    elif 'SetIamPolicy' in str(action):
                        event_type = 'privilege_escalation'
                    elif any(x in str(action).lower() for x in ['get', 'list', 'read']):
                        event_type = 'data_access'
                    elif any(x in str(action).lower() for x in ['create', 'update', 'insert']):
                        event_type = 'resource_modification'
                    elif any(x in str(action).lower() for x in ['delete']):
                        event_type = 'resource_deletion'
                    elif any(x in str(action).lower() for x in ['sink', 'logging']):
                        event_type = 'security_control_modification'
                
                # GCP Security Center
                elif 'gcp_security_center' in evidence_type:
                    timestamp = item.get('createTime')
                    resource = item.get('resourceName')
                    action = item.get('category')
                    cloud_provider = 'gcp'
                    event_type = 'security_alert'
                
                # GCP VPC Flow Logs
                elif 'gcp_vpc_flow' in evidence_type:
                    timestamp = item.get('start_time')
                    source_ip = item.get('connection', {}).get('src_ip')
                    resource = item.get('connection', {}).get('dest_ip')
                    action = f"{item.get('connection', {}).get('src_port')}->{item.get('connection', {}).get('dest_port')}"
                    cloud_provider = 'gcp'
                    event_type = 'network_flow'
                
                # Office 365 Audit
                elif 'office365_audit' in evidence_type:
                    timestamp = item.get('CreationTime')
                    user = item.get('UserId')
                    resource = item.get('ObjectId')
                    action = item.get('Operation')
                    source_ip = item.get('ClientIP')
                    cloud_provider = 'office365'
                    
                    # Determine event type
                    if 'Login' in str(action):
                        event_type = 'authentication'
                    elif any(x in str(action) for x in ['Add', 'Update', 'Modify']):
                        event_type = 'resource_modification'
                    elif any(x in str(action) for x in ['Delete', 'Remove']):
                        event_type = 'resource_deletion'
                    elif any(x in str(action) for x in ['FileAccessed', 'FileDownloaded']):
                        event_type = 'data_access'
                
                # Skip if missing essential information
                if not timestamp:
                    continue
                
                try:
                    # Normalize timestamp
                    normalized_time = analysis_utils.normalize_timestamp(timestamp)
                    
                    # Create normalized event
                    normalized_event = {
                        'timestamp': normalized_time,
                        'timestamp_str': normalized_time.isoformat(),
                        'user': user,
                        'resource': resource,
                        'action': action,
                        'source_ip': source_ip,
                        'cloud_provider': cloud_provider,
                        'event_type': event_type,
                        'evidence_type': evidence_type,
                        'raw_event': item
                    }
                    
                    normalized_events.append(normalized_event)
                    
                except (ValueError, TypeError) as e:
                    logger.warning(f"Could not normalize timestamp '{timestamp}': {str(e)}")
        
        # Sort events by timestamp
        normalized_events.sort(key=lambda e: e['timestamp'])
        
        return normalized_events
    
    def _correlate_by_time(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate events based on temporal proximity.
        
        Args:
            events: List of normalized event dictionaries
            
        Returns:
            List of time correlation dictionaries
        """
        correlations = []
        
        if len(events) < 2:
            return correlations
        
        # Define time windows for correlation (in seconds)
        time_windows = [60, 300, 900, 1800, 3600]  # 1min, 5min, 15min, 30min, 60min
        
        for window in time_windows:
            # Sliding window approach
            for i in range(len(events)):
                window_events = []
                start_time = events[i]['timestamp']
                end_time = start_time + datetime.timedelta(seconds=window)
                
                # Collect events within the time window
                for j in range(i, len(events)):
                    if events[j]['timestamp'] <= end_time:
                        window_events.append(events[j])
                    else:
                        break
                
                # Skip if not enough events in the window
                if len(window_events) < 3:
                    continue
                
                # Check for interesting event type combinations
                event_types = set(event.get('event_type') for event in window_events if event.get('event_type'))
                
                # Skip if not enough different event types
                if len(event_types) < 2:
                    continue
                
                # Check for interesting combinations
                interesting_combinations = [
                    {'types': ['authentication', 'privilege_escalation'], 'severity': 'high'},
                    {'types': ['authentication', 'data_access'], 'severity': 'medium'},
                    {'types': ['data_access', 'network_flow'], 'severity': 'high'},
                    {'types': ['security_control_modification', 'resource_modification'], 'severity': 'high'},
                    {'types': ['security_control_modification', 'data_access'], 'severity': 'high'},
                    {'types': ['authentication', 'security_alert'], 'severity': 'high'}
                ]
                
                for combo in interesting_combinations:
                    if all(t in event_types for t in combo['types']):
                        # Get events of the specified types
                        combo_events = [e for e in window_events if e.get('event_type') in combo['types']]
                        
                        # Create correlation
                        correlation = {
                            'correlation_type': 'time_window',
                            'description': f"Correlated events of types {', '.join(combo['types'])} within {window} seconds",
                            'time_window': {
                                'start': start_time.isoformat(),
                                'end': end_time.isoformat(),
                                'duration_seconds': window
                            },
                            'event_types': list(combo['types']),
                            'event_count': len(combo_events),
                            'events': combo_events,
                            'severity': combo['severity'],
                            'confidence': 'medium'
                        }
                        
                        correlations.append(correlation)
                        
                        # No need to check other combinations for this window
                        break
        
        return correlations
    
    def _correlate_by_entity(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate events based on common entities (user, resource, IP).
        
        Args:
            events: List of normalized event dictionaries
            
        Returns:
            List of entity correlation dictionaries
        """
        correlations = []
        
        # Group events by user
        user_events = {}
        for event in events:
            user = event.get('user')
            if user:
                if user not in user_events:
                    user_events[user] = []
                user_events[user].append(event)
        
        # Analyze each user's events
        for user, user_event_list in user_events.items():
            # Skip if not enough events
            if len(user_event_list) < 3:
                continue
            
            # Check for interesting event type combinations
            event_types = set(event.get('event_type') for event in user_event_list if event.get('event_type'))
            
            # Check for interesting combinations
            interesting_combinations = [
                {'types': ['authentication', 'privilege_escalation'], 'severity': 'high'},
                {'types': ['authentication', 'data_access', 'network_flow'], 'severity': 'high'},
                {'types': ['security_control_modification', 'data_access'], 'severity': 'high'},
                {'types': ['authentication', 'resource_modification', 'resource_deletion'], 'severity': 'high'}
            ]
            
            for combo in interesting_combinations:
                if all(t in event_types for t in combo['types']):
                    # Get events of the specified types
                    combo_events = [e for e in user_event_list if e.get('event_type') in combo['types']]
                    
                    # Create correlation
                    correlation = {
                        'correlation_type': 'user_activity',
                        'description': f"User {user} performed activities of types {', '.join(combo['types'])}",
                        'entity_type': 'user',
                        'entity_value': user,
                        'event_types': list(combo['types']),
                        'event_count': len(combo_events),
                        'events': combo_events,
                        'severity': combo['severity'],
                        'confidence': 'medium'
                    }
                    
                    correlations.append(correlation)
        
        # Group events by source IP
        ip_events = {}
        for event in events:
            ip = event.get('source_ip')
            if ip:
                if ip not in ip_events:
                    ip_events[ip] = []
                ip_events[ip].append(event)
        
        # Analyze each IP's events
        for ip, ip_event_list in ip_events.items():
            # Skip if not enough events
            if len(ip_event_list) < 3:
                continue
            
            # Check if events are from multiple users
            users = set(event.get('user') for event in ip_event_list if event.get('user'))
            
            if len(users) > 1:
                # Create correlation for multiple users from same IP
                correlation = {
                    'correlation_type': 'ip_activity',
                    'description': f"Multiple users ({len(users)}) accessed from the same IP address {ip}",
                    'entity_type': 'source_ip',
                    'entity_value': ip,
                    'users': list(users),
                    'event_count': len(ip_event_list),
                    'events': ip_event_list,
                    'severity': 'medium',
                    'confidence': 'medium'
                }
                
                correlations.append(correlation)
            
            # Check for interesting event type combinations
            event_types = set(event.get('event_type') for event in ip_event_list if event.get('event_type'))
            
            # Check for interesting combinations
            interesting_combinations = [
                {'types': ['authentication', 'privilege_escalation'], 'severity': 'high'},
                {'types': ['authentication', 'data_access', 'network_flow'], 'severity': 'high'},
                {'types': ['security_control_modification', 'data_access'], 'severity': 'high'}
            ]
            
            for combo in interesting_combinations:
                if all(t in event_types for t in combo['types']):
                    # Get events of the specified types
                    combo_events = [e for e in ip_event_list if e.get('event_type') in combo['types']]
                    
                    # Create correlation
                    correlation = {
                        'correlation_type': 'ip_activity',
                        'description': f"IP address {ip} associated with activities of types {', '.join(combo['types'])}",
                        'entity_type': 'source_ip',
                        'entity_value': ip,
                        'event_types': list(combo['types']),
                        'event_count': len(combo_events),
                        'events': combo_events,
                        'severity': combo['severity'],
                        'confidence': 'medium'
                    }
                    
                    correlations.append(correlation)
        
        # Group events by resource
        resource_events = {}
        for event in events:
            resource = event.get('resource')
            if resource:
                if resource not in resource_events:
                    resource_events[resource] = []
                resource_events[resource].append(event)
        
        # Analyze each resource's events
        for resource, resource_event_list in resource_events.items():
            # Skip if not enough events
            if len(resource_event_list) < 3:
                continue
            
            # Check if events are from multiple users
            users = set(event.get('user') for event in resource_event_list if event.get('user'))
            
            if len(users) > 2:  # More than 2 users
                # Create correlation for multiple users accessing same resource
                correlation = {
                    'correlation_type': 'resource_access',
                    'description': f"Multiple users ({len(users)}) accessed the same resource {resource}",
                    'entity_type': 'resource',
                    'entity_value': resource,
                    'users': list(users),
                    'event_count': len(resource_event_list),
                    'events': resource_event_list,
                    'severity': 'medium',
                    'confidence': 'medium'
                }
                
                correlations.append(correlation)
            
            # Check for interesting event type combinations
            event_types = set(event.get('event_type') for event in resource_event_list if event.get('event_type'))
            
            # Check for interesting combinations
            interesting_combinations = [
                {'types': ['data_access', 'resource_modification'], 'severity': 'medium'},
                {'types': ['data_access', 'resource_deletion'], 'severity': 'high'},
                {'types': ['resource_modification', 'resource_deletion'], 'severity': 'high'}
            ]
            
            for combo in interesting_combinations:
                if all(t in event_types for t in combo['types']):
                    # Get events of the specified types
                    combo_events = [e for e in resource_event_list if e.get('event_type') in combo['types']]
                    
                    # Create correlation
                    correlation = {
                        'correlation_type': 'resource_activity',
                        'description': f"Resource {resource} had activities of types {', '.join(combo['types'])}",
                        'entity_type': 'resource',
                        'entity_value': resource,
                        'event_types': list(combo['types']),
                        'event_count': len(combo_events),
                        'events': combo_events,
                        'severity': combo['severity'],
                        'confidence': 'medium'
                    }
                    
                    correlations.append(correlation)
        
        return correlations
    
    def _correlate_by_pattern(self, events: List[Dict[str, Any]], 
                            rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate events based on predefined attack patterns.
        
        Args:
            events: List of normalized event dictionaries
            rules: List of correlation rule dictionaries
            
        Returns:
            List of pattern correlation dictionaries
        """
        correlations = []
        
        # Apply each rule
        for rule in rules:
            # Skip rules without event sequence
            if 'event_sequence' not in rule:
                continue
            
            # Get rule parameters
            name = rule.get('name', 'Unnamed Pattern')
            description = rule.get('description', '')
            severity = rule.get('severity', 'medium')
            confidence = rule.get('confidence', 'medium')
            time_window = rule.get('time_window', 3600)  # Default: 1 hour
            event_sequence = rule.get('event_sequence', [])
            mitre_techniques = rule.get('mitre_techniques', [])
            
            # Skip if sequence is empty
            if not event_sequence:
                continue
            
            # Find matching event sequences
            matches = self._find_event_sequences(events, event_sequence, time_window)
            
            if matches:
                # Create correlation for each match
                for match in matches:
                    correlation = {
                        'correlation_type': 'attack_pattern',
                        'pattern_name': name,
                        'description': description,
                        'severity': severity,
                        'confidence': confidence,
                        'time_window_seconds': time_window,
                        'event_count': len(match),
                        'events': match,
                        'mitre_techniques': mitre_techniques
                    }
                    
                    correlations.append(correlation)
        
        return correlations
    
    def _find_event_sequences(self, events: List[Dict[str, Any]], 
                            event_sequence: List[Dict[str, Any]], 
                            time_window: int) -> List[List[Dict[str, Any]]]:
        """
        Find sequences of events that match a pattern.
        
        Args:
            events: List of normalized event dictionaries
            event_sequence: List of event pattern dictionaries
            time_window: Maximum time window in seconds
            
        Returns:
            List of matching event sequences
        """
        matches = []
        
        # Skip if not enough events
        if len(events) < len(event_sequence):
            return matches
        
        # Try each event as a starting point
        for i in range(len(events) - len(event_sequence) + 1):
            start_event = events[i]
            start_time = start_event['timestamp']
            end_time = start_time + datetime.timedelta(seconds=time_window)
            
            # Check if this event matches the first pattern
            if not self._event_matches_pattern(start_event, event_sequence[0]):
                continue
            
            # Try to find matching events for the rest of the sequence
            current_match = [start_event]
            current_index = i + 1
            
            for pattern_index in range(1, len(event_sequence)):
                pattern = event_sequence[pattern_index]
                match_found = False
                
                # Look for a matching event within the time window
                while current_index < len(events) and events[current_index]['timestamp'] <= end_time:
                    if self._event_matches_pattern(events[current_index], pattern):
                        current_match.append(events[current_index])
                        current_index += 1
                        match_found = True
                        break
                    
                    current_index += 1
                
                if not match_found:
                    # No match for this pattern, break and try next starting point
                    break
            
            # Check if we found a complete match
            if len(current_match) == len(event_sequence):
                matches.append(current_match)
        
        return matches
    
    def _event_matches_pattern(self, event: Dict[str, Any], pattern: Dict[str, Any]) -> bool:
        """
        Check if an event matches a pattern.
        
        Args:
            event: Normalized event dictionary
            pattern: Event pattern dictionary
            
        Returns:
            True if event matches pattern, False otherwise
        """
        # Check event type
        if 'type' in pattern and event.get('event_type') != pattern['type']:
            return False
        
        # Check specific patterns
        for specific_pattern in pattern.get('patterns', []):
            evidence_type = specific_pattern.get('evidence_type')
            field = specific_pattern.get('field')
            expected_value = specific_pattern.get('value')
            
            # Skip if missing required fields
            if not evidence_type or not field or expected_value is None:
                continue
            
            # Check evidence type
            if evidence_type not in event.get('evidence_type', ''):
                continue
            
            # Get actual value from raw event
            raw_event = event.get('raw_event', {})
            actual_value = self._get_nested_field(raw_event, field)
            
            # Check value
            if isinstance(expected_value, dict) and 'type' in expected_value:
                # Special matching types
                if expected_value['type'] == 'threshold':
                    threshold = expected_value.get('threshold')
                    if threshold is None or not isinstance(actual_value, (int, float)):
                        continue
                    
                    if float(actual_value) < float(threshold):
                        continue
            
            elif isinstance(expected_value, list):
                # Match any value in the list
                if actual_value not in expected_value:
                    continue
            
            else:
                # Direct value comparison
                if actual_value != expected_value:
                    continue
            
            # If we get here, the pattern matched
            return True
        
        # If no specific patterns or none matched
        return False
    
    def _get_nested_field(self, item: Dict[str, Any], field: str) -> Any:
        """
        Get a nested field value using dot notation.
        
        Args:
            item: Dictionary to extract field from
            field: Field name in dot notation
            
        Returns:
            Field value or None if not found
        """
        if '.' in field:
            parts = field.split('.')
            current = item
            
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None
            
            return current
        else:
            return item.get(field)
    
    def _correlate_cross_cloud(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Correlate events across different cloud providers.
        
        Args:
            events: List of normalized event dictionaries
            
        Returns:
            List of cross-cloud correlation dictionaries
        """
        correlations = []
        
        # Group events by user
        user_events = {}
        for event in events:
            user = event.get('user')
            if user:
                if user not in user_events:
                    user_events[user] = []
                user_events[user].append(event)
        
        # Analyze each user's events
        for user, user_event_list in user_events.items():
            # Skip if not enough events
            if len(user_event_list) < 3:
                continue
            
            # Check if events are from multiple cloud providers
            providers = set(event.get('cloud_provider') for event in user_event_list if event.get('cloud_provider'))
            
            if len(providers) > 1:
                # Group events by provider
                provider_events = {}
                for event in user_event_list:
                    provider = event.get('cloud_provider')
                    if provider:
                        if provider not in provider_events:
                            provider_events[provider] = []
                        provider_events[provider].append(event)
                
                # Check for similar event types across providers
                event_types_by_provider = {}
                for provider, provider_event_list in provider_events.items():
                    event_types_by_provider[provider] = set(event.get('event_type') for event in provider_event_list if event.get('event_type'))
                
                # Find common event types
                common_types = set()
                for provider, types in event_types_by_provider.items():
                    if not common_types:
                        common_types = types
                    else:
                        common_types &= types
                
                if common_types:
                    # Create correlation for similar activities across providers
                    correlation = {
                        'correlation_type': 'cross_cloud_activity',
                        'description': f"User {user} performed similar activities across multiple cloud providers: {', '.join(providers)}",
                        'user': user,
                        'cloud_providers': list(providers),
                        'common_event_types': list(common_types),
                        'event_count': len(user_event_list),
                        'events': user_event_list,
                        'severity': 'high',
                        'confidence': 'medium'
                    }
                    
                    correlations.append(correlation)
        
        # Group events by source IP
        ip_events = {}
        for event in events:
            ip = event.get('source_ip')
            if ip:
                if ip not in ip_events:
                    ip_events[ip] = []
                ip_events[ip].append(event)
        
        # Analyze each IP's events
        for ip, ip_event_list in ip_events.items():
            # Skip if not enough events
            if len(ip_event_list) < 3:
                continue
            
            # Check if events are from multiple cloud providers
            providers = set(event.get('cloud_provider') for event in ip_event_list if event.get('cloud_provider'))
            
            if len(providers) > 1:
                # Create correlation for activity across providers from same IP
                correlation = {
                    'correlation_type': 'cross_cloud_ip',
                    'description': f"IP address {ip} accessed multiple cloud providers: {', '.join(providers)}",
                    'source_ip': ip,
                    'cloud_providers': list(providers),
                    'event_count': len(ip_event_list),
                    'events': ip_event_list,
                    'severity': 'medium',
                    'confidence': 'medium'
                }
                
                correlations.append(correlation)
        
        return correlations
    
    def _correlate_with_analysis(self, events: List[Dict[str, Any]], 
                               analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Correlate events with results from other analyzers.
        
        Args:
            events: List of normalized event dictionaries
            analysis_results: Dictionary containing results from other analyzers
            
        Returns:
            List of analysis correlation dictionaries
        """
        correlations = []
        
        # Extract findings from analysis results
        findings = []
        
        for analysis_type, result in analysis_results.items():
            if isinstance(result, dict) and 'findings' in result:
                for finding in result['findings']:
                    finding['analysis_type'] = analysis_type
                    findings.append(finding)
        
        # Skip if no findings
        if not findings:
            return correlations
        
        # Group findings by type
        findings_by_type = {}
        for finding in findings:
            finding_type = finding.get('type')
            if finding_type:
                if finding_type not in findings_by_type:
                    findings_by_type[finding_type] = []
                findings_by_type[finding_type].append(finding)
        
        # Correlate findings of different types
        interesting_combinations = [
            {'types': ['statistical_anomaly', 'pattern_match'], 'severity': 'high'},
            {'types': ['temporal_anomaly', 'behavioral_anomaly'], 'severity': 'high'},
            {'types': ['access_anomaly', 'pattern_match'], 'severity': 'high'},
            {'types': ['network_anomaly', 'pattern_match'], 'severity': 'high'},
            {'types': ['time_correlation', 'pattern_match'], 'severity': 'high'},
            {'types': ['entity_correlation', 'behavioral_anomaly'], 'severity': 'high'}
        ]
        
        for combo in interesting_combinations:
            if all(t in findings_by_type for t in combo['types']):
                # Get findings of the specified types
                combo_findings = []
                for t in combo['types']:
                    combo_findings.extend(findings_by_type[t])
                
                # Create correlation
                correlation = {
                    'correlation_type': 'analysis_correlation',
                    'description': f"Correlated findings of types {', '.join(combo['types'])}",
                    'analysis_types': list(set(finding.get('analysis_type') for finding in combo_findings if finding.get('analysis_type'))),
                    'finding_types': combo['types'],
                    'finding_count': len(combo_findings),
                    'findings': combo_findings,
                    'severity': combo['severity'],
                    'confidence': 'high'
                }
                
                correlations.append(correlation)
        
        # Correlate findings with events
        for finding in findings:
            finding_type = finding.get('type')
            severity = finding.get('severity')
            
            if finding_type in ['pattern_match', 'attack_chain'] and severity == 'high':
                # Find related events
                related_events = []
                
                # Extract entities from finding
                entities = set()
                
                if 'affected_accounts' in finding:
                    entities.update(finding.get('affected_accounts', []))
                
                if 'affected_resources' in finding:
                    entities.update(finding.get('affected_resources', []))
                
                if 'source_ips' in finding:
                    entities.update(finding.get('source_ips', []))
                
                # Find events related to these entities
                for event in events:
                    if (event.get('user') in entities or 
                        event.get('resource') in entities or 
                        event.get('source_ip') in entities):
                        related_events.append(event)
                
                if related_events:
                    # Create correlation
                    correlation = {
                        'correlation_type': 'finding_event_correlation',
                        'description': f"Correlated high-severity {finding_type} finding with related events",
                        'finding': finding,
                        'event_count': len(related_events),
                        'events': related_events,
                        'severity': 'high',
                        'confidence': 'high'
                    }
                    
                    correlations.append(correlation)
        
        return correlations
