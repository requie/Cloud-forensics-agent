"""
Pattern detection module for the Cloud Forensics AI Agent.

This module provides functionality for detecting patterns and signatures
in cloud forensic evidence that may indicate security incidents or attacks.
"""

import datetime
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from ..core.base_analyzer import BaseAnalyzer
from ..utils import analysis_utils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PatternDetector(BaseAnalyzer):
    """
    Analyzer for detecting patterns and signatures in cloud forensic evidence.
    
    This analyzer processes various types of cloud logs and events to identify
    patterns that may indicate security incidents, attacks, or other suspicious activity.
    """
    
    def __init__(self, case_id: str, analysis_output_path: str):
        """
        Initialize the pattern detector.
        
        Args:
            case_id: Unique identifier for the forensic case
            analysis_output_path: Path where analysis results will be stored
        """
        super().__init__(case_id, analysis_output_path)
        
        # Initialize pattern signatures
        self.attack_signatures = self._load_attack_signatures()
        
        logger.info(f"Initialized PatternDetector for case {case_id}")
    
    def analyze(self, evidence_data: Dict[str, Any], 
               custom_signatures: List[Dict[str, Any]] = None,
               *args, **kwargs) -> Dict[str, Any]:
        """
        Analyze evidence data to detect patterns and signatures.
        
        Args:
            evidence_data: Dictionary containing evidence data to analyze
            custom_signatures: Optional list of custom pattern signatures
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
            
        Returns:
            Dictionary containing pattern detection results
        """
        self.start_analysis()
        
        # Set analysis parameters
        parameters = {
            'custom_signatures': custom_signatures
        }
        self.set_parameters(parameters)
        
        try:
            # Combine default and custom signatures
            signatures = self.attack_signatures.copy()
            if custom_signatures:
                signatures.extend(custom_signatures)
            
            # Detect patterns in evidence data
            detected_patterns = []
            
            # Process each evidence type
            for evidence_type, evidence_items in evidence_data.items():
                if not isinstance(evidence_items, list):
                    # Skip non-list evidence items
                    continue
                
                # Apply each signature to the evidence
                for signature in signatures:
                    if self._is_signature_applicable(signature, evidence_type):
                        matches = self._apply_signature(signature, evidence_items, evidence_type)
                        if matches:
                            detected_patterns.append({
                                'signature': signature,
                                'evidence_type': evidence_type,
                                'matches': matches,
                                'match_count': len(matches)
                            })
            
            # Detect multi-stage attack patterns
            attack_chains = self._detect_attack_chains(detected_patterns)
            
            # Detect credential usage patterns
            credential_patterns = self._detect_credential_patterns(evidence_data)
            
            # Detect data exfiltration patterns
            exfiltration_patterns = self._detect_data_exfiltration(evidence_data)
            
            # Detect privilege escalation patterns
            privilege_patterns = self._detect_privilege_escalation(evidence_data)
            
            # Save results
            patterns_path = self.save_results(detected_patterns, 'detected_patterns')
            chains_path = self.save_results(attack_chains, 'attack_chains')
            credential_path = self.save_results(credential_patterns, 'credential_patterns')
            exfiltration_path = self.save_results(exfiltration_patterns, 'exfiltration_patterns')
            privilege_path = self.save_results(privilege_patterns, 'privilege_patterns')
            
            # Generate findings
            findings = []
            
            # Add findings for detected patterns
            for pattern in detected_patterns:
                signature = pattern.get('signature', {})
                findings.append({
                    'type': 'pattern_match',
                    'pattern_name': signature.get('name'),
                    'severity': signature.get('severity', 'medium'),
                    'description': signature.get('description'),
                    'evidence_type': pattern.get('evidence_type'),
                    'match_count': pattern.get('match_count', 0),
                    'confidence': signature.get('confidence', 'medium'),
                    'mitre_technique': signature.get('mitre_technique')
                })
            
            # Add findings for attack chains
            for chain in attack_chains:
                findings.append({
                    'type': 'attack_chain',
                    'chain_name': chain.get('name'),
                    'severity': 'high',
                    'description': chain.get('description'),
                    'stages': chain.get('stages', []),
                    'confidence': chain.get('confidence', 'medium'),
                    'mitre_tactics': chain.get('mitre_tactics', [])
                })
            
            # Add findings for credential patterns
            for pattern in credential_patterns:
                findings.append({
                    'type': 'credential_abuse',
                    'severity': pattern.get('severity', 'high'),
                    'description': pattern.get('description'),
                    'affected_accounts': pattern.get('affected_accounts', []),
                    'confidence': pattern.get('confidence', 'medium')
                })
            
            # Add findings for exfiltration patterns
            for pattern in exfiltration_patterns:
                findings.append({
                    'type': 'data_exfiltration',
                    'severity': 'high',
                    'description': pattern.get('description'),
                    'data_sources': pattern.get('data_sources', []),
                    'volume': pattern.get('volume'),
                    'confidence': pattern.get('confidence', 'medium')
                })
            
            # Add findings for privilege escalation
            for pattern in privilege_patterns:
                findings.append({
                    'type': 'privilege_escalation',
                    'severity': 'high',
                    'description': pattern.get('description'),
                    'affected_resources': pattern.get('affected_resources', []),
                    'confidence': pattern.get('confidence', 'medium')
                })
            
            # Generate summary
            pattern_count = len(detected_patterns)
            chain_count = len(attack_chains)
            
            summary = (
                f"Pattern analysis detected {pattern_count} pattern matches across the evidence. "
                f"Analysis identified {chain_count} potential attack chains, "
                f"{len(credential_patterns)} credential abuse patterns, "
                f"{len(exfiltration_patterns)} potential data exfiltration patterns, and "
                f"{len(privilege_patterns)} privilege escalation patterns."
            )
            
            # Generate report
            results_paths = [patterns_path, chains_path, credential_path, exfiltration_path, privilege_path]
            report = self.generate_analysis_report(results_paths, summary, findings)
            
            return {
                'detected_patterns': detected_patterns,
                'attack_chains': attack_chains,
                'credential_patterns': credential_patterns,
                'exfiltration_patterns': exfiltration_patterns,
                'privilege_patterns': privilege_patterns,
                'findings': findings,
                'summary': summary,
                'report': report
            }
            
        except Exception as e:
            logger.error(f"Error in pattern detection: {str(e)}")
            raise
            
        finally:
            self.end_analysis()
    
    def _load_attack_signatures(self) -> List[Dict[str, Any]]:
        """
        Load built-in attack signatures.
        
        Returns:
            List of attack signature dictionaries
        """
        # Define built-in signatures for common cloud attack patterns
        signatures = [
            # AWS-specific signatures
            {
                'name': 'AWS Console Login Without MFA',
                'description': 'AWS Console login without multi-factor authentication',
                'applicable_to': ['aws_cloudtrail'],
                'severity': 'medium',
                'confidence': 'high',
                'detection_criteria': {
                    'eventName': 'ConsoleLogin',
                    'additionalEventData.MFAUsed': 'No'
                },
                'mitre_technique': 'T1078'
            },
            {
                'name': 'AWS Root Account Usage',
                'description': 'Use of the AWS root account',
                'applicable_to': ['aws_cloudtrail'],
                'severity': 'high',
                'confidence': 'high',
                'detection_criteria': {
                    'userIdentity.type': 'Root'
                },
                'mitre_technique': 'T1078.004'
            },
            {
                'name': 'AWS IAM Policy Change',
                'description': 'Modification of IAM policies',
                'applicable_to': ['aws_cloudtrail'],
                'severity': 'medium',
                'confidence': 'medium',
                'detection_criteria': {
                    'eventName': ['CreatePolicy', 'DeletePolicy', 'CreatePolicyVersion', 'DeletePolicyVersion', 'AttachRolePolicy', 'DetachRolePolicy']
                },
                'mitre_technique': 'T1098'
            },
            {
                'name': 'AWS Security Group Modification',
                'description': 'Modification of security groups',
                'applicable_to': ['aws_cloudtrail'],
                'severity': 'medium',
                'confidence': 'medium',
                'detection_criteria': {
                    'eventName': ['AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress', 'RevokeSecurityGroupIngress', 'RevokeSecurityGroupEgress', 'CreateSecurityGroup', 'DeleteSecurityGroup']
                },
                'mitre_technique': 'T1562.007'
            },
            {
                'name': 'AWS CloudTrail Changes',
                'description': 'Modification of CloudTrail logging configuration',
                'applicable_to': ['aws_cloudtrail'],
                'severity': 'high',
                'confidence': 'high',
                'detection_criteria': {
                    'eventName': ['StartLogging', 'StopLogging', 'UpdateTrail', 'DeleteTrail', 'CreateTrail', 'RemoveTags', 'AddTags']
                },
                'mitre_technique': 'T1562.008'
            },
            
            # Azure-specific signatures
            {
                'name': 'Azure Role Assignment Change',
                'description': 'Modification of Azure role assignments',
                'applicable_to': ['azure_activity_log'],
                'severity': 'medium',
                'confidence': 'medium',
                'detection_criteria': {
                    'operationName': ['Microsoft.Authorization/roleAssignments/write', 'Microsoft.Authorization/roleAssignments/delete']
                },
                'mitre_technique': 'T1098'
            },
            {
                'name': 'Azure Network Security Group Modification',
                'description': 'Modification of Azure Network Security Groups',
                'applicable_to': ['azure_activity_log'],
                'severity': 'medium',
                'confidence': 'medium',
                'detection_criteria': {
                    'operationName': ['Microsoft.Network/networkSecurityGroups/write', 'Microsoft.Network/networkSecurityGroups/delete', 'Microsoft.Network/networkSecurityGroups/securityRules/write', 'Microsoft.Network/networkSecurityGroups/securityRules/delete']
                },
                'mitre_technique': 'T1562.007'
            },
            {
                'name': 'Azure Diagnostic Settings Change',
                'description': 'Modification of Azure diagnostic settings',
                'applicable_to': ['azure_activity_log'],
                'severity': 'high',
                'confidence': 'high',
                'detection_criteria': {
                    'operationName': ['Microsoft.Insights/diagnosticSettings/write', 'Microsoft.Insights/diagnosticSettings/delete']
                },
                'mitre_technique': 'T1562.008'
            },
            
            # GCP-specific signatures
            {
                'name': 'GCP IAM Policy Change',
                'description': 'Modification of GCP IAM policies',
                'applicable_to': ['gcp_audit_log'],
                'severity': 'medium',
                'confidence': 'medium',
                'detection_criteria': {
                    'methodName': ['SetIamPolicy']
                },
                'mitre_technique': 'T1098'
            },
            {
                'name': 'GCP Firewall Rule Modification',
                'description': 'Modification of GCP firewall rules',
                'applicable_to': ['gcp_audit_log'],
                'severity': 'medium',
                'confidence': 'medium',
                'detection_criteria': {
                    'methodName': ['compute.firewalls.insert', 'compute.firewalls.patch', 'compute.firewalls.update', 'compute.firewalls.delete']
                },
                'mitre_technique': 'T1562.007'
            },
            {
                'name': 'GCP Logging Configuration Change',
                'description': 'Modification of GCP logging configuration',
                'applicable_to': ['gcp_audit_log'],
                'severity': 'high',
                'confidence': 'high',
                'detection_criteria': {
                    'methodName': ['UpdateSink', 'DeleteSink', 'CreateSink']
                },
                'mitre_technique': 'T1562.008'
            },
            
            # Generic cloud signatures
            {
                'name': 'Suspicious API Calls',
                'description': 'Suspicious API calls that may indicate reconnaissance or exploitation',
                'applicable_to': ['aws_cloudtrail', 'azure_activity_log', 'gcp_audit_log'],
                'severity': 'high',
                'confidence': 'medium',
                'detection_criteria': {
                    'errorCode': ['AccessDenied', 'UnauthorizedOperation', 'Forbidden', 'PermissionDenied']
                },
                'mitre_technique': 'T1078'
            },
            {
                'name': 'Multiple Failed Logins',
                'description': 'Multiple failed login attempts',
                'applicable_to': ['aws_cloudtrail', 'azure_activity_log', 'gcp_audit_log', 'office365_audit', 'gsuite_admin'],
                'severity': 'medium',
                'confidence': 'medium',
                'detection_criteria': {
                    'eventName': ['ConsoleLogin'],
                    'errorMessage': ['Failed authentication']
                },
                'threshold': 5,
                'mitre_technique': 'T1110'
            },
            {
                'name': 'Data Access from Unusual Location',
                'description': 'Data access from an unusual geographic location',
                'applicable_to': ['aws_cloudtrail', 'azure_activity_log', 'gcp_audit_log', 'office365_audit', 'gsuite_admin'],
                'severity': 'high',
                'confidence': 'medium',
                'detection_criteria': {
                    'sourceIPAddress': {'type': 'geo_unusual'}
                },
                'mitre_technique': 'T1078'
            }
        ]
        
        return signatures
    
    def _is_signature_applicable(self, signature: Dict[str, Any], evidence_type: str) -> bool:
        """
        Check if a signature is applicable to a specific evidence type.
        
        Args:
            signature: Signature dictionary
            evidence_type: Type of evidence
            
        Returns:
            True if signature is applicable, False otherwise
        """
        applicable_to = signature.get('applicable_to', [])
        
        if not applicable_to:
            return True
        
        for applicable_type in applicable_to:
            if applicable_type in evidence_type:
                return True
        
        return False
    
    def _apply_signature(self, signature: Dict[str, Any], evidence_items: List[Dict[str, Any]], 
                       evidence_type: str) -> List[Dict[str, Any]]:
        """
        Apply a signature to evidence items.
        
        Args:
            signature: Signature dictionary
            evidence_items: List of evidence items
            evidence_type: Type of evidence
            
        Returns:
            List of matching evidence items
        """
        matches = []
        detection_criteria = signature.get('detection_criteria', {})
        
        if not detection_criteria:
            return matches
        
        # Track occurrences for threshold-based signatures
        occurrences = {}
        threshold = signature.get('threshold', 1)
        
        for item in evidence_items:
            if not isinstance(item, dict):
                continue
            
            # Check if item matches all criteria
            is_match = True
            
            for field, expected_value in detection_criteria.items():
                # Handle nested fields using dot notation
                actual_value = self._get_nested_field(item, field)
                
                if actual_value is None:
                    is_match = False
                    break
                
                # Handle different types of expected values
                if isinstance(expected_value, dict) and 'type' in expected_value:
                    # Special matching types
                    if expected_value['type'] == 'geo_unusual':
                        # This would require historical data to implement properly
                        # For now, we'll just skip this check
                        continue
                    
                    elif expected_value['type'] == 'regex':
                        pattern = expected_value.get('pattern', '')
                        if not re.search(pattern, str(actual_value)):
                            is_match = False
                            break
                
                elif isinstance(expected_value, list):
                    # Match any value in the list
                    if actual_value not in expected_value:
                        is_match = False
                        break
                
                else:
                    # Direct value comparison
                    if actual_value != expected_value:
                        is_match = False
                        break
            
            if is_match:
                # For threshold-based signatures, track occurrences
                if threshold > 1:
                    # Use a relevant identifier from the item
                    identifier = self._get_item_identifier(item, evidence_type)
                    
                    if identifier not in occurrences:
                        occurrences[identifier] = []
                    
                    occurrences[identifier].append(item)
                else:
                    matches.append(item)
        
        # Process threshold-based matches
        if threshold > 1:
            for identifier, items in occurrences.items():
                if len(items) >= threshold:
                    matches.extend(items)
        
        return matches
    
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
    
    def _get_item_identifier(self, item: Dict[str, Any], evidence_type: str) -> str:
        """
        Get a unique identifier for an evidence item.
        
        Args:
            item: Evidence item
            evidence_type: Type of evidence
            
        Returns:
            Identifier string
        """
        # Use different fields based on evidence type
        if 'aws_cloudtrail' in evidence_type:
            return item.get('userIdentity', {}).get('arn', str(item.get('eventID', '')))
        
        elif 'azure_activity_log' in evidence_type:
            return item.get('caller', str(item.get('id', '')))
        
        elif 'gcp_audit_log' in evidence_type:
            return item.get('protoPayload', {}).get('authenticationInfo', {}).get('principalEmail', str(item.get('insertId', '')))
        
        else:
            # Default to a combination of fields
            return str(item.get('id', '')) + str(item.get('eventId', '')) + str(item.get('timestamp', ''))
    
    def _detect_attack_chains(self, detected_patterns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect multi-stage attack chains from individual patterns.
        
        Args:
            detected_patterns: List of detected pattern dictionaries
            
        Returns:
            List of attack chain dictionaries
        """
        attack_chains = []
        
        # Define known attack chain patterns
        chain_definitions = [
            {
                'name': 'Privilege Escalation Chain',
                'description': 'Multi-stage privilege escalation attack',
                'required_patterns': ['AWS IAM Policy Change', 'AWS Root Account Usage'],
                'mitre_tactics': ['TA0004', 'TA0005']
            },
            {
                'name': 'Defense Evasion Chain',
                'description': 'Attempt to disable security controls and evade detection',
                'required_patterns': ['AWS CloudTrail Changes', 'AWS Security Group Modification'],
                'mitre_tactics': ['TA0005']
            },
            {
                'name': 'Azure Privilege Escalation Chain',
                'description': 'Multi-stage privilege escalation in Azure',
                'required_patterns': ['Azure Role Assignment Change', 'Azure Diagnostic Settings Change'],
                'mitre_tactics': ['TA0004', 'TA0005']
            },
            {
                'name': 'GCP Defense Evasion Chain',
                'description': 'Attempt to disable security controls in GCP',
                'required_patterns': ['GCP Logging Configuration Change', 'GCP Firewall Rule Modification'],
                'mitre_tactics': ['TA0005']
            },
            {
                'name': 'Credential Access and Lateral Movement',
                'description': 'Credential theft followed by lateral movement',
                'required_patterns': ['Multiple Failed Logins', 'Data Access from Unusual Location'],
                'mitre_tactics': ['TA0006', 'TA0008']
            }
        ]
        
        # Check each chain definition
        for chain_def in chain_definitions:
            required_patterns = chain_def.get('required_patterns', [])
            
            # Check if all required patterns are present
            found_patterns = []
            for req_pattern in required_patterns:
                for detected in detected_patterns:
                    signature = detected.get('signature', {})
                    if signature.get('name') == req_pattern:
                        found_patterns.append(detected)
                        break
            
            if len(found_patterns) == len(required_patterns):
                # All required patterns found, create attack chain
                stages = []
                
                # Sort patterns by timestamp if available
                sorted_patterns = sorted(found_patterns, 
                                        key=lambda p: self._get_earliest_timestamp(p.get('matches', [])),
                                        reverse=False)
                
                for i, pattern in enumerate(sorted_patterns):
                    stages.append({
                        'stage_number': i + 1,
                        'pattern_name': pattern.get('signature', {}).get('name'),
                        'description': pattern.get('signature', {}).get('description'),
                        'evidence_type': pattern.get('evidence_type'),
                        'match_count': pattern.get('match_count', 0)
                    })
                
                attack_chains.append({
                    'name': chain_def.get('name'),
                    'description': chain_def.get('description'),
                    'stages': stages,
                    'confidence': 'medium',
                    'mitre_tactics': chain_def.get('mitre_tactics', [])
                })
        
        return attack_chains
    
    def _get_earliest_timestamp(self, items: List[Dict[str, Any]]) -> datetime.datetime:
        """
        Get the earliest timestamp from a list of items.
        
        Args:
            items: List of items with timestamps
            
        Returns:
            Earliest timestamp as datetime object
        """
        if not items:
            return datetime.datetime.max
        
        earliest = datetime.datetime.max
        
        for item in items:
            # Try common timestamp fields
            timestamp_fields = ['eventTime', 'timestamp', 'time', 'createdAt', 'CreationTime']
            
            for field in timestamp_fields:
                if field in item:
                    try:
                        item_time = analysis_utils.normalize_timestamp(item[field])
                        if item_time < earliest:
                            earliest = item_time
                    except (ValueError, TypeError):
                        pass
        
        return earliest
    
    def _detect_credential_patterns(self, evidence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect credential usage patterns that may indicate abuse.
        
        Args:
            evidence_data: Dictionary containing evidence data
            
        Returns:
            List of credential abuse pattern dictionaries
        """
        credential_patterns = []
        
        # Extract login events
        login_events = []
        
        # AWS Console logins
        if 'aws_cloudtrail' in evidence_data:
            for event in evidence_data['aws_cloudtrail']:
                if isinstance(event, dict) and event.get('eventName') == 'ConsoleLogin':
                    login_events.append({
                        'timestamp': event.get('eventTime'),
                        'user': event.get('userIdentity', {}).get('arn'),
                        'source_ip': event.get('sourceIPAddress'),
                        'success': event.get('responseElements', {}).get('ConsoleLogin') == 'Success',
                        'platform': 'AWS'
                    })
        
        # Azure logins
        if 'azure_activity_log' in evidence_data:
            for event in evidence_data['azure_activity_log']:
                if isinstance(event, dict) and 'Microsoft.AAD/SignIns' in event.get('operationName', ''):
                    login_events.append({
                        'timestamp': event.get('eventTimestamp'),
                        'user': event.get('caller'),
                        'source_ip': event.get('callerIpAddress'),
                        'success': event.get('status', {}).get('value') == 'Success',
                        'platform': 'Azure'
                    })
        
        # GCP logins
        if 'gcp_audit_log' in evidence_data:
            for event in evidence_data['gcp_audit_log']:
                if isinstance(event, dict) and event.get('protoPayload', {}).get('methodName') == 'google.login.Login.login':
                    login_events.append({
                        'timestamp': event.get('timestamp'),
                        'user': event.get('protoPayload', {}).get('authenticationInfo', {}).get('principalEmail'),
                        'source_ip': event.get('protoPayload', {}).get('requestMetadata', {}).get('callerIp'),
                        'success': 'error' not in event.get('protoPayload', {}),
                        'platform': 'GCP'
                    })
        
        # Office 365 logins
        if 'office365_audit' in evidence_data:
            for event in evidence_data['office365_audit']:
                if isinstance(event, dict) and event.get('Operation') == 'UserLoggedIn':
                    login_events.append({
                        'timestamp': event.get('CreationTime'),
                        'user': event.get('UserId'),
                        'source_ip': event.get('ClientIP'),
                        'success': event.get('ResultStatus') == 'Succeeded',
                        'platform': 'Office365'
                    })
        
        # G Suite logins
        if 'gsuite_admin' in evidence_data:
            for event in evidence_data['gsuite_admin']:
                if isinstance(event, dict) and event.get('events', {}).get('name') == 'login':
                    login_events.append({
                        'timestamp': event.get('id', {}).get('time'),
                        'user': event.get('actor', {}).get('email'),
                        'source_ip': event.get('ipAddress'),
                        'success': event.get('events', {}).get('parameters', {}).get('login_status') == 'success',
                        'platform': 'GSuite'
                    })
        
        # Sort login events by timestamp
        login_events.sort(key=lambda e: analysis_utils.normalize_timestamp(e['timestamp']) if e.get('timestamp') else datetime.datetime.min)
        
        # Detect rapid logins from different locations
        rapid_location_changes = self._detect_rapid_location_changes(login_events)
        if rapid_location_changes:
            credential_patterns.append({
                'pattern_type': 'rapid_location_change',
                'description': 'Rapid logins from different geographic locations',
                'affected_accounts': list(set(e['user'] for e in rapid_location_changes if e.get('user'))),
                'events': rapid_location_changes,
                'severity': 'high',
                'confidence': 'medium'
            })
        
        # Detect password spraying (multiple failed logins across different accounts)
        password_spraying = self._detect_password_spraying(login_events)
        if password_spraying:
            credential_patterns.append({
                'pattern_type': 'password_spraying',
                'description': 'Multiple failed login attempts across different accounts from the same source',
                'source_ips': list(set(e['source_ip'] for e in password_spraying if e.get('source_ip'))),
                'affected_accounts': list(set(e['user'] for e in password_spraying if e.get('user'))),
                'events': password_spraying,
                'severity': 'high',
                'confidence': 'medium'
            })
        
        # Detect successful logins after multiple failures (brute force)
        brute_force = self._detect_brute_force(login_events)
        if brute_force:
            credential_patterns.append({
                'pattern_type': 'brute_force',
                'description': 'Successful login after multiple failed attempts',
                'affected_accounts': list(set(account for account, events in brute_force.items())),
                'events': [e for account, events in brute_force.items() for e in events],
                'severity': 'high',
                'confidence': 'high'
            })
        
        return credential_patterns
    
    def _detect_rapid_location_changes(self, login_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect rapid logins from different locations for the same user.
        
        Args:
            login_events: List of login event dictionaries
            
        Returns:
            List of suspicious login events
        """
        suspicious_events = []
        
        # Group login events by user
        user_logins = {}
        for event in login_events:
            user = event.get('user')
            if not user:
                continue
            
            if user not in user_logins:
                user_logins[user] = []
            
            user_logins[user].append(event)
        
        # Check each user's login events for rapid location changes
        for user, events in user_logins.items():
            if len(events) < 2:
                continue
            
            # Sort events by timestamp
            sorted_events = sorted(events, key=lambda e: analysis_utils.normalize_timestamp(e['timestamp']) if e.get('timestamp') else datetime.datetime.min)
            
            for i in range(1, len(sorted_events)):
                prev_event = sorted_events[i-1]
                curr_event = sorted_events[i]
                
                prev_ip = prev_event.get('source_ip')
                curr_ip = curr_event.get('source_ip')
                
                if not prev_ip or not curr_ip or prev_ip == curr_ip:
                    continue
                
                # Check if events are close in time
                prev_time = analysis_utils.normalize_timestamp(prev_event['timestamp']) if prev_event.get('timestamp') else None
                curr_time = analysis_utils.normalize_timestamp(curr_event['timestamp']) if curr_event.get('timestamp') else None
                
                if prev_time and curr_time:
                    time_diff = (curr_time - prev_time).total_seconds()
                    
                    # If logins are less than 1 hour apart from different IPs, flag as suspicious
                    if time_diff < 3600:
                        suspicious_events.append(prev_event)
                        suspicious_events.append(curr_event)
        
        return suspicious_events
    
    def _detect_password_spraying(self, login_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect password spraying attacks (multiple failed logins across different accounts).
        
        Args:
            login_events: List of login event dictionaries
            
        Returns:
            List of suspicious login events
        """
        suspicious_events = []
        
        # Group failed login events by source IP
        ip_logins = {}
        for event in login_events:
            if event.get('success', True):
                continue
            
            source_ip = event.get('source_ip')
            if not source_ip:
                continue
            
            if source_ip not in ip_logins:
                ip_logins[source_ip] = []
            
            ip_logins[source_ip].append(event)
        
        # Check each source IP for failed logins across multiple accounts
        for source_ip, events in ip_logins.items():
            # Get unique users
            users = set(event.get('user') for event in events if event.get('user'))
            
            # If more than 3 different accounts had failed logins from the same IP, flag as suspicious
            if len(users) >= 3:
                suspicious_events.extend(events)
        
        return suspicious_events
    
    def _detect_brute_force(self, login_events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Detect brute force attacks (successful login after multiple failures).
        
        Args:
            login_events: List of login event dictionaries
            
        Returns:
            Dictionary mapping affected accounts to lists of suspicious login events
        """
        brute_force_patterns = {}
        
        # Group login events by user and source IP
        user_ip_logins = {}
        for event in login_events:
            user = event.get('user')
            source_ip = event.get('source_ip')
            
            if not user or not source_ip:
                continue
            
            key = f"{user}_{source_ip}"
            if key not in user_ip_logins:
                user_ip_logins[key] = []
            
            user_ip_logins[key].append(event)
        
        # Check each user+IP combination for brute force patterns
        for key, events in user_ip_logins.items():
            if len(events) < 4:  # Need at least a few events to detect a pattern
                continue
            
            # Sort events by timestamp
            sorted_events = sorted(events, key=lambda e: analysis_utils.normalize_timestamp(e['timestamp']) if e.get('timestamp') else datetime.datetime.min)
            
            # Look for a successful login after multiple failures
            failures = []
            for event in sorted_events:
                if not event.get('success', True):
                    failures.append(event)
                else:
                    # Successful login found
                    if len(failures) >= 3:  # At least 3 failed attempts before success
                        user = event.get('user')
                        if user not in brute_force_patterns:
                            brute_force_patterns[user] = []
                        
                        brute_force_patterns[user].extend(failures)
                        brute_force_patterns[user].append(event)
                    
                    failures = []  # Reset failures after a success
        
        return brute_force_patterns
    
    def _detect_data_exfiltration(self, evidence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect patterns that may indicate data exfiltration.
        
        Args:
            evidence_data: Dictionary containing evidence data
            
        Returns:
            List of data exfiltration pattern dictionaries
        """
        exfiltration_patterns = []
        
        # Extract data access events
        data_access_events = []
        
        # AWS S3 data access
        if 'aws_cloudtrail' in evidence_data:
            for event in evidence_data['aws_cloudtrail']:
                if isinstance(event, dict) and event.get('eventName') in ['GetObject', 'ListObjects', 'SelectObjectContent']:
                    data_access_events.append({
                        'timestamp': event.get('eventTime'),
                        'user': event.get('userIdentity', {}).get('arn'),
                        'source_ip': event.get('sourceIPAddress'),
                        'resource': event.get('requestParameters', {}).get('bucketName'),
                        'action': event.get('eventName'),
                        'platform': 'AWS',
                        'service': 'S3'
                    })
        
        # Azure Storage data access
        if 'azure_activity_log' in evidence_data:
            for event in evidence_data['azure_activity_log']:
                if isinstance(event, dict) and 'Microsoft.Storage/storageAccounts' in event.get('resourceProvider', ''):
                    data_access_events.append({
                        'timestamp': event.get('eventTimestamp'),
                        'user': event.get('caller'),
                        'source_ip': event.get('callerIpAddress'),
                        'resource': event.get('resourceId'),
                        'action': event.get('operationName'),
                        'platform': 'Azure',
                        'service': 'Storage'
                    })
        
        # GCP Storage data access
        if 'gcp_audit_log' in evidence_data:
            for event in evidence_data['gcp_audit_log']:
                if isinstance(event, dict) and 'storage.googleapis.com' in event.get('protoPayload', {}).get('serviceName', ''):
                    data_access_events.append({
                        'timestamp': event.get('timestamp'),
                        'user': event.get('protoPayload', {}).get('authenticationInfo', {}).get('principalEmail'),
                        'source_ip': event.get('protoPayload', {}).get('requestMetadata', {}).get('callerIp'),
                        'resource': event.get('resource', {}).get('labels', {}).get('bucket_name'),
                        'action': event.get('protoPayload', {}).get('methodName'),
                        'platform': 'GCP',
                        'service': 'Storage'
                    })
        
        # Detect large volume data access
        large_volume_access = self._detect_large_volume_access(data_access_events)
        if large_volume_access:
            exfiltration_patterns.append({
                'pattern_type': 'large_volume_access',
                'description': 'Large volume of data access events detected',
                'data_sources': list(set(f"{e['platform']}/{e['service']}" for e in large_volume_access if e.get('platform') and e.get('service'))),
                'affected_resources': list(set(e['resource'] for e in large_volume_access if e.get('resource'))),
                'events': large_volume_access,
                'volume': len(large_volume_access),
                'severity': 'high',
                'confidence': 'medium'
            })
        
        # Detect unusual data access patterns
        unusual_access = self._detect_unusual_data_access(data_access_events)
        if unusual_access:
            exfiltration_patterns.append({
                'pattern_type': 'unusual_data_access',
                'description': 'Unusual data access patterns detected',
                'data_sources': list(set(f"{e['platform']}/{e['service']}" for e in unusual_access if e.get('platform') and e.get('service'))),
                'affected_resources': list(set(e['resource'] for e in unusual_access if e.get('resource'))),
                'events': unusual_access,
                'volume': len(unusual_access),
                'severity': 'medium',
                'confidence': 'medium'
            })
        
        return exfiltration_patterns
    
    def _detect_large_volume_access(self, data_access_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect large volume data access that may indicate exfiltration.
        
        Args:
            data_access_events: List of data access event dictionaries
            
        Returns:
            List of suspicious data access events
        """
        suspicious_events = []
        
        # Group data access events by user and resource
        user_resource_access = {}
        for event in data_access_events:
            user = event.get('user')
            resource = event.get('resource')
            
            if not user or not resource:
                continue
            
            key = f"{user}_{resource}"
            if key not in user_resource_access:
                user_resource_access[key] = []
            
            user_resource_access[key].append(event)
        
        # Check each user+resource combination for high volume access
        for key, events in user_resource_access.items():
            # If more than 50 access events for the same resource by the same user, flag as suspicious
            if len(events) > 50:
                suspicious_events.extend(events)
        
        return suspicious_events
    
    def _detect_unusual_data_access(self, data_access_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect unusual data access patterns that may indicate exfiltration.
        
        Args:
            data_access_events: List of data access event dictionaries
            
        Returns:
            List of suspicious data access events
        """
        suspicious_events = []
        
        # Group data access events by user
        user_access = {}
        for event in data_access_events:
            user = event.get('user')
            
            if not user:
                continue
            
            if user not in user_access:
                user_access[user] = []
            
            user_access[user].append(event)
        
        # Check each user's access patterns
        for user, events in user_access.items():
            # Sort events by timestamp
            sorted_events = sorted(events, key=lambda e: analysis_utils.normalize_timestamp(e['timestamp']) if e.get('timestamp') else datetime.datetime.min)
            
            # Check for access to multiple resources in a short time
            resource_access_times = {}
            for event in sorted_events:
                resource = event.get('resource')
                timestamp = event.get('timestamp')
                
                if not resource or not timestamp:
                    continue
                
                if resource not in resource_access_times:
                    resource_access_times[resource] = []
                
                resource_access_times[resource].append(analysis_utils.normalize_timestamp(timestamp))
            
            # If user accessed more than 10 different resources, check time patterns
            if len(resource_access_times) > 10:
                # Get the earliest and latest access times
                all_times = [time for times in resource_access_times.values() for time in times]
                all_times.sort()
                
                if all_times:
                    earliest = all_times[0]
                    latest = all_times[-1]
                    
                    # If all accesses happened within 1 hour, flag as suspicious
                    if (latest - earliest).total_seconds() < 3600:
                        suspicious_events.extend(events)
        
        return suspicious_events
    
    def _detect_privilege_escalation(self, evidence_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Detect patterns that may indicate privilege escalation.
        
        Args:
            evidence_data: Dictionary containing evidence data
            
        Returns:
            List of privilege escalation pattern dictionaries
        """
        privilege_patterns = []
        
        # Extract privilege change events
        privilege_events = []
        
        # AWS IAM privilege changes
        if 'aws_cloudtrail' in evidence_data:
            for event in evidence_data['aws_cloudtrail']:
                if isinstance(event, dict) and event.get('eventName') in [
                    'AttachUserPolicy', 'AttachRolePolicy', 'AttachGroupPolicy',
                    'PutUserPolicy', 'PutRolePolicy', 'PutGroupPolicy',
                    'CreatePolicy', 'CreatePolicyVersion'
                ]:
                    privilege_events.append({
                        'timestamp': event.get('eventTime'),
                        'user': event.get('userIdentity', {}).get('arn'),
                        'source_ip': event.get('sourceIPAddress'),
                        'resource': event.get('requestParameters', {}).get('roleName') or 
                                  event.get('requestParameters', {}).get('userName') or 
                                  event.get('requestParameters', {}).get('groupName') or 
                                  event.get('requestParameters', {}).get('policyArn'),
                        'action': event.get('eventName'),
                        'platform': 'AWS',
                        'service': 'IAM'
                    })
        
        # Azure RBAC privilege changes
        if 'azure_activity_log' in evidence_data:
            for event in evidence_data['azure_activity_log']:
                if isinstance(event, dict) and 'Microsoft.Authorization/roleAssignments' in event.get('operationName', ''):
                    privilege_events.append({
                        'timestamp': event.get('eventTimestamp'),
                        'user': event.get('caller'),
                        'source_ip': event.get('callerIpAddress'),
                        'resource': event.get('resourceId'),
                        'action': event.get('operationName'),
                        'platform': 'Azure',
                        'service': 'RBAC'
                    })
        
        # GCP IAM privilege changes
        if 'gcp_audit_log' in evidence_data:
            for event in evidence_data['gcp_audit_log']:
                if isinstance(event, dict) and 'SetIamPolicy' in event.get('protoPayload', {}).get('methodName', ''):
                    privilege_events.append({
                        'timestamp': event.get('timestamp'),
                        'user': event.get('protoPayload', {}).get('authenticationInfo', {}).get('principalEmail'),
                        'source_ip': event.get('protoPayload', {}).get('requestMetadata', {}).get('callerIp'),
                        'resource': event.get('resource', {}).get('labels', {}).get('project_id'),
                        'action': event.get('protoPayload', {}).get('methodName'),
                        'platform': 'GCP',
                        'service': 'IAM'
                    })
        
        # Detect self-privilege escalation
        self_escalation = self._detect_self_privilege_escalation(privilege_events)
        if self_escalation:
            privilege_patterns.append({
                'pattern_type': 'self_privilege_escalation',
                'description': 'User modified their own privileges',
                'affected_resources': list(set(e['resource'] for e in self_escalation if e.get('resource'))),
                'events': self_escalation,
                'severity': 'high',
                'confidence': 'high'
            })
        
        # Detect privilege escalation chains
        escalation_chains = self._detect_escalation_chains(privilege_events)
        if escalation_chains:
            privilege_patterns.append({
                'pattern_type': 'escalation_chain',
                'description': 'Sequential privilege escalation detected',
                'affected_resources': list(set(e['resource'] for chain in escalation_chains.values() for e in chain if e.get('resource'))),
                'events': [e for chain in escalation_chains.values() for e in chain],
                'severity': 'high',
                'confidence': 'medium'
            })
        
        return privilege_patterns
    
    def _detect_self_privilege_escalation(self, privilege_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Detect users modifying their own privileges.
        
        Args:
            privilege_events: List of privilege change event dictionaries
            
        Returns:
            List of suspicious privilege change events
        """
        suspicious_events = []
        
        for event in privilege_events:
            user = event.get('user')
            resource = event.get('resource')
            
            if not user or not resource:
                continue
            
            # Check if user is modifying their own privileges
            # This is a simplified check and would need to be adapted for each platform
            if user in resource:
                suspicious_events.append(event)
        
        return suspicious_events
    
    def _detect_escalation_chains(self, privilege_events: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Detect chains of privilege escalation events.
        
        Args:
            privilege_events: List of privilege change event dictionaries
            
        Returns:
            Dictionary mapping users to lists of suspicious privilege change events
        """
        escalation_chains = {}
        
        # Group privilege events by user
        user_events = {}
        for event in privilege_events:
            user = event.get('user')
            
            if not user:
                continue
            
            if user not in user_events:
                user_events[user] = []
            
            user_events[user].append(event)
        
        # Check each user's privilege events for chains
        for user, events in user_events.items():
            if len(events) < 3:  # Need at least a few events to detect a chain
                continue
            
            # Sort events by timestamp
            sorted_events = sorted(events, key=lambda e: analysis_utils.normalize_timestamp(e['timestamp']) if e.get('timestamp') else datetime.datetime.min)
            
            # Check for multiple privilege changes in a short time
            if len(sorted_events) >= 3:
                first_time = analysis_utils.normalize_timestamp(sorted_events[0]['timestamp']) if sorted_events[0].get('timestamp') else None
                last_time = analysis_utils.normalize_timestamp(sorted_events[-1]['timestamp']) if sorted_events[-1].get('timestamp') else None
                
                if first_time and last_time:
                    time_diff = (last_time - first_time).total_seconds()
                    
                    # If 3+ privilege changes happened within 30 minutes, flag as suspicious
                    if time_diff < 1800:
                        escalation_chains[user] = sorted_events
        
        return escalation_chains
