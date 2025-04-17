"""
Base reporter class for the Cloud Forensics AI Agent.

This module provides the base functionality for generating forensic reports
in various formats from analysis results.
"""

import datetime
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BaseReporter:
    """
    Base class for forensic report generation.
    
    This class provides common functionality for all report formats,
    including report metadata, evidence handling, and chain of custody.
    """
    
    def __init__(self, case_id: str, report_output_path: str):
        """
        Initialize the base reporter.
        
        Args:
            case_id: Unique identifier for the forensic case
            report_output_path: Path where reports will be stored
        """
        self.case_id = case_id
        self.report_output_path = report_output_path
        self.report_id = str(uuid.uuid4())
        self.report_timestamp = datetime.datetime.utcnow()
        self.metadata = {
            'case_id': case_id,
            'report_id': self.report_id,
            'report_timestamp': self.report_timestamp.isoformat(),
            'report_version': '1.0',
            'report_generator': 'Cloud Forensics AI Agent',
            'report_format': 'base'
        }
        self.chain_of_custody = []
        
        # Create output directory if it doesn't exist
        os.makedirs(report_output_path, exist_ok=True)
        
        logger.info(f"Initialized BaseReporter for case {case_id}")
    
    def set_metadata(self, key: str, value: Any) -> None:
        """
        Set a metadata field for the report.
        
        Args:
            key: Metadata field name
            value: Metadata field value
        """
        self.metadata[key] = value
    
    def set_case_information(self, case_info: Dict[str, Any]) -> None:
        """
        Set case information for the report.
        
        Args:
            case_info: Dictionary containing case information
        """
        self.metadata['case_information'] = case_info
    
    def set_investigator_information(self, investigator_info: Dict[str, Any]) -> None:
        """
        Set investigator information for the report.
        
        Args:
            investigator_info: Dictionary containing investigator information
        """
        self.metadata['investigator_information'] = investigator_info
    
    def add_custody_event(self, event_type: str, description: str, 
                        handler: str, timestamp: Optional[datetime.datetime] = None) -> None:
        """
        Add a chain of custody event to the report.
        
        Args:
            event_type: Type of custody event
            description: Description of the event
            handler: Person or system handling the evidence
            timestamp: Event timestamp (defaults to current time)
        """
        if timestamp is None:
            timestamp = datetime.datetime.utcnow()
        
        custody_event = {
            'event_type': event_type,
            'description': description,
            'handler': handler,
            'timestamp': timestamp.isoformat()
        }
        
        self.chain_of_custody.append(custody_event)
    
    def generate_report(self, analysis_results: Dict[str, Any], 
                      evidence_metadata: Dict[str, Any] = None,
                      include_raw_data: bool = False) -> str:
        """
        Generate a forensic report from analysis results.
        
        Args:
            analysis_results: Dictionary containing analysis results
            evidence_metadata: Optional metadata about the evidence
            include_raw_data: Whether to include raw data in the report
            
        Returns:
            Path to the generated report
        """
        raise NotImplementedError("Subclasses must implement generate_report method")
    
    def _prepare_report_data(self, analysis_results: Dict[str, Any], 
                           evidence_metadata: Dict[str, Any] = None,
                           include_raw_data: bool = False) -> Dict[str, Any]:
        """
        Prepare data for report generation.
        
        Args:
            analysis_results: Dictionary containing analysis results
            evidence_metadata: Optional metadata about the evidence
            include_raw_data: Whether to include raw data in the report
            
        Returns:
            Dictionary containing prepared report data
        """
        # Add timestamp for report generation
        self.metadata['generation_timestamp'] = datetime.datetime.utcnow().isoformat()
        
        # Prepare report data
        report_data = {
            'metadata': self.metadata,
            'chain_of_custody': self.chain_of_custody,
            'evidence_metadata': evidence_metadata or {},
            'analysis_results': {}
        }
        
        # Process analysis results
        for analysis_type, result in analysis_results.items():
            if isinstance(result, dict):
                # Include summary and findings
                processed_result = {
                    'summary': result.get('summary', ''),
                    'findings': result.get('findings', [])
                }
                
                # Include report if available
                if 'report' in result:
                    processed_result['report'] = result['report']
                
                # Include raw data if requested
                if include_raw_data:
                    processed_result['raw_data'] = result
                
                report_data['analysis_results'][analysis_type] = processed_result
        
        # Add executive summary
        report_data['executive_summary'] = self._generate_executive_summary(analysis_results)
        
        # Add recommendations
        report_data['recommendations'] = self._generate_recommendations(analysis_results)
        
        return report_data
    
    def _generate_executive_summary(self, analysis_results: Dict[str, Any]) -> str:
        """
        Generate an executive summary from analysis results.
        
        Args:
            analysis_results: Dictionary containing analysis results
            
        Returns:
            Executive summary string
        """
        summary_parts = []
        
        # Add introduction
        summary_parts.append(f"Executive Summary for Case {self.case_id}")
        summary_parts.append("")
        summary_parts.append("This report presents the findings of a digital forensic analysis conducted on cloud-based evidence.")
        
        # Add high-level findings
        high_severity_findings = []
        medium_severity_findings = []
        
        for analysis_type, result in analysis_results.items():
            if isinstance(result, dict) and 'findings' in result:
                for finding in result['findings']:
                    if finding.get('severity') == 'high':
                        high_severity_findings.append(finding)
                    elif finding.get('severity') == 'medium':
                        medium_severity_findings.append(finding)
        
        summary_parts.append("")
        summary_parts.append(f"The analysis identified {len(high_severity_findings)} high-severity findings and {len(medium_severity_findings)} medium-severity findings.")
        
        # Add summary of analysis types
        analysis_types = list(analysis_results.keys())
        if analysis_types:
            summary_parts.append("")
            summary_parts.append(f"The following analysis types were performed: {', '.join(analysis_types)}.")
        
        # Add key findings
        if high_severity_findings:
            summary_parts.append("")
            summary_parts.append("Key High-Severity Findings:")
            for i, finding in enumerate(high_severity_findings[:5]):  # Limit to top 5
                summary_parts.append(f"- {finding.get('description', f'Finding {i+1}')}")
        
        # Add conclusion
        summary_parts.append("")
        summary_parts.append("This report provides detailed information about the analysis methodology, findings, and recommendations for remediation and future prevention.")
        
        return "\n".join(summary_parts)
    
    def _generate_recommendations(self, analysis_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generate recommendations based on analysis results.
        
        Args:
            analysis_results: Dictionary containing analysis results
            
        Returns:
            List of recommendation dictionaries
        """
        recommendations = []
        
        # Track finding types to avoid duplicate recommendations
        finding_types = set()
        
        # Process findings from all analysis types
        for analysis_type, result in analysis_results.items():
            if isinstance(result, dict) and 'findings' in result:
                for finding in result['findings']:
                    finding_type = finding.get('type')
                    if finding_type in finding_types:
                        continue
                    
                    finding_types.add(finding_type)
                    
                    # Generate recommendation based on finding type
                    recommendation = self._get_recommendation_for_finding(finding)
                    if recommendation:
                        recommendations.append(recommendation)
        
        # Add general recommendations
        general_recommendations = [
            {
                'title': 'Implement Multi-Factor Authentication',
                'description': 'Enable multi-factor authentication for all cloud service accounts to prevent unauthorized access.',
                'priority': 'high',
                'category': 'security'
            },
            {
                'title': 'Enable Comprehensive Logging',
                'description': 'Ensure comprehensive logging is enabled across all cloud services and retain logs for at least 90 days.',
                'priority': 'high',
                'category': 'monitoring'
            },
            {
                'title': 'Regular Security Assessments',
                'description': 'Conduct regular security assessments and penetration testing of cloud environments.',
                'priority': 'medium',
                'category': 'governance'
            }
        ]
        
        # Add general recommendations that don't duplicate existing ones
        for rec in general_recommendations:
            if not any(r.get('title') == rec['title'] for r in recommendations):
                recommendations.append(rec)
        
        return recommendations
    
    def _get_recommendation_for_finding(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Get a recommendation for a specific finding.
        
        Args:
            finding: Finding dictionary
            
        Returns:
            Recommendation dictionary or None
        """
        finding_type = finding.get('type')
        severity = finding.get('severity', 'medium')
        
        # Define recommendations for different finding types
        recommendations = {
            'pattern_match': {
                'title': 'Review and Update Security Policies',
                'description': 'Review and update security policies to address the detected attack patterns.',
                'priority': severity,
                'category': 'governance'
            },
            'attack_chain': {
                'title': 'Implement Defense-in-Depth Strategy',
                'description': 'Implement a defense-in-depth strategy to break attack chains at multiple points.',
                'priority': 'high',
                'category': 'security'
            },
            'statistical_anomaly': {
                'title': 'Establish Baseline Monitoring',
                'description': 'Establish baseline monitoring and alerting for statistical anomalies in cloud resource usage.',
                'priority': severity,
                'category': 'monitoring'
            },
            'behavioral_anomaly': {
                'title': 'Implement User Behavior Analytics',
                'description': 'Implement user behavior analytics to detect and alert on unusual user activities.',
                'priority': severity,
                'category': 'monitoring'
            },
            'temporal_anomaly': {
                'title': 'Implement Time-Based Access Controls',
                'description': 'Implement time-based access controls to restrict access during unusual hours.',
                'priority': severity,
                'category': 'security'
            },
            'access_anomaly': {
                'title': 'Review and Restrict Access Permissions',
                'description': 'Review and restrict access permissions based on the principle of least privilege.',
                'priority': 'high',
                'category': 'security'
            },
            'network_anomaly': {
                'title': 'Implement Network Segmentation',
                'description': 'Implement network segmentation and restrict traffic between segments.',
                'priority': severity,
                'category': 'network'
            },
            'time_correlation': {
                'title': 'Enhance Real-Time Monitoring',
                'description': 'Enhance real-time monitoring and alerting for correlated events.',
                'priority': severity,
                'category': 'monitoring'
            },
            'entity_correlation': {
                'title': 'Implement Entity-Based Monitoring',
                'description': 'Implement entity-based monitoring to detect suspicious activities across multiple resources.',
                'priority': severity,
                'category': 'monitoring'
            },
            'pattern_correlation': {
                'title': 'Deploy Advanced Threat Protection',
                'description': 'Deploy advanced threat protection solutions to detect and respond to complex attack patterns.',
                'priority': 'high',
                'category': 'security'
            },
            'cross_cloud_correlation': {
                'title': 'Implement Centralized Security Monitoring',
                'description': 'Implement centralized security monitoring across all cloud environments.',
                'priority': 'high',
                'category': 'monitoring'
            },
            'credential_abuse': {
                'title': 'Implement Credential Management',
                'description': 'Implement robust credential management practices, including regular rotation and monitoring.',
                'priority': 'high',
                'category': 'security'
            },
            'data_exfiltration': {
                'title': 'Implement Data Loss Prevention',
                'description': 'Implement data loss prevention controls to detect and prevent unauthorized data transfers.',
                'priority': 'high',
                'category': 'data'
            },
            'privilege_escalation': {
                'title': 'Implement Privileged Access Management',
                'description': 'Implement privileged access management to control and monitor privileged operations.',
                'priority': 'high',
                'category': 'security'
            }
        }
        
        return recommendations.get(finding_type)
    
    def _format_timestamp(self, timestamp: Union[str, datetime.datetime]) -> str:
        """
        Format a timestamp for display in reports.
        
        Args:
            timestamp: Timestamp as string or datetime object
            
        Returns:
            Formatted timestamp string
        """
        if isinstance(timestamp, str):
            try:
                dt = datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            except ValueError:
                return timestamp
        else:
            dt = timestamp
        
        return dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    
    def _sanitize_for_report(self, data: Any) -> Any:
        """
        Sanitize data for inclusion in reports.
        
        Args:
            data: Data to sanitize
            
        Returns:
            Sanitized data
        """
        if isinstance(data, dict):
            return {k: self._sanitize_for_report(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._sanitize_for_report(item) for item in data]
        elif isinstance(data, (int, float, bool, str)) or data is None:
            return data
        else:
            return str(data)
