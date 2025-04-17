"""
Utility functions for the reporting modules of the Cloud Forensics AI Agent.
"""

import datetime
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def normalize_timestamp(timestamp: Union[str, datetime.datetime]) -> str:
    """
    Normalize a timestamp to a standard format.
    
    Args:
        timestamp: Timestamp as string or datetime object
        
    Returns:
        Normalized timestamp string
    """
    if isinstance(timestamp, str):
        try:
            dt = datetime.datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        except ValueError:
            # Try other common formats
            formats = [
                '%Y-%m-%dT%H:%M:%S.%f',
                '%Y-%m-%dT%H:%M:%S',
                '%Y-%m-%d %H:%M:%S.%f',
                '%Y-%m-%d %H:%M:%S',
                '%Y/%m/%d %H:%M:%S',
                '%d/%m/%Y %H:%M:%S',
                '%m/%d/%Y %H:%M:%S'
            ]
            
            for fmt in formats:
                try:
                    dt = datetime.datetime.strptime(timestamp, fmt)
                    break
                except ValueError:
                    continue
            else:
                return timestamp  # Return original if no format matches
    else:
        dt = timestamp
    
    return dt.strftime('%Y-%m-%d %H:%M:%S UTC')

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to ensure it's valid across operating systems.
    
    Args:
        filename: Original filename
        
    Returns:
        Sanitized filename
    """
    # Replace invalid characters with underscores
    sanitized = re.sub(r'[\\/*?:"<>|]', '_', filename)
    
    # Ensure filename isn't too long
    if len(sanitized) > 255:
        base, ext = os.path.splitext(sanitized)
        sanitized = base[:255-len(ext)] + ext
    
    return sanitized

def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: File size in bytes
        
    Returns:
        Human-readable file size string
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.2f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.2f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"

def generate_report_summary(findings: List[Dict[str, Any]]) -> str:
    """
    Generate a summary of findings for a report.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        Summary string
    """
    if not findings:
        return "No findings were identified during the analysis."
    
    # Count findings by severity
    severity_counts = {'high': 0, 'medium': 0, 'low': 0}
    for finding in findings:
        severity = finding.get('severity', 'low').lower()
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    # Count findings by type
    type_counts = {}
    for finding in findings:
        finding_type = finding.get('type', 'unknown')
        if finding_type not in type_counts:
            type_counts[finding_type] = 0
        type_counts[finding_type] += 1
    
    # Generate summary text
    summary_parts = []
    
    total_findings = sum(severity_counts.values())
    summary_parts.append(f"The analysis identified a total of {total_findings} findings.")
    
    if severity_counts['high'] > 0:
        summary_parts.append(f"There are {severity_counts['high']} high-severity findings that require immediate attention.")
    
    if severity_counts['medium'] > 0:
        summary_parts.append(f"There are {severity_counts['medium']} medium-severity findings that should be addressed.")
    
    if severity_counts['low'] > 0:
        summary_parts.append(f"There are {severity_counts['low']} low-severity findings for consideration.")
    
    # Add information about finding types
    if type_counts:
        summary_parts.append("The findings include:")
        for finding_type, count in type_counts.items():
            summary_parts.append(f"- {count} {finding_type} finding{'s' if count > 1 else ''}")
    
    return " ".join(summary_parts)

def merge_findings(findings_lists: List[List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """
    Merge multiple lists of findings, removing duplicates.
    
    Args:
        findings_lists: List of finding lists to merge
        
    Returns:
        Merged list of findings
    """
    if not findings_lists:
        return []
    
    # Flatten the list of lists
    all_findings = []
    for findings in findings_lists:
        all_findings.extend(findings)
    
    # Remove duplicates based on description
    unique_findings = {}
    for finding in all_findings:
        description = finding.get('description', '')
        if description and description not in unique_findings:
            unique_findings[description] = finding
    
    return list(unique_findings.values())

def extract_mitre_techniques(findings: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """
    Extract MITRE ATT&CK techniques from findings.
    
    Args:
        findings: List of finding dictionaries
        
    Returns:
        Dictionary mapping technique IDs to technique information
    """
    techniques = {}
    
    for finding in findings:
        mitre_techniques = finding.get('mitre_techniques', [])
        for technique in mitre_techniques:
            if isinstance(technique, str):
                # Just the technique ID
                technique_id = technique
                if technique_id not in techniques:
                    techniques[technique_id] = {
                        'id': technique_id,
                        'findings': []
                    }
                techniques[technique_id]['findings'].append(finding)
            elif isinstance(technique, dict):
                # Technique information
                technique_id = technique.get('id')
                if technique_id and technique_id not in techniques:
                    techniques[technique_id] = technique.copy()
                    techniques[technique_id]['findings'] = []
                if technique_id:
                    techniques[technique_id]['findings'].append(finding)
    
    return techniques
