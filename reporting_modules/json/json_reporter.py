"""
JSON reporter for the Cloud Forensics AI Agent.

This module provides functionality for generating forensic reports
in JSON format from analysis results.
"""

import datetime
import json
import logging
import os
from typing import Any, Dict, List, Optional, Union

from ..core.base_reporter import BaseReporter

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class JSONReporter(BaseReporter):
    """
    Reporter for generating forensic reports in JSON format.
    
    This class extends the BaseReporter to generate machine-readable
    JSON reports for programmatic consumption and integration.
    """
    
    def __init__(self, case_id: str, report_output_path: str):
        """
        Initialize the JSON reporter.
        
        Args:
            case_id: Unique identifier for the forensic case
            report_output_path: Path where reports will be stored
        """
        super().__init__(case_id, report_output_path)
        self.metadata['report_format'] = 'json'
        logger.info(f"Initialized JSONReporter for case {case_id}")
    
    def generate_report(self, analysis_results: Dict[str, Any], 
                      evidence_metadata: Dict[str, Any] = None,
                      include_raw_data: bool = False) -> str:
        """
        Generate a JSON forensic report from analysis results.
        
        Args:
            analysis_results: Dictionary containing analysis results
            evidence_metadata: Optional metadata about the evidence
            include_raw_data: Whether to include raw data in the report
            
        Returns:
            Path to the generated JSON report
        """
        # Prepare report data
        report_data = self._prepare_report_data(analysis_results, evidence_metadata, include_raw_data)
        
        # Convert datetime objects to strings
        report_data = self._convert_datetime_to_str(report_data)
        
        # Write JSON to file
        report_filename = f"forensic_report_{self.case_id}_{self.report_id}.json"
        report_path = os.path.join(self.report_output_path, report_filename)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2)
        
        logger.info(f"Generated JSON report at {report_path}")
        
        # Add custody event
        self.add_custody_event(
            event_type="report_generation",
            description=f"Generated JSON forensic report",
            handler="Cloud Forensics AI Agent"
        )
        
        return report_path
    
    def _convert_datetime_to_str(self, data: Any) -> Any:
        """
        Convert datetime objects to ISO format strings in a nested structure.
        
        Args:
            data: Data structure that may contain datetime objects
            
        Returns:
            Data structure with datetime objects converted to strings
        """
        if isinstance(data, datetime.datetime):
            return data.isoformat()
        elif isinstance(data, dict):
            return {k: self._convert_datetime_to_str(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._convert_datetime_to_str(item) for item in data]
        else:
            return data
