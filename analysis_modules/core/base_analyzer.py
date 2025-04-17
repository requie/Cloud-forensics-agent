"""
Base analyzer class for all analysis modules.

This module defines the abstract base class that all analyzers must implement,
ensuring consistent interfaces and behavior across different analysis types.
"""

import abc
import datetime
import json
import logging
import os
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BaseAnalyzer(abc.ABC):
    """
    Abstract base class for all analyzers in the Cloud Forensics AI Agent.
    
    This class defines the common interface and functionality that all analysis
    modules must implement, regardless of analysis type.
    """
    
    def __init__(self, case_id: str, analysis_output_path: str):
        """
        Initialize the base analyzer.
        
        Args:
            case_id: Unique identifier for the forensic case
            analysis_output_path: Path where analysis results will be stored
        """
        self.case_id = case_id
        self.analysis_output_path = analysis_output_path
        self.analyzer_id = str(uuid.uuid4())
        self.analysis_start_time = None
        self.analysis_end_time = None
        self.analysis_metadata = {
            'analyzer_type': self.__class__.__name__,
            'case_id': case_id,
            'analyzer_id': self.analyzer_id,
            'parameters': {}
        }
        
        # Ensure analysis output path exists
        os.makedirs(analysis_output_path, exist_ok=True)
        
        logger.info(f"Initialized analyzer {self.analyzer_id} for case {case_id}")
    
    @abc.abstractmethod
    def analyze(self, evidence_data: Dict[str, Any], *args, **kwargs) -> Dict[str, Any]:
        """
        Analyze the provided evidence data.
        
        This method must be implemented by all concrete analyzer classes.
        
        Args:
            evidence_data: Dictionary containing evidence data to analyze
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
            
        Returns:
            A dictionary containing analysis results
        """
        pass
    
    def start_analysis(self) -> None:
        """Record the start time of the analysis process."""
        self.analysis_start_time = datetime.datetime.utcnow()
        self.analysis_metadata['analysis_start_time'] = self.analysis_start_time.isoformat()
        logger.info(f"Starting analysis with {self.__class__.__name__}")
    
    def end_analysis(self) -> None:
        """Record the end time of the analysis process."""
        self.analysis_end_time = datetime.datetime.utcnow()
        self.analysis_metadata['analysis_end_time'] = self.analysis_end_time.isoformat()
        
        if self.analysis_start_time:
            duration = (self.analysis_end_time - self.analysis_start_time).total_seconds()
            self.analysis_metadata['analysis_duration_seconds'] = duration
        
        logger.info(f"Completed analysis with {self.__class__.__name__}")
    
    def set_parameters(self, parameters: Dict[str, Any]) -> None:
        """
        Set parameters for the analysis.
        
        Args:
            parameters: Dictionary of parameters to use for analysis
        """
        self.analysis_metadata['parameters'] = parameters
        logger.info(f"Set analysis parameters: {parameters}")
    
    def save_results(self, results: Any, result_type: str) -> str:
        """
        Save analysis results to storage with proper metadata.
        
        Args:
            results: The analysis results to save
            result_type: Type of results (e.g., 'timeline', 'anomalies', 'patterns')
            
        Returns:
            Path to the saved results file
        """
        # Generate a unique filename
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
        filename = f"{self.case_id}_{result_type}_{self.analyzer_id}_{timestamp}"
        
        # Determine file extension and save method based on result type
        if isinstance(results, (dict, list)):
            file_path = os.path.join(self.analysis_output_path, f"{filename}.json")
            with open(file_path, 'w') as f:
                json.dump(results, f, indent=2)
        elif isinstance(results, str):
            file_path = os.path.join(self.analysis_output_path, f"{filename}.txt")
            with open(file_path, 'w') as f:
                f.write(results)
        else:
            raise TypeError(f"Unsupported result data type: {type(results)}")
        
        logger.info(f"Saved analysis results to {file_path}")
        return file_path
    
    def generate_analysis_report(self, results_paths: List[str], 
                               summary: str, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate a report of the analysis activity.
        
        Args:
            results_paths: List of paths to saved result files
            summary: Summary of the analysis findings
            findings: List of specific findings from the analysis
            
        Returns:
            Dictionary containing analysis report
        """
        if not self.analysis_end_time:
            self.end_analysis()
        
        report = {
            **self.analysis_metadata,
            'results_files': results_paths,
            'summary': summary,
            'findings': findings,
            'finding_count': len(findings)
        }
        
        # Save report to file
        report_file = os.path.join(
            self.analysis_output_path, 
            f"{self.case_id}_{self.analyzer_id}_analysis_report.json"
        )
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Generated analysis report: {report_file}")
        return report
