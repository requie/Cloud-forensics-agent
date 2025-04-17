"""
Base collector class for all data collection modules.

This module defines the abstract base class that all data collectors must implement,
ensuring consistent interfaces and behavior across different cloud providers and
service models.
"""

import abc
import datetime
import hashlib
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

class BaseCollector(abc.ABC):
    """
    Abstract base class for all data collectors in the Cloud Forensics AI Agent.
    
    This class defines the common interface and functionality that all data
    collectors must implement, regardless of cloud provider or service model.
    """
    
    def __init__(self, case_id: str, evidence_storage_path: str):
        """
        Initialize the base collector.
        
        Args:
            case_id: Unique identifier for the forensic case
            evidence_storage_path: Path where collected evidence will be stored
        """
        self.case_id = case_id
        self.evidence_storage_path = evidence_storage_path
        self.collector_id = str(uuid.uuid4())
        self.collection_start_time = None
        self.collection_end_time = None
        self.chain_of_custody = []
        
        # Ensure evidence storage path exists
        os.makedirs(evidence_storage_path, exist_ok=True)
        
        logger.info(f"Initialized collector {self.collector_id} for case {case_id}")
    
    @abc.abstractmethod
    def collect(self, *args, **kwargs) -> Dict[str, Any]:
        """
        Collect evidence from the target source.
        
        This method must be implemented by all concrete collector classes.
        
        Returns:
            A dictionary containing metadata about the collected evidence
        """
        pass
    
    def start_collection(self) -> None:
        """Record the start time of the collection process."""
        self.collection_start_time = datetime.datetime.utcnow()
        self._add_custody_event("Collection started")
    
    def end_collection(self) -> None:
        """Record the end time of the collection process."""
        self.collection_end_time = datetime.datetime.utcnow()
        self._add_custody_event("Collection completed")
    
    def _add_custody_event(self, event_description: str) -> None:
        """
        Add an event to the chain of custody.
        
        Args:
            event_description: Description of the custody event
        """
        event = {
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "collector_id": self.collector_id,
            "description": event_description
        }
        self.chain_of_custody.append(event)
        
        # Write chain of custody to file
        custody_file = os.path.join(
            self.evidence_storage_path, 
            f"{self.case_id}_chain_of_custody.json"
        )
        with open(custody_file, 'w') as f:
            json.dump(self.chain_of_custody, f, indent=2)
    
    def save_evidence(self, evidence_data: Any, evidence_type: str, 
                     source_identifier: str) -> str:
        """
        Save collected evidence to storage with proper metadata.
        
        Args:
            evidence_data: The actual evidence data to save
            evidence_type: Type of evidence (e.g., 'log', 'snapshot', 'config')
            source_identifier: Identifier for the source of the evidence
            
        Returns:
            Path to the saved evidence file
        """
        # Generate a unique filename
        timestamp = datetime.datetime.utcnow().strftime("%Y%m%d%H%M%S")
        filename = f"{self.case_id}_{evidence_type}_{source_identifier}_{timestamp}"
        
        # Determine file extension and save method based on evidence type
        if isinstance(evidence_data, (dict, list)):
            file_path = os.path.join(self.evidence_storage_path, f"{filename}.json")
            with open(file_path, 'w') as f:
                json.dump(evidence_data, f, indent=2)
        elif isinstance(evidence_data, str):
            file_path = os.path.join(self.evidence_storage_path, f"{filename}.txt")
            with open(file_path, 'w') as f:
                f.write(evidence_data)
        elif isinstance(evidence_data, bytes):
            file_path = os.path.join(self.evidence_storage_path, f"{filename}.bin")
            with open(file_path, 'wb') as f:
                f.write(evidence_data)
        else:
            raise TypeError(f"Unsupported evidence data type: {type(evidence_data)}")
        
        # Calculate hash of the evidence for integrity verification
        file_hash = self._calculate_file_hash(file_path)
        
        # Record in chain of custody
        self._add_custody_event(
            f"Evidence saved: {evidence_type} from {source_identifier} "
            f"to {file_path} with hash {file_hash}"
        )
        
        logger.info(f"Saved evidence to {file_path}")
        return file_path
    
    def _calculate_file_hash(self, file_path: str) -> str:
        """
        Calculate a SHA-256 hash of a file for integrity verification.
        
        Args:
            file_path: Path to the file to hash
            
        Returns:
            Hexadecimal string representation of the file hash
        """
        sha256_hash = hashlib.sha256()
        with open(file_path, "rb") as f:
            # Read and update hash in chunks for memory efficiency
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    
    def generate_collection_report(self) -> Dict[str, Any]:
        """
        Generate a report of the collection activity.
        
        Returns:
            Dictionary containing collection metadata and summary
        """
        if not self.collection_start_time or not self.collection_end_time:
            raise ValueError("Collection has not been completed")
        
        duration = (self.collection_end_time - self.collection_start_time).total_seconds()
        
        report = {
            "case_id": self.case_id,
            "collector_id": self.collector_id,
            "collector_type": self.__class__.__name__,
            "collection_start_time": self.collection_start_time.isoformat(),
            "collection_end_time": self.collection_end_time.isoformat(),
            "collection_duration_seconds": duration,
            "chain_of_custody": self.chain_of_custody
        }
        
        # Save report to file
        report_file = os.path.join(
            self.evidence_storage_path, 
            f"{self.case_id}_{self.collector_id}_collection_report.json"
        )
        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Generated collection report: {report_file}")
        return report
