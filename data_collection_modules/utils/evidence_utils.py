"""
Evidence collection utilities for maintaining forensic integrity.

This module provides utility functions for evidence collection, integrity verification,
and chain of custody maintenance across all collector modules.
"""

import datetime
import hashlib
import json
import logging
import os
import shutil
import tempfile
from typing import Any, Dict, List, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def create_forensic_copy(source_path: str, destination_path: str) -> Dict[str, str]:
    """
    Create a forensic copy of a file with integrity verification.
    
    Args:
        source_path: Path to the source file
        destination_path: Path where the copy should be stored
        
    Returns:
        Dictionary containing file metadata and hash information
    """
    # Calculate hash of source file before copying
    source_hash = calculate_file_hash(source_path)
    
    # Create copy
    shutil.copy2(source_path, destination_path)
    
    # Calculate hash of destination file after copying
    destination_hash = calculate_file_hash(destination_path)
    
    # Verify hashes match
    if source_hash != destination_hash:
        raise ValueError(f"Hash mismatch: Source {source_hash} != Destination {destination_hash}")
    
    # Get file metadata
    file_stats = os.stat(destination_path)
    
    metadata = {
        "source_path": source_path,
        "destination_path": destination_path,
        "file_size_bytes": file_stats.st_size,
        "hash_algorithm": "sha256",
        "file_hash": destination_hash,
        "copy_timestamp": datetime.datetime.utcnow().isoformat()
    }
    
    logger.info(f"Created forensic copy: {source_path} -> {destination_path}")
    return metadata

def calculate_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """
    Calculate a cryptographic hash of a file.
    
    Args:
        file_path: Path to the file to hash
        algorithm: Hash algorithm to use (default: sha256)
        
    Returns:
        Hexadecimal string representation of the file hash
    """
    if algorithm.lower() == "sha256":
        hash_obj = hashlib.sha256()
    elif algorithm.lower() == "sha1":
        hash_obj = hashlib.sha1()
    elif algorithm.lower() == "md5":
        hash_obj = hashlib.md5()
    else:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    with open(file_path, "rb") as f:
        # Read and update hash in chunks for memory efficiency
        for byte_block in iter(lambda: f.read(4096), b""):
            hash_obj.update(byte_block)
    
    return hash_obj.hexdigest()

def create_evidence_container(evidence_data: Any, metadata: Dict[str, Any], 
                             output_path: str) -> str:
    """
    Create a standardized evidence container with data and metadata.
    
    Args:
        evidence_data: The evidence data to store
        metadata: Metadata about the evidence
        output_path: Path where the container should be stored
        
    Returns:
        Path to the created evidence container
    """
    # Create a temporary directory for assembling the container
    with tempfile.TemporaryDirectory() as temp_dir:
        # Save evidence data
        if isinstance(evidence_data, (dict, list)):
            evidence_file = os.path.join(temp_dir, "evidence.json")
            with open(evidence_file, 'w') as f:
                json.dump(evidence_data, f, indent=2)
        elif isinstance(evidence_data, str):
            evidence_file = os.path.join(temp_dir, "evidence.txt")
            with open(evidence_file, 'w') as f:
                f.write(evidence_data)
        elif isinstance(evidence_data, bytes):
            evidence_file = os.path.join(temp_dir, "evidence.bin")
            with open(evidence_file, 'wb') as f:
                f.write(evidence_data)
        else:
            raise TypeError(f"Unsupported evidence data type: {type(evidence_data)}")
        
        # Calculate evidence hash
        evidence_hash = calculate_file_hash(evidence_file)
        
        # Add hash to metadata
        metadata["evidence_hash"] = evidence_hash
        metadata["evidence_hash_algorithm"] = "sha256"
        metadata["container_creation_time"] = datetime.datetime.utcnow().isoformat()
        
        # Save metadata
        metadata_file = os.path.join(temp_dir, "metadata.json")
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2)
        
        # Create archive of the evidence and metadata
        shutil.make_archive(output_path, 'zip', temp_dir)
    
    final_path = f"{output_path}.zip"
    logger.info(f"Created evidence container at {final_path}")
    return final_path

def validate_evidence_container(container_path: str) -> Dict[str, Any]:
    """
    Validate the integrity of an evidence container.
    
    Args:
        container_path: Path to the evidence container
        
    Returns:
        Dictionary with validation results
    """
    # Create a temporary directory for extracting the container
    with tempfile.TemporaryDirectory() as temp_dir:
        # Extract the container
        shutil.unpack_archive(container_path, temp_dir, 'zip')
        
        # Load metadata
        metadata_file = os.path.join(temp_dir, "metadata.json")
        if not os.path.exists(metadata_file):
            raise ValueError(f"Invalid evidence container: metadata.json not found")
        
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
        
        # Determine evidence file path based on type
        if os.path.exists(os.path.join(temp_dir, "evidence.json")):
            evidence_file = os.path.join(temp_dir, "evidence.json")
        elif os.path.exists(os.path.join(temp_dir, "evidence.txt")):
            evidence_file = os.path.join(temp_dir, "evidence.txt")
        elif os.path.exists(os.path.join(temp_dir, "evidence.bin")):
            evidence_file = os.path.join(temp_dir, "evidence.bin")
        else:
            raise ValueError(f"Invalid evidence container: evidence file not found")
        
        # Calculate evidence hash
        calculated_hash = calculate_file_hash(evidence_file)
        
        # Compare with stored hash
        hash_valid = calculated_hash == metadata.get("evidence_hash")
        
        validation_result = {
            "container_path": container_path,
            "metadata": metadata,
            "hash_valid": hash_valid,
            "stored_hash": metadata.get("evidence_hash"),
            "calculated_hash": calculated_hash,
            "validation_time": datetime.datetime.utcnow().isoformat()
        }
        
        logger.info(f"Validated evidence container {container_path}: {'Valid' if hash_valid else 'Invalid'}")
        return validation_result
