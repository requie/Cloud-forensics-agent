"""
Utility functions for analysis modules.

This module provides common utility functions used across different analysis modules
for processing evidence, handling data formats, and supporting analysis operations.
"""

import datetime
import hashlib
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def load_evidence_file(file_path: str) -> Any:
    """
    Load evidence data from a file.
    
    Args:
        file_path: Path to the evidence file
        
    Returns:
        The loaded evidence data
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Evidence file not found: {file_path}")
    
    file_ext = os.path.splitext(file_path)[1].lower()
    
    if file_ext == '.json':
        with open(file_path, 'r') as f:
            return json.load(f)
    elif file_ext in ['.txt', '.log']:
        with open(file_path, 'r') as f:
            return f.read()
    else:
        raise ValueError(f"Unsupported file format: {file_ext}")

def normalize_timestamp(timestamp: Union[str, int, float, datetime.datetime]) -> datetime.datetime:
    """
    Normalize different timestamp formats to a standard datetime object.
    
    Args:
        timestamp: Timestamp in various formats
        
    Returns:
        Normalized datetime object
    """
    if isinstance(timestamp, datetime.datetime):
        return timestamp
    
    if isinstance(timestamp, (int, float)):
        # Assume Unix timestamp
        return datetime.datetime.fromtimestamp(timestamp, tz=datetime.timezone.utc)
    
    if isinstance(timestamp, str):
        # Try different string formats
        formats_to_try = [
            # ISO 8601
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S%z",
            # Common log formats
            "%Y-%m-%d %H:%M:%S.%f",
            "%Y-%m-%d %H:%M:%S",
            "%Y/%m/%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",  # Apache log format
            "%b %d %H:%M:%S",  # Syslog format
            "%b %d %Y %H:%M:%S"  # Another common format
        ]
        
        for fmt in formats_to_try:
            try:
                dt = datetime.datetime.strptime(timestamp, fmt)
                # Add UTC timezone if not specified
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                return dt
            except ValueError:
                continue
        
        # If all formats fail, try parsing with dateutil
        try:
            from dateutil import parser
            dt = parser.parse(timestamp)
            # Add UTC timezone if not specified
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=datetime.timezone.utc)
            return dt
        except:
            raise ValueError(f"Could not parse timestamp: {timestamp}")
    
    raise TypeError(f"Unsupported timestamp type: {type(timestamp)}")

def extract_ip_addresses(text: str) -> List[str]:
    """
    Extract IP addresses from text.
    
    Args:
        text: Text to extract IP addresses from
        
    Returns:
        List of extracted IP addresses
    """
    # IPv4 pattern
    ipv4_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    # IPv6 pattern (simplified)
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    
    ipv4_addresses = re.findall(ipv4_pattern, text)
    ipv6_addresses = re.findall(ipv6_pattern, text)
    
    # Filter valid IPv4 addresses
    valid_ipv4 = []
    for ip in ipv4_addresses:
        octets = ip.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            valid_ipv4.append(ip)
    
    return valid_ipv4 + ipv6_addresses

def extract_urls(text: str) -> List[str]:
    """
    Extract URLs from text.
    
    Args:
        text: Text to extract URLs from
        
    Returns:
        List of extracted URLs
    """
    # URL pattern
    url_pattern = r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+(?:/[-\w%!$&\'()*+,;=:@/~]+)*(?:\?[-\w%!$&\'()*+,;=:@/~]*)?(?:#[-\w%!$&\'()*+,;=:@/~]*)?'
    
    return re.findall(url_pattern, text)

def calculate_file_hash(file_path: str, hash_type: str = 'sha256') -> str:
    """
    Calculate hash of a file.
    
    Args:
        file_path: Path to the file
        hash_type: Type of hash to calculate ('md5', 'sha1', 'sha256')
        
    Returns:
        Calculated hash as a hexadecimal string
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")
    
    if hash_type == 'md5':
        hash_func = hashlib.md5()
    elif hash_type == 'sha1':
        hash_func = hashlib.sha1()
    elif hash_type == 'sha256':
        hash_func = hashlib.sha256()
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            hash_func.update(chunk)
    
    return hash_func.hexdigest()

def find_common_elements(lists: List[List[Any]]) -> List[Any]:
    """
    Find common elements across multiple lists.
    
    Args:
        lists: List of lists to find common elements in
        
    Returns:
        List of common elements
    """
    if not lists:
        return []
    
    common = set(lists[0])
    for lst in lists[1:]:
        common.intersection_update(lst)
    
    return list(common)

def group_by_attribute(items: List[Dict[str, Any]], attribute: str) -> Dict[Any, List[Dict[str, Any]]]:
    """
    Group a list of dictionaries by a specific attribute.
    
    Args:
        items: List of dictionaries to group
        attribute: Attribute to group by
        
    Returns:
        Dictionary mapping attribute values to lists of items
    """
    result = {}
    
    for item in items:
        if attribute not in item:
            continue
        
        key = item[attribute]
        if key not in result:
            result[key] = []
        
        result[key].append(item)
    
    return result

def calculate_time_difference(time1: Union[str, datetime.datetime], 
                             time2: Union[str, datetime.datetime]) -> float:
    """
    Calculate the time difference between two timestamps in seconds.
    
    Args:
        time1: First timestamp
        time2: Second timestamp
        
    Returns:
        Time difference in seconds
    """
    dt1 = normalize_timestamp(time1)
    dt2 = normalize_timestamp(time2)
    
    return abs((dt2 - dt1).total_seconds())

def is_within_timeframe(timestamp: Union[str, datetime.datetime],
                       start_time: Union[str, datetime.datetime],
                       end_time: Union[str, datetime.datetime]) -> bool:
    """
    Check if a timestamp is within a specified timeframe.
    
    Args:
        timestamp: Timestamp to check
        start_time: Start of timeframe
        end_time: End of timeframe
        
    Returns:
        True if timestamp is within timeframe, False otherwise
    """
    dt = normalize_timestamp(timestamp)
    start = normalize_timestamp(start_time)
    end = normalize_timestamp(end_time)
    
    return start <= dt <= end

def extract_json_fields(json_data: Dict[str, Any], field_paths: List[str]) -> Dict[str, Any]:
    """
    Extract specific fields from a JSON object using dot notation paths.
    
    Args:
        json_data: JSON data to extract fields from
        field_paths: List of field paths in dot notation (e.g., 'user.name')
        
    Returns:
        Dictionary mapping field paths to extracted values
    """
    result = {}
    
    for path in field_paths:
        parts = path.split('.')
        current = json_data
        
        try:
            for part in parts:
                if isinstance(current, dict):
                    current = current.get(part)
                elif isinstance(current, list) and part.isdigit():
                    current = current[int(part)]
                else:
                    current = None
                    break
            
            result[path] = current
        except (KeyError, IndexError, TypeError):
            result[path] = None
    
    return result

def filter_events_by_criteria(events: List[Dict[str, Any]], criteria: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Filter a list of events based on specified criteria.
    
    Args:
        events: List of event dictionaries
        criteria: Dictionary mapping field names to required values
        
    Returns:
        Filtered list of events
    """
    filtered_events = []
    
    for event in events:
        matches = True
        
        for field, value in criteria.items():
            if field not in event or event[field] != value:
                matches = False
                break
        
        if matches:
            filtered_events.append(event)
    
    return filtered_events

def merge_events(events1: List[Dict[str, Any]], events2: List[Dict[str, Any]], 
                key_field: str) -> List[Dict[str, Any]]:
    """
    Merge two lists of events based on a common key field.
    
    Args:
        events1: First list of event dictionaries
        events2: Second list of event dictionaries
        key_field: Field to use as the merge key
        
    Returns:
        Merged list of events
    """
    # Create a dictionary of events from the first list
    events_dict = {event.get(key_field): event for event in events1 if key_field in event}
    
    # Merge events from the second list
    for event in events2:
        if key_field not in event:
            continue
        
        key = event.get(key_field)
        if key in events_dict:
            # Merge the event data
            merged_event = {**events_dict[key], **event}
            events_dict[key] = merged_event
        else:
            events_dict[key] = event
    
    return list(events_dict.values())

def detect_outliers(values: List[float], method: str = 'iqr', threshold: float = 1.5) -> List[int]:
    """
    Detect outliers in a list of numeric values.
    
    Args:
        values: List of numeric values
        method: Method to use for outlier detection ('iqr' or 'zscore')
        threshold: Threshold for outlier detection
        
    Returns:
        List of indices of outlier values
    """
    if not values:
        return []
    
    if method == 'iqr':
        # Interquartile Range method
        values_sorted = sorted(values)
        q1_idx = int(len(values) * 0.25)
        q3_idx = int(len(values) * 0.75)
        
        q1 = values_sorted[q1_idx]
        q3 = values_sorted[q3_idx]
        iqr = q3 - q1
        
        lower_bound = q1 - threshold * iqr
        upper_bound = q3 + threshold * iqr
        
        outliers = [i for i, v in enumerate(values) if v < lower_bound or v > upper_bound]
    
    elif method == 'zscore':
        # Z-score method
        import numpy as np
        
        mean = np.mean(values)
        std = np.std(values)
        
        if std == 0:
            return []
        
        zscores = [(v - mean) / std for v in values]
        outliers = [i for i, z in enumerate(zscores) if abs(z) > threshold]
    
    else:
        raise ValueError(f"Unsupported outlier detection method: {method}")
    
    return outliers
