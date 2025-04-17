"""
Timeline analysis module for the Cloud Forensics AI Agent.

This module provides functionality for creating and analyzing event timelines
from collected cloud forensic evidence.
"""

import datetime
import json
import logging
import os
from typing import Any, Dict, List, Optional, Tuple, Union

from ..core.base_analyzer import BaseAnalyzer
from ..utils import analysis_utils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TimelineAnalyzer(BaseAnalyzer):
    """
    Analyzer for creating and analyzing event timelines from cloud forensic evidence.
    
    This analyzer processes various types of cloud logs and events to create
    a unified timeline, identify temporal patterns, and detect suspicious
    time-based activity.
    """
    
    def __init__(self, case_id: str, analysis_output_path: str):
        """
        Initialize the timeline analyzer.
        
        Args:
            case_id: Unique identifier for the forensic case
            analysis_output_path: Path where analysis results will be stored
        """
        super().__init__(case_id, analysis_output_path)
        logger.info(f"Initialized TimelineAnalyzer for case {case_id}")
    
    def analyze(self, evidence_data: Dict[str, Any], 
               time_field_mappings: Dict[str, str] = None,
               start_time: Union[str, datetime.datetime] = None,
               end_time: Union[str, datetime.datetime] = None,
               *args, **kwargs) -> Dict[str, Any]:
        """
        Analyze evidence data to create and analyze event timelines.
        
        Args:
            evidence_data: Dictionary containing evidence data to analyze
            time_field_mappings: Mapping of evidence types to timestamp field names
            start_time: Optional start time for timeline analysis
            end_time: Optional end time for timeline analysis
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
            
        Returns:
            Dictionary containing timeline analysis results
        """
        self.start_analysis()
        
        # Set analysis parameters
        parameters = {
            'time_field_mappings': time_field_mappings,
            'start_time': start_time.isoformat() if isinstance(start_time, datetime.datetime) else start_time,
            'end_time': end_time.isoformat() if isinstance(end_time, datetime.datetime) else end_time
        }
        self.set_parameters(parameters)
        
        try:
            # Extract events from evidence data
            events = self._extract_events(evidence_data, time_field_mappings)
            
            # Filter events by time range if specified
            if start_time or end_time:
                events = self._filter_events_by_time(events, start_time, end_time)
            
            # Sort events by timestamp
            timeline = self._create_timeline(events)
            
            # Identify time gaps and clusters
            time_gaps = self._identify_time_gaps(timeline)
            time_clusters = self._identify_time_clusters(timeline)
            
            # Identify suspicious time patterns
            suspicious_patterns = self._identify_suspicious_patterns(timeline)
            
            # Save results
            timeline_path = self.save_results(timeline, 'timeline')
            gaps_path = self.save_results(time_gaps, 'time_gaps')
            clusters_path = self.save_results(time_clusters, 'time_clusters')
            patterns_path = self.save_results(suspicious_patterns, 'suspicious_patterns')
            
            # Generate findings
            findings = []
            
            # Add findings for suspicious patterns
            for pattern in suspicious_patterns:
                findings.append({
                    'type': 'suspicious_time_pattern',
                    'severity': pattern.get('severity', 'medium'),
                    'description': pattern.get('description'),
                    'events': pattern.get('events'),
                    'confidence': pattern.get('confidence', 'medium')
                })
            
            # Add findings for significant time gaps
            for gap in time_gaps:
                if gap.get('duration_seconds', 0) > 3600:  # Gaps longer than 1 hour
                    findings.append({
                        'type': 'significant_time_gap',
                        'severity': 'low',
                        'description': f"Significant time gap of {gap.get('duration_seconds')} seconds between events",
                        'start_event': gap.get('start_event'),
                        'end_event': gap.get('end_event'),
                        'confidence': 'high'
                    })
            
            # Generate summary
            event_count = len(timeline)
            time_range = self._get_timeline_range(timeline)
            
            summary = (
                f"Timeline analysis identified {event_count} events between "
                f"{time_range.get('start_time')} and {time_range.get('end_time')}. "
                f"Analysis detected {len(suspicious_patterns)} suspicious time patterns and "
                f"{len(time_gaps)} significant time gaps."
            )
            
            # Generate report
            results_paths = [timeline_path, gaps_path, clusters_path, patterns_path]
            report = self.generate_analysis_report(results_paths, summary, findings)
            
            return {
                'timeline': timeline,
                'time_gaps': time_gaps,
                'time_clusters': time_clusters,
                'suspicious_patterns': suspicious_patterns,
                'findings': findings,
                'summary': summary,
                'report': report
            }
            
        except Exception as e:
            logger.error(f"Error in timeline analysis: {str(e)}")
            raise
            
        finally:
            self.end_analysis()
    
    def _extract_events(self, evidence_data: Dict[str, Any], 
                      time_field_mappings: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """
        Extract events from evidence data.
        
        Args:
            evidence_data: Dictionary containing evidence data
            time_field_mappings: Mapping of evidence types to timestamp field names
            
        Returns:
            List of event dictionaries with normalized timestamps
        """
        events = []
        
        # Default time field mappings if not provided
        if not time_field_mappings:
            time_field_mappings = {
                'aws_cloudtrail': 'eventTime',
                'aws_guardduty': 'createdAt',
                'aws_vpc_flow': 'start',
                'azure_activity_log': 'eventTimestamp',
                'azure_security_alert': 'alertTimeStamp',
                'gcp_audit_log': 'timestamp',
                'office365_audit': 'CreationTime',
                'gsuite_admin': 'id.time'
            }
        
        # Process each evidence type
        for evidence_type, evidence_items in evidence_data.items():
            if not isinstance(evidence_items, list):
                # Skip non-list evidence items
                continue
            
            # Get the timestamp field for this evidence type
            time_field = None
            for mapping_key, field_name in time_field_mappings.items():
                if mapping_key in evidence_type.lower():
                    time_field = field_name
                    break
            
            if not time_field:
                # Try to infer timestamp field
                common_time_fields = ['timestamp', 'time', 'eventTime', 'createdAt', 'date', 'eventDate']
                for item in evidence_items[:1]:  # Check first item
                    if isinstance(item, dict):
                        for field in common_time_fields:
                            if field in item:
                                time_field = field
                                break
            
            if not time_field:
                logger.warning(f"Could not determine timestamp field for evidence type: {evidence_type}")
                continue
            
            # Extract events with timestamps
            for item in evidence_items:
                if not isinstance(item, dict):
                    continue
                
                # Extract timestamp using dot notation
                timestamp_value = None
                if '.' in time_field:
                    parts = time_field.split('.')
                    current = item
                    try:
                        for part in parts:
                            current = current.get(part)
                        timestamp_value = current
                    except (AttributeError, TypeError):
                        pass
                else:
                    timestamp_value = item.get(time_field)
                
                if not timestamp_value:
                    continue
                
                try:
                    # Normalize timestamp
                    normalized_time = analysis_utils.normalize_timestamp(timestamp_value)
                    
                    # Create event with normalized timestamp
                    event = {
                        'timestamp': normalized_time.isoformat(),
                        'timestamp_original': timestamp_value,
                        'evidence_type': evidence_type,
                        'event_data': item
                    }
                    
                    events.append(event)
                    
                except (ValueError, TypeError) as e:
                    logger.warning(f"Could not normalize timestamp '{timestamp_value}': {str(e)}")
        
        return events
    
    def _filter_events_by_time(self, events: List[Dict[str, Any]],
                             start_time: Union[str, datetime.datetime] = None,
                             end_time: Union[str, datetime.datetime] = None) -> List[Dict[str, Any]]:
        """
        Filter events by time range.
        
        Args:
            events: List of event dictionaries
            start_time: Optional start time for filtering
            end_time: Optional end time for filtering
            
        Returns:
            Filtered list of events
        """
        if not start_time and not end_time:
            return events
        
        filtered_events = []
        
        # Normalize start and end times if provided
        norm_start = analysis_utils.normalize_timestamp(start_time) if start_time else None
        norm_end = analysis_utils.normalize_timestamp(end_time) if end_time else None
        
        for event in events:
            event_time = analysis_utils.normalize_timestamp(event['timestamp'])
            
            # Check if event is within time range
            if norm_start and event_time < norm_start:
                continue
            if norm_end and event_time > norm_end:
                continue
            
            filtered_events.append(event)
        
        return filtered_events
    
    def _create_timeline(self, events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Create a sorted timeline from events.
        
        Args:
            events: List of event dictionaries
            
        Returns:
            List of events sorted by timestamp
        """
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda e: analysis_utils.normalize_timestamp(e['timestamp']))
        
        # Add sequence numbers
        for i, event in enumerate(sorted_events):
            event['sequence_number'] = i + 1
        
        return sorted_events
    
    def _identify_time_gaps(self, timeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identify significant time gaps in the timeline.
        
        Args:
            timeline: List of events sorted by timestamp
            
        Returns:
            List of time gaps with metadata
        """
        time_gaps = []
        
        if len(timeline) < 2:
            return time_gaps
        
        # Calculate time differences between consecutive events
        for i in range(1, len(timeline)):
            prev_event = timeline[i-1]
            curr_event = timeline[i]
            
            prev_time = analysis_utils.normalize_timestamp(prev_event['timestamp'])
            curr_time = analysis_utils.normalize_timestamp(curr_event['timestamp'])
            
            # Calculate time difference in seconds
            time_diff = (curr_time - prev_time).total_seconds()
            
            # Identify significant gaps (more than 5 minutes)
            if time_diff > 300:
                time_gaps.append({
                    'start_event': prev_event,
                    'end_event': curr_event,
                    'start_time': prev_time.isoformat(),
                    'end_time': curr_time.isoformat(),
                    'duration_seconds': time_diff
                })
        
        return time_gaps
    
    def _identify_time_clusters(self, timeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identify clusters of events that occur close together in time.
        
        Args:
            timeline: List of events sorted by timestamp
            
        Returns:
            List of time clusters with metadata
        """
        time_clusters = []
        
        if len(timeline) < 3:
            return time_clusters
        
        # Parameters for clustering
        cluster_threshold = 60  # Maximum seconds between events in a cluster
        min_cluster_size = 3    # Minimum number of events to form a cluster
        
        current_cluster = []
        
        for i in range(1, len(timeline)):
            prev_event = timeline[i-1]
            curr_event = timeline[i]
            
            prev_time = analysis_utils.normalize_timestamp(prev_event['timestamp'])
            curr_time = analysis_utils.normalize_timestamp(curr_event['timestamp'])
            
            # Calculate time difference in seconds
            time_diff = (curr_time - prev_time).total_seconds()
            
            # Check if events are close enough to be in the same cluster
            if time_diff <= cluster_threshold:
                if not current_cluster:
                    current_cluster = [prev_event, curr_event]
                else:
                    current_cluster.append(curr_event)
            else:
                # End of cluster
                if len(current_cluster) >= min_cluster_size:
                    # Calculate cluster metadata
                    start_time = analysis_utils.normalize_timestamp(current_cluster[0]['timestamp'])
                    end_time = analysis_utils.normalize_timestamp(current_cluster[-1]['timestamp'])
                    duration = (end_time - start_time).total_seconds()
                    
                    time_clusters.append({
                        'events': current_cluster,
                        'event_count': len(current_cluster),
                        'start_time': start_time.isoformat(),
                        'end_time': end_time.isoformat(),
                        'duration_seconds': duration,
                        'events_per_second': len(current_cluster) / max(1, duration)
                    })
                
                # Start a new cluster
                current_cluster = [curr_event]
        
        # Check if the last cluster is valid
        if len(current_cluster) >= min_cluster_size:
            start_time = analysis_utils.normalize_timestamp(current_cluster[0]['timestamp'])
            end_time = analysis_utils.normalize_timestamp(current_cluster[-1]['timestamp'])
            duration = (end_time - start_time).total_seconds()
            
            time_clusters.append({
                'events': current_cluster,
                'event_count': len(current_cluster),
                'start_time': start_time.isoformat(),
                'end_time': end_time.isoformat(),
                'duration_seconds': duration,
                'events_per_second': len(current_cluster) / max(1, duration)
            })
        
        return time_clusters
    
    def _identify_suspicious_patterns(self, timeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identify suspicious time patterns in the timeline.
        
        Args:
            timeline: List of events sorted by timestamp
            
        Returns:
            List of suspicious patterns with metadata
        """
        suspicious_patterns = []
        
        if len(timeline) < 2:
            return suspicious_patterns
        
        # Check for off-hours activity
        off_hours_events = self._identify_off_hours_activity(timeline)
        if off_hours_events:
            suspicious_patterns.append({
                'pattern_type': 'off_hours_activity',
                'description': 'Activity detected during off-hours (nights and weekends)',
                'events': off_hours_events,
                'event_count': len(off_hours_events),
                'severity': 'medium',
                'confidence': 'medium'
            })
        
        # Check for unusual event frequency
        unusual_frequency = self._identify_unusual_frequency(timeline)
        if unusual_frequency:
            suspicious_patterns.append({
                'pattern_type': 'unusual_frequency',
                'description': 'Unusual frequency of events detected',
                'events': unusual_frequency.get('events', []),
                'event_count': len(unusual_frequency.get('events', [])),
                'details': unusual_frequency.get('details', {}),
                'severity': 'high',
                'confidence': 'medium'
            })
        
        # Check for temporal proximity of different event types
        related_events = self._identify_related_events(timeline)
        for pattern in related_events:
            suspicious_patterns.append({
                'pattern_type': 'related_events',
                'description': pattern.get('description', 'Related events detected in close temporal proximity'),
                'events': pattern.get('events', []),
                'event_count': len(pattern.get('events', [])),
                'details': pattern.get('details', {}),
                'severity': pattern.get('severity', 'medium'),
                'confidence': pattern.get('confidence', 'medium')
            })
        
        return suspicious_patterns
    
    def _identify_off_hours_activity(self, timeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identify activity during off-hours (nights and weekends).
        
        Args:
            timeline: List of events sorted by timestamp
            
        Returns:
            List of events that occurred during off-hours
        """
        off_hours_events = []
        
        for event in timeline:
            event_time = analysis_utils.normalize_timestamp(event['timestamp'])
            
            # Check if event occurred during off-hours
            hour = event_time.hour
            weekday = event_time.weekday()  # 0-6, where 0 is Monday
            
            # Define off-hours: weekends or between 10 PM and 6 AM
            is_weekend = weekday >= 5  # Saturday or Sunday
            is_night = hour < 6 or hour >= 22
            
            if is_weekend or is_night:
                off_hours_events.append(event)
        
        return off_hours_events
    
    def _identify_unusual_frequency(self, timeline: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Identify unusual frequency of events.
        
        Args:
            timeline: List of events sorted by timestamp
            
        Returns:
            Dictionary with unusual frequency metadata
        """
        if len(timeline) < 10:
            return None
        
        # Calculate event frequency over time
        time_windows = []
        window_size = 3600  # 1 hour in seconds
        
        if len(timeline) < 2:
            return None
        
        start_time = analysis_utils.normalize_timestamp(timeline[0]['timestamp'])
        end_time = analysis_utils.normalize_timestamp(timeline[-1]['timestamp'])
        
        total_duration = (end_time - start_time).total_seconds()
        if total_duration <= 0:
            return None
        
        # Create time windows
        current_time = start_time
        while current_time < end_time:
            window_end = current_time + datetime.timedelta(seconds=window_size)
            
            # Count events in this window
            events_in_window = []
            for event in timeline:
                event_time = analysis_utils.normalize_timestamp(event['timestamp'])
                if current_time <= event_time < window_end:
                    events_in_window.append(event)
            
            if events_in_window:
                time_windows.append({
                    'start_time': current_time.isoformat(),
                    'end_time': window_end.isoformat(),
                    'event_count': len(events_in_window),
                    'events': events_in_window
                })
            
            current_time = window_end
        
        # Calculate average and standard deviation of event counts
        if not time_windows:
            return None
        
        event_counts = [window['event_count'] for window in time_windows]
        
        # Calculate statistics
        avg_count = sum(event_counts) / len(event_counts)
        
        # Calculate standard deviation
        variance = sum((count - avg_count) ** 2 for count in event_counts) / len(event_counts)
        std_dev = variance ** 0.5
        
        # Identify windows with unusual event counts (more than 2 standard deviations from mean)
        threshold = 2.0
        unusual_windows = []
        
        for window in time_windows:
            if std_dev > 0:
                z_score = abs(window['event_count'] - avg_count) / std_dev
                if z_score > threshold:
                    window['z_score'] = z_score
                    unusual_windows.append(window)
        
        if not unusual_windows:
            return None
        
        # Combine events from unusual windows
        all_unusual_events = []
        for window in unusual_windows:
            all_unusual_events.extend(window['events'])
        
        return {
            'events': all_unusual_events,
            'details': {
                'unusual_windows': unusual_windows,
                'average_events_per_window': avg_count,
                'standard_deviation': std_dev
            }
        }
    
    def _identify_related_events(self, timeline: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Identify related events based on temporal proximity.
        
        Args:
            timeline: List of events sorted by timestamp
            
        Returns:
            List of related event patterns
        """
        related_patterns = []
        
        # Define suspicious event type combinations
        suspicious_combinations = [
            {
                'types': ['aws_cloudtrail', 'aws_guardduty'],
                'description': 'GuardDuty alert closely following CloudTrail API activity',
                'max_seconds': 300,
                'severity': 'high',
                'confidence': 'high'
            },
            {
                'types': ['azure_activity_log', 'azure_security_alert'],
                'description': 'Azure Security Alert closely following Azure Activity Log entry',
                'max_seconds': 300,
                'severity': 'high',
                'confidence': 'high'
            },
            {
                'types': ['login', 'permission_change'],
                'description': 'Permission change closely following login event',
                'max_seconds': 600,
                'severity': 'high',
                'confidence': 'medium'
            },
            {
                'types': ['network_access', 'data_access'],
                'description': 'Data access closely following network access event',
                'max_seconds': 120,
                'severity': 'medium',
                'confidence': 'medium'
            }
        ]
        
        # Check each combination
        for combo in suspicious_combinations:
            combo_patterns = self._find_event_combinations(timeline, combo['types'], combo['max_seconds'])
            
            for pattern in combo_patterns:
                related_patterns.append({
                    'description': combo['description'],
                    'events': pattern,
                    'details': {
                        'types': combo['types'],
                        'max_seconds': combo['max_seconds']
                    },
                    'severity': combo['severity'],
                    'confidence': combo['confidence']
                })
        
        return related_patterns
    
    def _find_event_combinations(self, timeline: List[Dict[str, Any]], 
                               types: List[str], max_seconds: int) -> List[List[Dict[str, Any]]]:
        """
        Find combinations of events of specified types within a time window.
        
        Args:
            timeline: List of events sorted by timestamp
            types: List of event types to look for
            max_seconds: Maximum time window in seconds
            
        Returns:
            List of event combinations
        """
        combinations = []
        
        for i, event1 in enumerate(timeline):
            # Check if this event matches the first type
            if not any(t in event1['evidence_type'] for t in types):
                continue
            
            # Find matching events within the time window
            matching_events = [event1]
            event1_time = analysis_utils.normalize_timestamp(event1['timestamp'])
            
            # Look ahead for other event types
            for j in range(i+1, len(timeline)):
                event2 = timeline[j]
                event2_time = analysis_utils.normalize_timestamp(event2['timestamp'])
                
                # Check if within time window
                time_diff = (event2_time - event1_time).total_seconds()
                if time_diff > max_seconds:
                    break
                
                # Check if this event matches any of the required types
                if any(t in event2['evidence_type'] for t in types):
                    matching_events.append(event2)
            
            # Check if we found events for all required types
            found_types = set()
            for event in matching_events:
                for t in types:
                    if t in event['evidence_type']:
                        found_types.add(t)
            
            if len(found_types) == len(types):
                combinations.append(matching_events)
        
        return combinations
    
    def _get_timeline_range(self, timeline: List[Dict[str, Any]]) -> Dict[str, str]:
        """
        Get the time range of the timeline.
        
        Args:
            timeline: List of events sorted by timestamp
            
        Returns:
            Dictionary with start and end times
        """
        if not timeline:
            return {
                'start_time': None,
                'end_time': None
            }
        
        start_time = analysis_utils.normalize_timestamp(timeline[0]['timestamp'])
        end_time = analysis_utils.normalize_timestamp(timeline[-1]['timestamp'])
        
        return {
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat()
        }
