"""
Anomaly detection module for the Cloud Forensics AI Agent.

This module provides functionality for detecting anomalies in cloud forensic evidence
using statistical and machine learning approaches.
"""

import datetime
import json
import logging
import os
import numpy as np
from typing import Any, Dict, List, Optional, Tuple, Union

from ..core.base_analyzer import BaseAnalyzer
from ..utils import analysis_utils

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class AnomalyDetector(BaseAnalyzer):
    """
    Analyzer for detecting anomalies in cloud forensic evidence.
    
    This analyzer uses statistical and machine learning approaches to identify
    anomalous behavior, events, and patterns that may indicate security incidents.
    """
    
    def __init__(self, case_id: str, analysis_output_path: str):
        """
        Initialize the anomaly detector.
        
        Args:
            case_id: Unique identifier for the forensic case
            analysis_output_path: Path where analysis results will be stored
        """
        super().__init__(case_id, analysis_output_path)
        logger.info(f"Initialized AnomalyDetector for case {case_id}")
    
    def analyze(self, evidence_data: Dict[str, Any], 
               baseline_data: Dict[str, Any] = None,
               sensitivity: str = 'medium',
               *args, **kwargs) -> Dict[str, Any]:
        """
        Analyze evidence data to detect anomalies.
        
        Args:
            evidence_data: Dictionary containing evidence data to analyze
            baseline_data: Optional baseline data for comparison
            sensitivity: Sensitivity level for anomaly detection ('low', 'medium', 'high')
            *args: Additional positional arguments
            **kwargs: Additional keyword arguments
            
        Returns:
            Dictionary containing anomaly detection results
        """
        self.start_analysis()
        
        # Set analysis parameters
        parameters = {
            'has_baseline': baseline_data is not None,
            'sensitivity': sensitivity
        }
        self.set_parameters(parameters)
        
        try:
            # Convert sensitivity to numerical threshold
            threshold = self._get_threshold_from_sensitivity(sensitivity)
            
            # Detect statistical anomalies
            statistical_anomalies = self._detect_statistical_anomalies(evidence_data, baseline_data, threshold)
            
            # Detect behavioral anomalies
            behavioral_anomalies = self._detect_behavioral_anomalies(evidence_data, baseline_data, threshold)
            
            # Detect temporal anomalies
            temporal_anomalies = self._detect_temporal_anomalies(evidence_data, threshold)
            
            # Detect access anomalies
            access_anomalies = self._detect_access_anomalies(evidence_data, baseline_data, threshold)
            
            # Detect network anomalies
            network_anomalies = self._detect_network_anomalies(evidence_data, threshold)
            
            # Save results
            statistical_path = self.save_results(statistical_anomalies, 'statistical_anomalies')
            behavioral_path = self.save_results(behavioral_anomalies, 'behavioral_anomalies')
            temporal_path = self.save_results(temporal_anomalies, 'temporal_anomalies')
            access_path = self.save_results(access_anomalies, 'access_anomalies')
            network_path = self.save_results(network_anomalies, 'network_anomalies')
            
            # Generate findings
            findings = []
            
            # Add findings for statistical anomalies
            for anomaly in statistical_anomalies:
                findings.append({
                    'type': 'statistical_anomaly',
                    'severity': anomaly.get('severity', 'medium'),
                    'description': anomaly.get('description'),
                    'evidence_type': anomaly.get('evidence_type'),
                    'confidence': anomaly.get('confidence', 'medium'),
                    'anomaly_score': anomaly.get('anomaly_score')
                })
            
            # Add findings for behavioral anomalies
            for anomaly in behavioral_anomalies:
                findings.append({
                    'type': 'behavioral_anomaly',
                    'severity': anomaly.get('severity', 'medium'),
                    'description': anomaly.get('description'),
                    'affected_entities': anomaly.get('affected_entities', []),
                    'confidence': anomaly.get('confidence', 'medium'),
                    'anomaly_score': anomaly.get('anomaly_score')
                })
            
            # Add findings for temporal anomalies
            for anomaly in temporal_anomalies:
                findings.append({
                    'type': 'temporal_anomaly',
                    'severity': anomaly.get('severity', 'medium'),
                    'description': anomaly.get('description'),
                    'time_period': anomaly.get('time_period'),
                    'confidence': anomaly.get('confidence', 'medium'),
                    'anomaly_score': anomaly.get('anomaly_score')
                })
            
            # Add findings for access anomalies
            for anomaly in access_anomalies:
                findings.append({
                    'type': 'access_anomaly',
                    'severity': anomaly.get('severity', 'high'),
                    'description': anomaly.get('description'),
                    'affected_resources': anomaly.get('affected_resources', []),
                    'confidence': anomaly.get('confidence', 'medium'),
                    'anomaly_score': anomaly.get('anomaly_score')
                })
            
            # Add findings for network anomalies
            for anomaly in network_anomalies:
                findings.append({
                    'type': 'network_anomaly',
                    'severity': anomaly.get('severity', 'high'),
                    'description': anomaly.get('description'),
                    'affected_resources': anomaly.get('affected_resources', []),
                    'confidence': anomaly.get('confidence', 'medium'),
                    'anomaly_score': anomaly.get('anomaly_score')
                })
            
            # Generate summary
            total_anomalies = (
                len(statistical_anomalies) + 
                len(behavioral_anomalies) + 
                len(temporal_anomalies) + 
                len(access_anomalies) + 
                len(network_anomalies)
            )
            
            summary = (
                f"Anomaly detection identified {total_anomalies} anomalies across the evidence. "
                f"Analysis found {len(statistical_anomalies)} statistical anomalies, "
                f"{len(behavioral_anomalies)} behavioral anomalies, "
                f"{len(temporal_anomalies)} temporal anomalies, "
                f"{len(access_anomalies)} access anomalies, and "
                f"{len(network_anomalies)} network anomalies."
            )
            
            # Generate report
            results_paths = [statistical_path, behavioral_path, temporal_path, access_path, network_path]
            report = self.generate_analysis_report(results_paths, summary, findings)
            
            return {
                'statistical_anomalies': statistical_anomalies,
                'behavioral_anomalies': behavioral_anomalies,
                'temporal_anomalies': temporal_anomalies,
                'access_anomalies': access_anomalies,
                'network_anomalies': network_anomalies,
                'findings': findings,
                'summary': summary,
                'report': report
            }
            
        except Exception as e:
            logger.error(f"Error in anomaly detection: {str(e)}")
            raise
            
        finally:
            self.end_analysis()
    
    def _get_threshold_from_sensitivity(self, sensitivity: str) -> float:
        """
        Convert sensitivity level to numerical threshold.
        
        Args:
            sensitivity: Sensitivity level ('low', 'medium', 'high')
            
        Returns:
            Numerical threshold value
        """
        if sensitivity.lower() == 'low':
            return 3.0  # Less sensitive, higher threshold
        elif sensitivity.lower() == 'high':
            return 1.5  # More sensitive, lower threshold
        else:  # medium
            return 2.0
    
    def _detect_statistical_anomalies(self, evidence_data: Dict[str, Any], 
                                    baseline_data: Dict[str, Any] = None,
                                    threshold: float = 2.0) -> List[Dict[str, Any]]:
        """
        Detect statistical anomalies in evidence data.
        
        Args:
            evidence_data: Dictionary containing evidence data
            baseline_data: Optional baseline data for comparison
            threshold: Threshold for anomaly detection
            
        Returns:
            List of statistical anomaly dictionaries
        """
        anomalies = []
        
        # Process each evidence type
        for evidence_type, evidence_items in evidence_data.items():
            if not isinstance(evidence_items, list) or not evidence_items:
                continue
            
            # Get baseline data for this evidence type if available
            baseline_items = None
            if baseline_data and evidence_type in baseline_data:
                baseline_items = baseline_data[evidence_type]
            
            # Extract numerical features for statistical analysis
            features = self._extract_numerical_features(evidence_items)
            
            if not features:
                continue
            
            # Calculate statistics for each feature
            for feature_name, feature_values in features.items():
                # Skip features with insufficient data
                if len(feature_values) < 5:
                    continue
                
                # Calculate mean and standard deviation
                mean = np.mean(feature_values)
                std_dev = np.std(feature_values)
                
                if std_dev == 0:
                    continue
                
                # Compare with baseline if available
                baseline_mean = None
                baseline_std = None
                
                if baseline_items:
                    baseline_features = self._extract_numerical_features(baseline_items)
                    if feature_name in baseline_features:
                        baseline_values = baseline_features[feature_name]
                        if len(baseline_values) >= 5:
                            baseline_mean = np.mean(baseline_values)
                            baseline_std = np.std(baseline_values)
                
                # Detect anomalies
                anomalous_values = []
                anomalous_indices = []
                
                for i, value in enumerate(feature_values):
                    # Calculate z-score
                    z_score = abs((value - mean) / std_dev)
                    
                    # Check if value is anomalous
                    if z_score > threshold:
                        anomalous_values.append(value)
                        anomalous_indices.append(i)
                
                if anomalous_values:
                    # Calculate anomaly score
                    max_z_score = max(abs((value - mean) / std_dev) for value in anomalous_values)
                    anomaly_score = min(1.0, max_z_score / (threshold * 2))
                    
                    # Determine severity based on anomaly score
                    severity = 'low'
                    if anomaly_score > 0.7:
                        severity = 'high'
                    elif anomaly_score > 0.4:
                        severity = 'medium'
                    
                    # Create anomaly record
                    anomaly = {
                        'evidence_type': evidence_type,
                        'feature': feature_name,
                        'description': f"Statistical anomaly detected in {feature_name} values",
                        'anomalous_values': anomalous_values,
                        'mean': float(mean),
                        'std_dev': float(std_dev),
                        'threshold': threshold,
                        'anomaly_score': float(anomaly_score),
                        'severity': severity,
                        'confidence': 'high',
                        'anomalous_items': [evidence_items[i] for i in anomalous_indices if i < len(evidence_items)]
                    }
                    
                    # Add baseline comparison if available
                    if baseline_mean is not None and baseline_std is not None:
                        anomaly['baseline_mean'] = float(baseline_mean)
                        anomaly['baseline_std_dev'] = float(baseline_std)
                        
                        # Calculate distribution shift
                        distribution_shift = abs((mean - baseline_mean) / baseline_std)
                        anomaly['distribution_shift'] = float(distribution_shift)
                        
                        if distribution_shift > threshold:
                            anomaly['description'] = f"Statistical anomaly detected in {feature_name} values with significant shift from baseline"
                    
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _extract_numerical_features(self, items: List[Dict[str, Any]]) -> Dict[str, List[float]]:
        """
        Extract numerical features from evidence items.
        
        Args:
            items: List of evidence item dictionaries
            
        Returns:
            Dictionary mapping feature names to lists of numerical values
        """
        features = {}
        
        # Skip if items is not a list of dictionaries
        if not items or not isinstance(items[0], dict):
            return features
        
        # Identify numerical fields in the first item
        numerical_fields = []
        for field, value in self._flatten_dict(items[0]).items():
            if isinstance(value, (int, float)) and not isinstance(value, bool):
                numerical_fields.append(field)
        
        # Extract values for each numerical field
        for field in numerical_fields:
            values = []
            
            for item in items:
                flat_item = self._flatten_dict(item)
                if field in flat_item and isinstance(flat_item[field], (int, float)) and not isinstance(flat_item[field], bool):
                    values.append(float(flat_item[field]))
            
            if values:
                features[field] = values
        
        return features
    
    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '') -> Dict[str, Any]:
        """
        Flatten a nested dictionary.
        
        Args:
            d: Dictionary to flatten
            parent_key: Parent key for nested dictionaries
            
        Returns:
            Flattened dictionary
        """
        items = []
        
        for k, v in d.items():
            new_key = f"{parent_key}.{k}" if parent_key else k
            
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key).items())
            else:
                items.append((new_key, v))
        
        return dict(items)
    
    def _detect_behavioral_anomalies(self, evidence_data: Dict[str, Any], 
                                   baseline_data: Dict[str, Any] = None,
                                   threshold: float = 2.0) -> List[Dict[str, Any]]:
        """
        Detect behavioral anomalies in evidence data.
        
        Args:
            evidence_data: Dictionary containing evidence data
            baseline_data: Optional baseline data for comparison
            threshold: Threshold for anomaly detection
            
        Returns:
            List of behavioral anomaly dictionaries
        """
        anomalies = []
        
        # Extract user activities
        user_activities = self._extract_user_activities(evidence_data)
        
        # Get baseline user activities if available
        baseline_activities = {}
        if baseline_data:
            baseline_activities = self._extract_user_activities(baseline_data)
        
        # Analyze each user's activities
        for user, activities in user_activities.items():
            # Skip users with insufficient data
            if len(activities) < 5:
                continue
            
            # Get baseline activities for this user if available
            user_baseline = None
            if user in baseline_activities:
                user_baseline = baseline_activities[user]
            
            # Detect anomalies in activity types
            activity_types = {}
            for activity in activities:
                activity_type = activity.get('activity_type')
                if activity_type:
                    if activity_type not in activity_types:
                        activity_types[activity_type] = 0
                    activity_types[activity_type] += 1
            
            # Compare with baseline if available
            if user_baseline:
                baseline_types = {}
                for activity in user_baseline:
                    activity_type = activity.get('activity_type')
                    if activity_type:
                        if activity_type not in baseline_types:
                            baseline_types[activity_type] = 0
                        baseline_types[activity_type] += 1
                
                # Check for new activity types
                new_activity_types = []
                for activity_type in activity_types:
                    if activity_type not in baseline_types:
                        new_activity_types.append(activity_type)
                
                if new_activity_types:
                    anomaly = {
                        'type': 'new_activity_types',
                        'description': f"User {user} performed new types of activities not seen in baseline",
                        'user': user,
                        'new_activity_types': new_activity_types,
                        'affected_entities': [user],
                        'anomaly_score': 0.8,
                        'severity': 'high',
                        'confidence': 'medium',
                        'activities': [a for a in activities if a.get('activity_type') in new_activity_types]
                    }
                    anomalies.append(anomaly)
                
                # Check for significant changes in activity frequencies
                for activity_type, count in activity_types.items():
                    if activity_type in baseline_types:
                        baseline_count = baseline_types[activity_type]
                        
                        # Calculate relative change
                        if baseline_count > 0:
                            relative_change = abs(count - baseline_count) / baseline_count
                            
                            if relative_change > 1.0:  # More than 100% change
                                anomaly = {
                                    'type': 'activity_frequency_change',
                                    'description': f"Significant change in frequency of {activity_type} activities for user {user}",
                                    'user': user,
                                    'activity_type': activity_type,
                                    'current_count': count,
                                    'baseline_count': baseline_count,
                                    'relative_change': float(relative_change),
                                    'affected_entities': [user],
                                    'anomaly_score': min(1.0, relative_change / 3.0),
                                    'severity': 'medium',
                                    'confidence': 'medium',
                                    'activities': [a for a in activities if a.get('activity_type') == activity_type]
                                }
                                anomalies.append(anomaly)
            
            # Detect unusual activity patterns
            activity_hours = {}
            for activity in activities:
                timestamp = activity.get('timestamp')
                if timestamp:
                    try:
                        dt = analysis_utils.normalize_timestamp(timestamp)
                        hour = dt.hour
                        
                        if hour not in activity_hours:
                            activity_hours[hour] = 0
                        activity_hours[hour] += 1
                    except (ValueError, TypeError):
                        pass
            
            # Check for activities during unusual hours (11 PM - 5 AM)
            unusual_hours = [23, 0, 1, 2, 3, 4]
            unusual_hour_activities = []
            
            for hour in unusual_hours:
                if hour in activity_hours:
                    unusual_hour_activities.extend([
                        a for a in activities 
                        if a.get('timestamp') and 
                        analysis_utils.normalize_timestamp(a.get('timestamp')).hour == hour
                    ])
            
            if unusual_hour_activities:
                anomaly = {
                    'type': 'unusual_hours',
                    'description': f"User {user} performed activities during unusual hours (11 PM - 5 AM)",
                    'user': user,
                    'affected_entities': [user],
                    'anomaly_score': 0.7,
                    'severity': 'medium',
                    'confidence': 'medium',
                    'activities': unusual_hour_activities
                }
                anomalies.append(anomaly)
        
        return anomalies
    
    def _extract_user_activities(self, evidence_data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract user activities from evidence data.
        
        Args:
            evidence_data: Dictionary containing evidence data
            
        Returns:
            Dictionary mapping users to lists of activity dictionaries
        """
        user_activities = {}
        
        # Process each evidence type
        for evidence_type, evidence_items in evidence_data.items():
            if not isinstance(evidence_items, list):
                continue
            
            for item in evidence_items:
                if not isinstance(item, dict):
                    continue
                
                # Extract user and activity information based on evidence type
                user = None
                timestamp = None
                activity_type = None
                
                if 'aws_cloudtrail' in evidence_type:
                    user = item.get('userIdentity', {}).get('arn')
                    timestamp = item.get('eventTime')
                    activity_type = item.get('eventName')
                
                elif 'azure_activity_log' in evidence_type:
                    user = item.get('caller')
                    timestamp = item.get('eventTimestamp')
                    activity_type = item.get('operationName')
                
                elif 'gcp_audit_log' in evidence_type:
                    user = item.get('protoPayload', {}).get('authenticationInfo', {}).get('principalEmail')
                    timestamp = item.get('timestamp')
                    activity_type = item.get('protoPayload', {}).get('methodName')
                
                elif 'office365_audit' in evidence_type:
                    user = item.get('UserId')
                    timestamp = item.get('CreationTime')
                    activity_type = item.get('Operation')
                
                elif 'gsuite_admin' in evidence_type:
                    user = item.get('actor', {}).get('email')
                    timestamp = item.get('id', {}).get('time')
                    activity_type = item.get('events', {}).get('name')
                
                # Skip if missing essential information
                if not user or not timestamp or not activity_type:
                    continue
                
                # Add activity to user's activities
                if user not in user_activities:
                    user_activities[user] = []
                
                user_activities[user].append({
                    'evidence_type': evidence_type,
                    'timestamp': timestamp,
                    'activity_type': activity_type,
                    'evidence_item': item
                })
        
        return user_activities
    
    def _detect_temporal_anomalies(self, evidence_data: Dict[str, Any], 
                                 threshold: float = 2.0) -> List[Dict[str, Any]]:
        """
        Detect temporal anomalies in evidence data.
        
        Args:
            evidence_data: Dictionary containing evidence data
            threshold: Threshold for anomaly detection
            
        Returns:
            List of temporal anomaly dictionaries
        """
        anomalies = []
        
        # Extract all events with timestamps
        events = []
        
        for evidence_type, evidence_items in evidence_data.items():
            if not isinstance(evidence_items, list):
                continue
            
            for item in evidence_items:
                if not isinstance(item, dict):
                    continue
                
                # Extract timestamp based on evidence type
                timestamp = None
                
                if 'aws_cloudtrail' in evidence_type:
                    timestamp = item.get('eventTime')
                elif 'azure_activity_log' in evidence_type:
                    timestamp = item.get('eventTimestamp')
                elif 'gcp_audit_log' in evidence_type:
                    timestamp = item.get('timestamp')
                elif 'office365_audit' in evidence_type:
                    timestamp = item.get('CreationTime')
                elif 'gsuite_admin' in evidence_type:
                    timestamp = item.get('id', {}).get('time')
                else:
                    # Try common timestamp fields
                    for field in ['timestamp', 'time', 'eventTime', 'createdAt', 'date']:
                        if field in item:
                            timestamp = item[field]
                            break
                
                if timestamp:
                    try:
                        dt = analysis_utils.normalize_timestamp(timestamp)
                        events.append({
                            'timestamp': dt,
                            'evidence_type': evidence_type,
                            'evidence_item': item
                        })
                    except (ValueError, TypeError):
                        pass
        
        # Sort events by timestamp
        events.sort(key=lambda e: e['timestamp'])
        
        if len(events) < 10:
            return anomalies
        
        # Analyze event frequency over time
        time_windows = []
        window_size = 3600  # 1 hour in seconds
        
        start_time = events[0]['timestamp']
        end_time = events[-1]['timestamp']
        
        current_time = start_time
        while current_time < end_time:
            window_end = current_time + datetime.timedelta(seconds=window_size)
            
            # Count events in this window
            events_in_window = []
            for event in events:
                if current_time <= event['timestamp'] < window_end:
                    events_in_window.append(event)
            
            time_windows.append({
                'start_time': current_time,
                'end_time': window_end,
                'event_count': len(events_in_window),
                'events': events_in_window
            })
            
            current_time = window_end
        
        # Calculate average and standard deviation of event counts
        event_counts = [window['event_count'] for window in time_windows]
        
        if not event_counts:
            return anomalies
        
        mean_count = np.mean(event_counts)
        std_dev = np.std(event_counts)
        
        if std_dev == 0:
            return anomalies
        
        # Identify windows with unusual event counts
        for window in time_windows:
            z_score = abs(window['event_count'] - mean_count) / std_dev
            
            if z_score > threshold:
                # Calculate anomaly score
                anomaly_score = min(1.0, z_score / (threshold * 2))
                
                # Determine severity based on anomaly score
                severity = 'low'
                if anomaly_score > 0.7:
                    severity = 'high'
                elif anomaly_score > 0.4:
                    severity = 'medium'
                
                description = "Unusually high event frequency detected" if window['event_count'] > mean_count else "Unusually low event frequency detected"
                
                anomaly = {
                    'type': 'event_frequency',
                    'description': description,
                    'time_period': {
                        'start': window['start_time'].isoformat(),
                        'end': window['end_time'].isoformat()
                    },
                    'event_count': window['event_count'],
                    'average_count': float(mean_count),
                    'z_score': float(z_score),
                    'anomaly_score': float(anomaly_score),
                    'severity': severity,
                    'confidence': 'medium',
                    'events': [e['evidence_item'] for e in window['events']]
                }
                
                anomalies.append(anomaly)
        
        # Detect unusual time gaps between events
        time_gaps = []
        
        for i in range(1, len(events)):
            prev_event = events[i-1]
            curr_event = events[i]
            
            time_diff = (curr_event['timestamp'] - prev_event['timestamp']).total_seconds()
            time_gaps.append(time_diff)
        
        if time_gaps:
            mean_gap = np.mean(time_gaps)
            std_dev_gap = np.std(time_gaps)
            
            if std_dev_gap > 0:
                # Identify unusually large gaps
                for i, gap in enumerate(time_gaps):
                    z_score = (gap - mean_gap) / std_dev_gap
                    
                    if z_score > threshold:
                        # Calculate anomaly score
                        anomaly_score = min(1.0, z_score / (threshold * 2))
                        
                        # Determine severity based on anomaly score
                        severity = 'low'
                        if anomaly_score > 0.7:
                            severity = 'high'
                        elif anomaly_score > 0.4:
                            severity = 'medium'
                        
                        anomaly = {
                            'type': 'time_gap',
                            'description': "Unusually large time gap between events",
                            'time_period': {
                                'start': events[i]['timestamp'].isoformat(),
                                'end': events[i+1]['timestamp'].isoformat()
                            },
                            'gap_seconds': float(gap),
                            'average_gap': float(mean_gap),
                            'z_score': float(z_score),
                            'anomaly_score': float(anomaly_score),
                            'severity': severity,
                            'confidence': 'medium',
                            'events': [events[i]['evidence_item'], events[i+1]['evidence_item']]
                        }
                        
                        anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_access_anomalies(self, evidence_data: Dict[str, Any], 
                               baseline_data: Dict[str, Any] = None,
                               threshold: float = 2.0) -> List[Dict[str, Any]]:
        """
        Detect access anomalies in evidence data.
        
        Args:
            evidence_data: Dictionary containing evidence data
            baseline_data: Optional baseline data for comparison
            threshold: Threshold for anomaly detection
            
        Returns:
            List of access anomaly dictionaries
        """
        anomalies = []
        
        # Extract resource access events
        resource_access = self._extract_resource_access(evidence_data)
        
        # Get baseline resource access if available
        baseline_access = {}
        if baseline_data:
            baseline_access = self._extract_resource_access(baseline_data)
        
        # Analyze access patterns for each resource
        for resource, access_events in resource_access.items():
            # Skip resources with insufficient data
            if len(access_events) < 5:
                continue
            
            # Get baseline access for this resource if available
            resource_baseline = None
            if resource in baseline_access:
                resource_baseline = baseline_access[resource]
            
            # Identify users who accessed the resource
            users = set(event.get('user') for event in access_events if event.get('user'))
            
            # Compare with baseline if available
            if resource_baseline:
                baseline_users = set(event.get('user') for event in resource_baseline if event.get('user'))
                
                # Check for new users
                new_users = users - baseline_users
                
                if new_users:
                    # Get access events for new users
                    new_user_events = [
                        event for event in access_events 
                        if event.get('user') in new_users
                    ]
                    
                    anomaly = {
                        'type': 'new_resource_access',
                        'description': f"New users accessed resource {resource}",
                        'resource': resource,
                        'new_users': list(new_users),
                        'affected_resources': [resource],
                        'anomaly_score': 0.8,
                        'severity': 'high',
                        'confidence': 'medium',
                        'events': new_user_events
                    }
                    anomalies.append(anomaly)
            
            # Detect unusual access patterns
            user_access_counts = {}
            for event in access_events:
                user = event.get('user')
                if user:
                    if user not in user_access_counts:
                        user_access_counts[user] = 0
                    user_access_counts[user] += 1
            
            # Calculate statistics
            access_counts = list(user_access_counts.values())
            
            if len(access_counts) >= 3:
                mean_count = np.mean(access_counts)
                std_dev = np.std(access_counts)
                
                if std_dev > 0:
                    # Identify users with unusually high access counts
                    for user, count in user_access_counts.items():
                        z_score = (count - mean_count) / std_dev
                        
                        if z_score > threshold:
                            # Get events for this user
                            user_events = [
                                event for event in access_events 
                                if event.get('user') == user
                            ]
                            
                            # Calculate anomaly score
                            anomaly_score = min(1.0, z_score / (threshold * 2))
                            
                            # Determine severity based on anomaly score
                            severity = 'medium'
                            if anomaly_score > 0.7:
                                severity = 'high'
                            
                            anomaly = {
                                'type': 'unusual_access_frequency',
                                'description': f"User {user} accessed resource {resource} with unusual frequency",
                                'resource': resource,
                                'user': user,
                                'access_count': count,
                                'average_count': float(mean_count),
                                'z_score': float(z_score),
                                'affected_resources': [resource],
                                'anomaly_score': float(anomaly_score),
                                'severity': severity,
                                'confidence': 'medium',
                                'events': user_events
                            }
                            anomalies.append(anomaly)
        
        # Analyze user access patterns
        user_resources = {}
        for resource, access_events in resource_access.items():
            for event in access_events:
                user = event.get('user')
                if user:
                    if user not in user_resources:
                        user_resources[user] = set()
                    user_resources[user].add(resource)
        
        # Get baseline user resources if available
        baseline_user_resources = {}
        if baseline_data:
            for resource, access_events in baseline_access.items():
                for event in access_events:
                    user = event.get('user')
                    if user:
                        if user not in baseline_user_resources:
                            baseline_user_resources[user] = set()
                        baseline_user_resources[user].add(resource)
        
        # Check for users accessing new resources
        for user, resources in user_resources.items():
            if user in baseline_user_resources:
                baseline_resources = baseline_user_resources[user]
                
                # Check for new resources
                new_resources = resources - baseline_resources
                
                if new_resources and len(new_resources) >= 3:  # At least 3 new resources
                    # Get access events for new resources
                    new_resource_events = []
                    for resource in new_resources:
                        if resource in resource_access:
                            new_resource_events.extend([
                                event for event in resource_access[resource] 
                                if event.get('user') == user
                            ])
                    
                    anomaly = {
                        'type': 'new_resource_access_pattern',
                        'description': f"User {user} accessed multiple new resources",
                        'user': user,
                        'new_resources': list(new_resources),
                        'affected_resources': list(new_resources),
                        'anomaly_score': 0.7,
                        'severity': 'high',
                        'confidence': 'medium',
                        'events': new_resource_events
                    }
                    anomalies.append(anomaly)
        
        return anomalies
    
    def _extract_resource_access(self, evidence_data: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Extract resource access events from evidence data.
        
        Args:
            evidence_data: Dictionary containing evidence data
            
        Returns:
            Dictionary mapping resources to lists of access event dictionaries
        """
        resource_access = {}
        
        # Process each evidence type
        for evidence_type, evidence_items in evidence_data.items():
            if not isinstance(evidence_items, list):
                continue
            
            for item in evidence_items:
                if not isinstance(item, dict):
                    continue
                
                # Extract resource and access information based on evidence type
                resource = None
                user = None
                timestamp = None
                action = None
                
                if 'aws_cloudtrail' in evidence_type:
                    # Check for S3 access
                    if 'eventName' in item and item['eventName'] in ['GetObject', 'PutObject', 'ListObjects']:
                        bucket = item.get('requestParameters', {}).get('bucketName')
                        key = item.get('requestParameters', {}).get('key')
                        
                        if bucket:
                            resource = f"s3://{bucket}"
                            if key:
                                resource += f"/{key}"
                    
                    # Check for EC2 access
                    elif 'eventName' in item and 'Instance' in item.get('eventName', ''):
                        instance_id = item.get('requestParameters', {}).get('instanceId')
                        if instance_id:
                            resource = f"ec2:{instance_id}"
                    
                    # Check for IAM access
                    elif 'eventName' in item and any(x in item.get('eventName', '') for x in ['Role', 'User', 'Policy']):
                        role_name = item.get('requestParameters', {}).get('roleName')
                        user_name = item.get('requestParameters', {}).get('userName')
                        policy_name = item.get('requestParameters', {}).get('policyName')
                        
                        if role_name:
                            resource = f"iam:role/{role_name}"
                        elif user_name:
                            resource = f"iam:user/{user_name}"
                        elif policy_name:
                            resource = f"iam:policy/{policy_name}"
                    
                    user = item.get('userIdentity', {}).get('arn')
                    timestamp = item.get('eventTime')
                    action = item.get('eventName')
                
                elif 'azure_activity_log' in evidence_type:
                    resource = item.get('resourceId')
                    user = item.get('caller')
                    timestamp = item.get('eventTimestamp')
                    action = item.get('operationName')
                
                elif 'gcp_audit_log' in evidence_type:
                    resource = item.get('resource', {}).get('labels', {}).get('bucket_name')
                    if not resource:
                        resource = item.get('resource', {}).get('labels', {}).get('instance_id')
                    
                    user = item.get('protoPayload', {}).get('authenticationInfo', {}).get('principalEmail')
                    timestamp = item.get('timestamp')
                    action = item.get('protoPayload', {}).get('methodName')
                
                # Skip if missing essential information
                if not resource or not user or not timestamp:
                    continue
                
                # Add access event to resource's events
                if resource not in resource_access:
                    resource_access[resource] = []
                
                resource_access[resource].append({
                    'evidence_type': evidence_type,
                    'timestamp': timestamp,
                    'user': user,
                    'action': action,
                    'evidence_item': item
                })
        
        return resource_access
    
    def _detect_network_anomalies(self, evidence_data: Dict[str, Any], 
                                threshold: float = 2.0) -> List[Dict[str, Any]]:
        """
        Detect network anomalies in evidence data.
        
        Args:
            evidence_data: Dictionary containing evidence data
            threshold: Threshold for anomaly detection
            
        Returns:
            List of network anomaly dictionaries
        """
        anomalies = []
        
        # Extract network flow events
        flow_events = []
        
        # AWS VPC Flow Logs
        if 'aws_vpc_flow' in evidence_data:
            for item in evidence_data['aws_vpc_flow']:
                if not isinstance(item, dict):
                    continue
                
                flow_events.append({
                    'evidence_type': 'aws_vpc_flow',
                    'src_ip': item.get('srcAddr'),
                    'dst_ip': item.get('dstAddr'),
                    'src_port': item.get('srcPort'),
                    'dst_port': item.get('dstPort'),
                    'protocol': item.get('protocol'),
                    'bytes': item.get('bytes'),
                    'packets': item.get('packets'),
                    'start_time': item.get('start'),
                    'end_time': item.get('end'),
                    'action': item.get('action'),
                    'evidence_item': item
                })
        
        # Azure NSG Flow Logs
        if 'azure_nsg_flow' in evidence_data:
            for item in evidence_data['azure_nsg_flow']:
                if not isinstance(item, dict):
                    continue
                
                flow_events.append({
                    'evidence_type': 'azure_nsg_flow',
                    'src_ip': item.get('sourceAddress'),
                    'dst_ip': item.get('destinationAddress'),
                    'src_port': item.get('sourcePort'),
                    'dst_port': item.get('destinationPort'),
                    'protocol': item.get('protocol'),
                    'bytes': item.get('dataBytes') or item.get('totalBytes'),
                    'packets': item.get('packets'),
                    'start_time': item.get('startTime'),
                    'end_time': item.get('endTime'),
                    'action': item.get('decision'),
                    'evidence_item': item
                })
        
        # GCP VPC Flow Logs
        if 'gcp_vpc_flow' in evidence_data:
            for item in evidence_data['gcp_vpc_flow']:
                if not isinstance(item, dict):
                    continue
                
                flow_events.append({
                    'evidence_type': 'gcp_vpc_flow',
                    'src_ip': item.get('connection', {}).get('src_ip'),
                    'dst_ip': item.get('connection', {}).get('dest_ip'),
                    'src_port': item.get('connection', {}).get('src_port'),
                    'dst_port': item.get('connection', {}).get('dest_port'),
                    'protocol': item.get('connection', {}).get('protocol'),
                    'bytes': item.get('bytes_sent'),
                    'packets': item.get('packets_sent'),
                    'start_time': item.get('start_time'),
                    'end_time': item.get('end_time'),
                    'action': 'ACCEPT',  # GCP logs typically only show accepted flows
                    'evidence_item': item
                })
        
        if not flow_events:
            return anomalies
        
        # Detect unusual data transfer volumes
        transfer_volumes = {}
        
        for event in flow_events:
            src_ip = event.get('src_ip')
            dst_ip = event.get('dst_ip')
            bytes_transferred = event.get('bytes')
            
            if not src_ip or not dst_ip or not bytes_transferred:
                continue
            
            # Create a key for this flow direction
            flow_key = f"{src_ip}_{dst_ip}"
            
            if flow_key not in transfer_volumes:
                transfer_volumes[flow_key] = {
                    'src_ip': src_ip,
                    'dst_ip': dst_ip,
                    'total_bytes': 0,
                    'flow_count': 0,
                    'events': []
                }
            
            transfer_volumes[flow_key]['total_bytes'] += int(bytes_transferred)
            transfer_volumes[flow_key]['flow_count'] += 1
            transfer_volumes[flow_key]['events'].append(event)
        
        # Calculate statistics for data transfer volumes
        if len(transfer_volumes) >= 3:
            volumes = [data['total_bytes'] for data in transfer_volumes.values()]
            
            mean_volume = np.mean(volumes)
            std_dev = np.std(volumes)
            
            if std_dev > 0:
                # Identify flows with unusually high data transfer
                for flow_key, data in transfer_volumes.items():
                    z_score = (data['total_bytes'] - mean_volume) / std_dev
                    
                    if z_score > threshold:
                        # Calculate anomaly score
                        anomaly_score = min(1.0, z_score / (threshold * 2))
                        
                        # Determine severity based on anomaly score
                        severity = 'medium'
                        if anomaly_score > 0.7:
                            severity = 'high'
                        
                        anomaly = {
                            'type': 'unusual_data_transfer',
                            'description': f"Unusually large data transfer detected from {data['src_ip']} to {data['dst_ip']}",
                            'src_ip': data['src_ip'],
                            'dst_ip': data['dst_ip'],
                            'total_bytes': data['total_bytes'],
                            'flow_count': data['flow_count'],
                            'average_bytes': float(mean_volume),
                            'z_score': float(z_score),
                            'affected_resources': [data['src_ip'], data['dst_ip']],
                            'anomaly_score': float(anomaly_score),
                            'severity': severity,
                            'confidence': 'medium',
                            'events': data['events']
                        }
                        anomalies.append(anomaly)
        
        # Detect unusual port usage
        port_usage = {}
        
        for event in flow_events:
            src_ip = event.get('src_ip')
            dst_ip = event.get('dst_ip')
            dst_port = event.get('dst_port')
            
            if not src_ip or not dst_ip or not dst_port:
                continue
            
            # Create a key for this IP
            ip_key = src_ip
            
            if ip_key not in port_usage:
                port_usage[ip_key] = {
                    'ip': ip_key,
                    'ports': set(),
                    'events': []
                }
            
            port_usage[ip_key]['ports'].add(int(dst_port))
            port_usage[ip_key]['events'].append(event)
        
        # Check for unusual port scanning behavior
        for ip_key, data in port_usage.items():
            # If an IP is connecting to more than 20 different ports, flag as port scanning
            if len(data['ports']) > 20:
                anomaly = {
                    'type': 'port_scanning',
                    'description': f"Potential port scanning detected from {data['ip']}",
                    'source_ip': data['ip'],
                    'port_count': len(data['ports']),
                    'ports': list(data['ports']),
                    'affected_resources': [data['ip']],
                    'anomaly_score': 0.9,
                    'severity': 'high',
                    'confidence': 'medium',
                    'events': data['events']
                }
                anomalies.append(anomaly)
        
        # Detect connections to suspicious ports
        suspicious_ports = [22, 23, 3389, 445, 135, 137, 138, 139, 1433, 3306, 5432]
        
        for event in flow_events:
            src_ip = event.get('src_ip')
            dst_ip = event.get('dst_ip')
            dst_port = event.get('dst_port')
            
            if not src_ip or not dst_ip or not dst_port:
                continue
            
            # Check if destination port is suspicious
            if int(dst_port) in suspicious_ports:
                anomaly = {
                    'type': 'suspicious_port_connection',
                    'description': f"Connection to suspicious port {dst_port} detected",
                    'source_ip': src_ip,
                    'destination_ip': dst_ip,
                    'destination_port': dst_port,
                    'affected_resources': [dst_ip],
                    'anomaly_score': 0.7,
                    'severity': 'medium',
                    'confidence': 'medium',
                    'events': [event]
                }
                anomalies.append(anomaly)
        
        return anomalies
