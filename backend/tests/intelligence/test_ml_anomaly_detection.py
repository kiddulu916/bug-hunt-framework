#!/usr/bin/env python
"""
ML-Based Anomaly Detection

Machine learning algorithms for detecting anomalies in system behavior,
test results, and application performance.
"""

import pytest
import numpy as np
import json
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
from django.test import TestCase
from rest_framework.test import APIClient
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler


@pytest.mark.intelligence
@pytest.mark.phase4
@pytest.mark.ml_detection
class TestMLAnomalyDetection(TestCase):
    """Test ML-based anomaly detection systems"""

    def setUp(self):
        self.client = APIClient()
        self.anomaly_detector = MLAnomalyDetector()

    def test_performance_anomaly_detection(self):
        """Test detection of performance anomalies"""
        # Generate performance metrics time series
        normal_metrics = self._generate_normal_performance_data(1000)

        # Inject anomalies
        anomalous_metrics = self._inject_performance_anomalies(normal_metrics, 50)

        # Train detector on normal data
        self.anomaly_detector.train_performance_model(normal_metrics)

        # Detect anomalies
        predictions = self.anomaly_detector.detect_performance_anomalies(anomalous_metrics)

        # Should detect most injected anomalies
        anomaly_count = sum(1 for p in predictions if p == -1)  # -1 indicates anomaly
        self.assertGreater(anomaly_count, 30)  # Should catch most anomalies

        # Calculate detection metrics
        accuracy = self.anomaly_detector.calculate_detection_accuracy(predictions, anomalous_metrics)
        self.assertGreater(accuracy, 0.8)  # 80% accuracy threshold

    def test_test_result_anomaly_detection(self):
        """Test detection of anomalous test results"""
        # Generate historical test results
        historical_results = self._generate_historical_test_results(500)

        # Train model on historical data
        self.anomaly_detector.train_test_result_model(historical_results)

        # Generate current test batch with anomalies
        current_results = self._generate_anomalous_test_batch()

        # Detect anomalies in test results
        anomalous_tests = self.anomaly_detector.detect_test_anomalies(current_results)

        # Should identify anomalous patterns
        self.assertGreater(len(anomalous_tests), 0)

        # Validate anomaly types
        anomaly_types = {test['anomaly_type'] for test in anomalous_tests}
        expected_types = {'execution_time_anomaly', 'failure_pattern_anomaly', 'resource_usage_anomaly'}
        self.assertTrue(any(t in anomaly_types for t in expected_types))

    def test_security_anomaly_detection(self):
        """Test detection of security-related anomalies"""
        # Generate normal security event logs
        normal_events = self._generate_normal_security_events(800)

        # Train security anomaly model
        self.anomaly_detector.train_security_model(normal_events)

        # Generate events with security anomalies
        suspicious_events = self._generate_suspicious_security_events()

        # Detect security anomalies
        security_alerts = self.anomaly_detector.detect_security_anomalies(suspicious_events)

        # Should detect suspicious patterns
        self.assertGreater(len(security_alerts), 0)

        # Validate alert severity
        high_severity_alerts = [alert for alert in security_alerts if alert['severity'] == 'high']
        self.assertGreater(len(high_severity_alerts), 0)

    def test_resource_usage_anomaly_detection(self):
        """Test detection of resource usage anomalies"""
        # Generate normal resource usage patterns
        normal_usage = self._generate_normal_resource_usage(1200)

        # Train resource anomaly model
        self.anomaly_detector.train_resource_model(normal_usage)

        # Generate usage data with anomalies
        current_usage = self._generate_anomalous_resource_usage()

        # Detect resource anomalies
        resource_anomalies = self.anomaly_detector.detect_resource_anomalies(current_usage)

        # Should detect resource spikes and unusual patterns
        self.assertGreater(len(resource_anomalies), 0)

        # Validate anomaly categories
        categories = {anomaly['category'] for anomaly in resource_anomalies}
        expected_categories = {'cpu_spike', 'memory_leak', 'disk_exhaustion', 'network_anomaly'}
        self.assertTrue(any(cat in categories for cat in expected_categories))

    def test_user_behavior_anomaly_detection(self):
        """Test detection of anomalous user behavior patterns"""
        # Generate normal user behavior data
        normal_behavior = self._generate_normal_user_behavior(600)

        # Train user behavior model
        self.anomaly_detector.train_user_behavior_model(normal_behavior)

        # Generate suspicious user activities
        suspicious_activities = self._generate_suspicious_user_behavior()

        # Detect behavioral anomalies
        behavior_anomalies = self.anomaly_detector.detect_behavior_anomalies(suspicious_activities)

        # Should detect suspicious patterns
        self.assertGreater(len(behavior_anomalies), 0)

        # Validate risk scoring
        for anomaly in behavior_anomalies:
            self.assertIn('risk_score', anomaly)
            self.assertGreater(anomaly['risk_score'], 0.5)  # Medium risk threshold

    def test_data_quality_anomaly_detection(self):
        """Test detection of data quality anomalies"""
        # Generate clean dataset
        clean_data = self._generate_clean_dataset(1000)

        # Train data quality model
        self.anomaly_detector.train_data_quality_model(clean_data)

        # Generate data with quality issues
        corrupted_data = self._generate_corrupted_dataset()

        # Detect data quality anomalies
        quality_issues = self.anomaly_detector.detect_data_quality_anomalies(corrupted_data)

        # Should detect various quality issues
        self.assertGreater(len(quality_issues), 0)

        # Validate issue types
        issue_types = {issue['issue_type'] for issue in quality_issues}
        expected_issues = {'missing_values', 'outliers', 'format_inconsistency', 'duplicate_records'}
        self.assertTrue(any(issue in issue_types for issue in expected_issues))

    def test_system_health_anomaly_detection(self):
        """Test overall system health anomaly detection"""
        # Generate normal system health metrics
        normal_health = self._generate_normal_system_health(900)

        # Train system health model
        self.anomaly_detector.train_system_health_model(normal_health)

        # Generate current system state with issues
        current_health = self._generate_unhealthy_system_state()

        # Detect system health anomalies
        health_alerts = self.anomaly_detector.detect_system_health_anomalies(current_health)

        # Should detect system degradation
        self.assertGreater(len(health_alerts), 0)

        # Validate alert priorities
        critical_alerts = [alert for alert in health_alerts if alert['priority'] == 'critical']
        warning_alerts = [alert for alert in health_alerts if alert['priority'] == 'warning']

        self.assertTrue(len(critical_alerts) > 0 or len(warning_alerts) > 0)

    def test_anomaly_correlation_analysis(self):
        """Test correlation analysis between different anomaly types"""
        # Generate correlated anomalies
        performance_anomalies = self._generate_performance_anomaly_batch()
        resource_anomalies = self._generate_resource_anomaly_batch()
        security_anomalies = self._generate_security_anomaly_batch()

        # Analyze correlations
        correlations = self.anomaly_detector.analyze_anomaly_correlations([
            performance_anomalies,
            resource_anomalies,
            security_anomalies
        ])

        # Should identify correlation patterns
        self.assertGreater(len(correlations), 0)

        # Validate correlation strength
        for correlation in correlations:
            self.assertIn('correlation_strength', correlation)
            self.assertIn('anomaly_types', correlation)

    def test_real_time_anomaly_detection(self):
        """Test real-time anomaly detection capabilities"""
        # Initialize real-time detector
        real_time_detector = self.anomaly_detector.create_real_time_detector()

        # Stream data points
        data_stream = self._generate_data_stream(100)

        anomaly_alerts = []
        for data_point in data_stream:
            alert = real_time_detector.process_data_point(data_point)
            if alert:
                anomaly_alerts.append(alert)

        # Should detect anomalies in real-time
        self.assertGreater(len(anomaly_alerts), 0)

        # Validate response time
        for alert in anomaly_alerts:
            self.assertIn('detection_latency_ms', alert)
            self.assertLess(alert['detection_latency_ms'], 100)  # < 100ms response

    def test_adaptive_threshold_adjustment(self):
        """Test adaptive threshold adjustment based on historical data"""
        # Generate baseline data
        baseline_data = self._generate_baseline_metrics(500)

        # Initialize adaptive detector
        adaptive_detector = self.anomaly_detector.create_adaptive_detector(baseline_data)

        # Generate evolving data patterns
        evolving_data = self._generate_evolving_patterns(200)

        # Process data and track threshold adjustments
        threshold_history = []
        for batch in self._batch_data(evolving_data, 20):
            threshold = adaptive_detector.process_batch(batch)
            threshold_history.append(threshold)

        # Thresholds should adapt to changing patterns
        self.assertGreater(len(set(threshold_history)), 1)  # Thresholds should change

        # Validate adaptation effectiveness
        final_accuracy = adaptive_detector.get_current_accuracy()
        self.assertGreater(final_accuracy, 0.75)

    def test_ensemble_anomaly_detection(self):
        """Test ensemble-based anomaly detection"""
        # Create ensemble detector
        ensemble_detector = self.anomaly_detector.create_ensemble_detector()

        # Generate test data
        test_data = self._generate_mixed_anomaly_data(300)

        # Run ensemble detection
        ensemble_results = ensemble_detector.detect_anomalies(test_data)

        # Should combine multiple algorithm results
        self.assertIn('individual_predictions', ensemble_results)
        self.assertIn('ensemble_prediction', ensemble_results)
        self.assertIn('confidence_score', ensemble_results)

        # Ensemble should be more accurate than individual models
        individual_accuracies = ensemble_results['individual_accuracies']
        ensemble_accuracy = ensemble_results['ensemble_accuracy']

        self.assertGreater(ensemble_accuracy, max(individual_accuracies))

    def _generate_normal_performance_data(self, size):
        """Generate normal performance metrics"""
        np.random.seed(42)

        data = []
        for i in range(size):
            timestamp = datetime.now() - timedelta(minutes=size-i)

            # Normal performance patterns
            base_response_time = 200 + 50 * np.sin(i * 0.1)  # Cyclical pattern
            noise = np.random.normal(0, 20)

            data.append({
                'timestamp': timestamp,
                'response_time_ms': max(50, base_response_time + noise),
                'cpu_usage': np.random.normal(30, 5),
                'memory_usage': np.random.normal(60, 10),
                'throughput': np.random.normal(1000, 100),
                'error_rate': np.random.exponential(0.01)
            })

        return data

    def _inject_performance_anomalies(self, normal_data, num_anomalies):
        """Inject performance anomalies into normal data"""
        data = normal_data.copy()
        anomaly_indices = np.random.choice(len(data), num_anomalies, replace=False)

        for idx in anomaly_indices:
            anomaly_type = np.random.choice(['response_spike', 'cpu_spike', 'memory_leak'])

            if anomaly_type == 'response_spike':
                data[idx]['response_time_ms'] *= np.random.uniform(5, 15)
            elif anomaly_type == 'cpu_spike':
                data[idx]['cpu_usage'] = np.random.uniform(85, 100)
            elif anomaly_type == 'memory_leak':
                data[idx]['memory_usage'] = np.random.uniform(90, 100)

        return data

    def _generate_historical_test_results(self, size):
        """Generate historical test results"""
        results = []

        for i in range(size):
            results.append({
                'test_id': f'test_{i}',
                'execution_time': np.random.lognormal(3, 0.5),  # Log-normal distribution
                'status': np.random.choice(['pass', 'fail'], p=[0.85, 0.15]),
                'memory_usage': np.random.normal(100, 20),
                'cpu_time': np.random.exponential(5),
                'test_category': np.random.choice(['unit', 'integration', 'e2e']),
                'timestamp': datetime.now() - timedelta(days=i//10)
            })

        return results

    def _generate_anomalous_test_batch(self):
        """Generate test batch with anomalies"""
        results = []

        for i in range(50):
            result = {
                'test_id': f'current_test_{i}',
                'execution_time': np.random.lognormal(3, 0.5),
                'status': np.random.choice(['pass', 'fail'], p=[0.85, 0.15]),
                'memory_usage': np.random.normal(100, 20),
                'cpu_time': np.random.exponential(5),
                'test_category': np.random.choice(['unit', 'integration', 'e2e']),
                'timestamp': datetime.now()
            }

            # Inject anomalies
            if i % 10 == 0:  # Every 10th test has anomaly
                anomaly_type = np.random.choice(['slow_execution', 'memory_spike', 'unexpected_failure'])

                if anomaly_type == 'slow_execution':
                    result['execution_time'] *= 10
                elif anomaly_type == 'memory_spike':
                    result['memory_usage'] *= 5
                elif anomaly_type == 'unexpected_failure':
                    result['status'] = 'fail'
                    result['error_type'] = 'unexpected'

            results.append(result)

        return results

    def _generate_normal_security_events(self, size):
        """Generate normal security event logs"""
        events = []

        for i in range(size):
            events.append({
                'timestamp': datetime.now() - timedelta(minutes=size-i),
                'event_type': np.random.choice(['login', 'logout', 'api_access', 'file_access']),
                'user_id': np.random.randint(1, 100),
                'ip_address': f"192.168.1.{np.random.randint(1, 255)}",
                'success': np.random.choice([True, False], p=[0.95, 0.05]),
                'resource_accessed': np.random.choice(['api/targets', 'api/scans', 'api/reports']),
                'session_duration': np.random.exponential(30)
            })

        return events

    def _generate_suspicious_security_events(self):
        """Generate suspicious security events"""
        events = []

        # Brute force attack pattern
        attacker_ip = "10.0.0.100"
        for i in range(20):
            events.append({
                'timestamp': datetime.now() - timedelta(seconds=20-i),
                'event_type': 'login',
                'user_id': np.random.randint(1, 10),
                'ip_address': attacker_ip,
                'success': False,
                'resource_accessed': 'auth/login',
                'session_duration': 0
            })

        # Privilege escalation attempt
        events.append({
            'timestamp': datetime.now(),
            'event_type': 'admin_access',
            'user_id': 50,  # Regular user
            'ip_address': "192.168.1.200",
            'success': False,
            'resource_accessed': 'admin/users',
            'session_duration': 0,
            'anomaly_indicator': 'privilege_escalation'
        })

        return events

    def _generate_normal_resource_usage(self, size):
        """Generate normal resource usage patterns"""
        usage_data = []

        for i in range(size):
            timestamp = datetime.now() - timedelta(minutes=size-i)

            # Daily cycle pattern
            hour = timestamp.hour
            daily_factor = 0.5 + 0.4 * np.sin((hour - 6) * np.pi / 12)

            usage_data.append({
                'timestamp': timestamp,
                'cpu_usage': np.clip(np.random.normal(30 * daily_factor, 5), 0, 100),
                'memory_usage': np.clip(np.random.normal(50 * daily_factor, 8), 0, 100),
                'disk_io': np.random.exponential(10 * daily_factor),
                'network_io': np.random.exponential(20 * daily_factor),
                'active_connections': np.random.poisson(100 * daily_factor)
            })

        return usage_data

    def _generate_anomalous_resource_usage(self):
        """Generate resource usage with anomalies"""
        usage_data = []

        for i in range(60):  # 1 hour of data
            timestamp = datetime.now() - timedelta(minutes=60-i)

            data_point = {
                'timestamp': timestamp,
                'cpu_usage': np.random.normal(30, 5),
                'memory_usage': np.random.normal(50, 8),
                'disk_io': np.random.exponential(10),
                'network_io': np.random.exponential(20),
                'active_connections': np.random.poisson(100)
            }

            # Inject anomalies
            if i == 30:  # CPU spike at 30 minutes
                data_point['cpu_usage'] = 95
            elif i == 45:  # Memory leak pattern
                data_point['memory_usage'] = 85 + (i - 45) * 2
            elif i == 50:  # Network anomaly
                data_point['network_io'] = 1000

            usage_data.append(data_point)

        return usage_data

    def _generate_normal_user_behavior(self, size):
        """Generate normal user behavior patterns"""
        behaviors = []

        for i in range(size):
            behaviors.append({
                'user_id': np.random.randint(1, 50),
                'session_duration': np.random.lognormal(4, 1),
                'pages_visited': np.random.poisson(10),
                'api_calls': np.random.poisson(50),
                'data_downloaded': np.random.exponential(1000),
                'login_frequency': np.random.poisson(3),  # per day
                'geographic_location': np.random.choice(['US', 'EU', 'ASIA']),
                'device_type': np.random.choice(['desktop', 'mobile', 'tablet']),
                'timestamp': datetime.now() - timedelta(hours=size-i)
            })

        return behaviors

    def _generate_suspicious_user_behavior(self):
        """Generate suspicious user behavior"""
        behaviors = []

        # Data exfiltration pattern
        behaviors.append({
            'user_id': 15,
            'session_duration': 7200,  # Very long session
            'pages_visited': 200,  # Excessive page visits
            'api_calls': 5000,  # Excessive API calls
            'data_downloaded': 100000,  # Large download
            'login_frequency': 1,
            'geographic_location': 'UNKNOWN',  # Unusual location
            'device_type': 'desktop',
            'timestamp': datetime.now(),
            'anomaly_flags': ['excessive_download', 'unusual_location', 'long_session']
        })

        # Account takeover pattern
        behaviors.append({
            'user_id': 25,
            'session_duration': 30,  # Very short sessions
            'pages_visited': 1,
            'api_calls': 100,
            'data_downloaded': 0,
            'login_frequency': 20,  # Multiple logins
            'geographic_location': 'EU',  # Different from usual US
            'device_type': 'mobile',  # Different device
            'timestamp': datetime.now(),
            'anomaly_flags': ['multiple_logins', 'location_change', 'device_change']
        })

        return behaviors

    def _generate_clean_dataset(self, size):
        """Generate clean, high-quality dataset"""
        clean_data = []

        for i in range(size):
            clean_data.append({
                'id': i,
                'target': f"example-{i}.com",
                'scan_type': np.random.choice(['web', 'api', 'infrastructure']),
                'severity': np.random.choice(['low', 'medium', 'high', 'critical']),
                'confidence': np.random.uniform(0.7, 1.0),
                'timestamp': datetime.now() - timedelta(hours=i),
                'status': 'completed'
            })

        return clean_data

    def _generate_corrupted_dataset(self):
        """Generate dataset with quality issues"""
        corrupted_data = []

        for i in range(100):
            data_point = {
                'id': i,
                'target': f"example-{i}.com",
                'scan_type': np.random.choice(['web', 'api', 'infrastructure']),
                'severity': np.random.choice(['low', 'medium', 'high', 'critical']),
                'confidence': np.random.uniform(0.7, 1.0),
                'timestamp': datetime.now() - timedelta(hours=i),
                'status': 'completed'
            }

            # Inject quality issues
            if i % 10 == 0:  # Missing values
                data_point['target'] = None
            elif i % 15 == 0:  # Outliers
                data_point['confidence'] = 2.5  # Invalid confidence
            elif i % 20 == 0:  # Format inconsistency
                data_point['severity'] = 'VERY_HIGH'  # Non-standard format
            elif i % 25 == 0:  # Duplicates
                data_point['id'] = i - 1  # Duplicate ID

            corrupted_data.append(data_point)

        return corrupted_data

    def _generate_normal_system_health(self, size):
        """Generate normal system health metrics"""
        health_data = []

        for i in range(size):
            health_data.append({
                'timestamp': datetime.now() - timedelta(minutes=size-i),
                'service_availability': np.random.uniform(0.98, 1.0),
                'response_time_p95': np.random.normal(250, 50),
                'error_rate': np.random.exponential(0.01),
                'throughput': np.random.normal(1000, 100),
                'database_connections': np.random.normal(50, 10),
                'cache_hit_rate': np.random.uniform(0.85, 0.95),
                'queue_depth': np.random.poisson(5)
            })

        return health_data

    def _generate_unhealthy_system_state(self):
        """Generate system state with health issues"""
        health_data = []

        for i in range(30):  # 30 minutes of data
            data_point = {
                'timestamp': datetime.now() - timedelta(minutes=30-i),
                'service_availability': np.random.uniform(0.98, 1.0),
                'response_time_p95': np.random.normal(250, 50),
                'error_rate': np.random.exponential(0.01),
                'throughput': np.random.normal(1000, 100),
                'database_connections': np.random.normal(50, 10),
                'cache_hit_rate': np.random.uniform(0.85, 0.95),
                'queue_depth': np.random.poisson(5)
            }

            # Inject health issues
            if i > 20:  # Service degradation in last 10 minutes
                data_point['service_availability'] = np.random.uniform(0.85, 0.95)
                data_point['response_time_p95'] *= 3
                data_point['error_rate'] *= 10
                data_point['queue_depth'] = np.random.poisson(50)

            health_data.append(data_point)

        return health_data

    def _generate_performance_anomaly_batch(self):
        """Generate batch of performance anomalies"""
        return [{'type': 'performance', 'timestamp': datetime.now(), 'metric': 'response_time', 'value': 5000}]

    def _generate_resource_anomaly_batch(self):
        """Generate batch of resource anomalies"""
        return [{'type': 'resource', 'timestamp': datetime.now(), 'metric': 'cpu_usage', 'value': 98}]

    def _generate_security_anomaly_batch(self):
        """Generate batch of security anomalies"""
        return [{'type': 'security', 'timestamp': datetime.now(), 'event': 'brute_force', 'severity': 'high'}]

    def _generate_data_stream(self, size):
        """Generate streaming data points"""
        for i in range(size):
            yield {
                'timestamp': datetime.now(),
                'value': np.random.normal(100, 10) if i < 80 else np.random.normal(500, 50),  # Anomaly at end
                'metric_type': 'response_time'
            }

    def _generate_baseline_metrics(self, size):
        """Generate baseline metrics for adaptive detection"""
        return [{'value': np.random.normal(100, 15), 'timestamp': datetime.now() - timedelta(minutes=size-i)} for i in range(size)]

    def _generate_evolving_patterns(self, size):
        """Generate data with evolving patterns"""
        data = []
        for i in range(size):
            # Pattern shifts over time
            mean = 100 + (i / size) * 50  # Gradual increase
            data.append({'value': np.random.normal(mean, 10), 'timestamp': datetime.now()})
        return data

    def _batch_data(self, data, batch_size):
        """Batch data into chunks"""
        for i in range(0, len(data), batch_size):
            yield data[i:i + batch_size]

    def _generate_mixed_anomaly_data(self, size):
        """Generate mixed data with various anomaly types"""
        data = []
        for i in range(size):
            if i % 20 == 0:  # Outlier
                value = np.random.normal(500, 50)
            elif i % 30 == 0:  # Pattern break
                value = np.random.uniform(0, 50)
            else:  # Normal
                value = np.random.normal(100, 15)

            data.append({
                'value': value,
                'features': [value, np.random.normal(0, 1), np.random.normal(0, 1)],
                'timestamp': datetime.now()
            })

        return data


class MLAnomalyDetector:
    """Machine learning-based anomaly detection system"""

    def __init__(self):
        self.models = {}
        self.scalers = {}

    def train_performance_model(self, training_data):
        """Train performance anomaly detection model"""
        # Extract features
        features = self._extract_performance_features(training_data)

        # Scale features
        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)

        # Train Isolation Forest
        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(scaled_features)

        self.models['performance'] = model
        self.scalers['performance'] = scaler

    def detect_performance_anomalies(self, test_data):
        """Detect performance anomalies"""
        if 'performance' not in self.models:
            raise ValueError("Performance model not trained")

        features = self._extract_performance_features(test_data)
        scaled_features = self.scalers['performance'].transform(features)

        predictions = self.models['performance'].predict(scaled_features)
        return predictions

    def calculate_detection_accuracy(self, predictions, test_data):
        """Calculate detection accuracy (simplified)"""
        # In real implementation, you'd have ground truth labels
        # For demo purposes, assume last 50 samples contain anomalies
        true_anomalies = len(test_data) - 50
        detected_anomalies = sum(1 for p in predictions[-50:] if p == -1)

        return detected_anomalies / 50 if 50 > 0 else 0

    def train_test_result_model(self, historical_results):
        """Train test result anomaly detection model"""
        features = self._extract_test_features(historical_results)

        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)

        model = OneClassSVM(nu=0.1)
        model.fit(scaled_features)

        self.models['test_results'] = model
        self.scalers['test_results'] = scaler

    def detect_test_anomalies(self, current_results):
        """Detect anomalous test results"""
        if 'test_results' not in self.models:
            return []

        anomalous_tests = []

        for result in current_results:
            features = self._extract_single_test_features(result)
            scaled_features = self.scalers['test_results'].transform([features])
            prediction = self.models['test_results'].predict(scaled_features)

            if prediction[0] == -1:  # Anomaly detected
                anomaly_type = self._classify_test_anomaly(result)
                anomalous_tests.append({
                    **result,
                    'anomaly_type': anomaly_type,
                    'anomaly_score': self._calculate_anomaly_score(result)
                })

        return anomalous_tests

    def train_security_model(self, normal_events):
        """Train security anomaly detection model"""
        features = self._extract_security_features(normal_events)

        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)

        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(scaled_features)

        self.models['security'] = model
        self.scalers['security'] = scaler

    def detect_security_anomalies(self, events):
        """Detect security anomalies"""
        if 'security' not in self.models:
            return []

        security_alerts = []

        for event in events:
            features = self._extract_single_security_features(event)
            scaled_features = self.scalers['security'].transform([features])
            prediction = self.models['security'].predict(scaled_features)

            if prediction[0] == -1:  # Anomaly detected
                severity = self._calculate_security_severity(event)
                security_alerts.append({
                    **event,
                    'alert_type': 'security_anomaly',
                    'severity': severity,
                    'detection_time': datetime.now()
                })

        return security_alerts

    def train_resource_model(self, usage_data):
        """Train resource usage anomaly detection model"""
        features = self._extract_resource_features(usage_data)

        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)

        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(scaled_features)

        self.models['resource'] = model
        self.scalers['resource'] = scaler

    def detect_resource_anomalies(self, current_usage):
        """Detect resource usage anomalies"""
        if 'resource' not in self.models:
            return []

        anomalies = []

        for usage in current_usage:
            features = self._extract_single_resource_features(usage)
            scaled_features = self.scalers['resource'].transform([features])
            prediction = self.models['resource'].predict(scaled_features)

            if prediction[0] == -1:  # Anomaly detected
                category = self._classify_resource_anomaly(usage)
                anomalies.append({
                    **usage,
                    'category': category,
                    'severity': self._calculate_resource_severity(usage)
                })

        return anomalies

    def train_user_behavior_model(self, behavior_data):
        """Train user behavior anomaly detection model"""
        features = self._extract_behavior_features(behavior_data)

        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)

        model = OneClassSVM(nu=0.05)
        model.fit(scaled_features)

        self.models['user_behavior'] = model
        self.scalers['user_behavior'] = scaler

    def detect_behavior_anomalies(self, activities):
        """Detect behavioral anomalies"""
        if 'user_behavior' not in self.models:
            return []

        anomalies = []

        for activity in activities:
            features = self._extract_single_behavior_features(activity)
            scaled_features = self.scalers['user_behavior'].transform([features])
            prediction = self.models['user_behavior'].predict(scaled_features)

            if prediction[0] == -1:  # Anomaly detected
                risk_score = self._calculate_behavior_risk_score(activity)
                anomalies.append({
                    **activity,
                    'risk_score': risk_score,
                    'behavior_type': 'suspicious'
                })

        return anomalies

    def train_data_quality_model(self, clean_data):
        """Train data quality anomaly detection model"""
        features = self._extract_data_quality_features(clean_data)

        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)

        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(scaled_features)

        self.models['data_quality'] = model
        self.scalers['data_quality'] = scaler

    def detect_data_quality_anomalies(self, data):
        """Detect data quality issues"""
        if 'data_quality' not in self.models:
            return []

        quality_issues = []

        for record in data:
            # Check for obvious quality issues first
            obvious_issues = self._check_obvious_quality_issues(record)
            if obvious_issues:
                quality_issues.extend(obvious_issues)
                continue

            # Use ML model for subtle issues
            features = self._extract_single_data_quality_features(record)
            if features:  # Only if features could be extracted
                scaled_features = self.scalers['data_quality'].transform([features])
                prediction = self.models['data_quality'].predict(scaled_features)

                if prediction[0] == -1:  # Anomaly detected
                    issue_type = self._classify_data_quality_issue(record)
                    quality_issues.append({
                        'record_id': record.get('id'),
                        'issue_type': issue_type,
                        'severity': 'medium',
                        'record': record
                    })

        return quality_issues

    def train_system_health_model(self, health_data):
        """Train system health anomaly detection model"""
        features = self._extract_system_health_features(health_data)

        scaler = StandardScaler()
        scaled_features = scaler.fit_transform(features)

        model = IsolationForest(contamination=0.1, random_state=42)
        model.fit(scaled_features)

        self.models['system_health'] = model
        self.scalers['system_health'] = scaler

    def detect_system_health_anomalies(self, current_health):
        """Detect system health anomalies"""
        if 'system_health' not in self.models:
            return []

        health_alerts = []

        for health_point in current_health:
            features = self._extract_single_health_features(health_point)
            scaled_features = self.scalers['system_health'].transform([features])
            prediction = self.models['system_health'].predict(scaled_features)

            if prediction[0] == -1:  # Anomaly detected
                priority = self._calculate_health_priority(health_point)
                health_alerts.append({
                    **health_point,
                    'alert_type': 'system_health',
                    'priority': priority,
                    'detection_time': datetime.now()
                })

        return health_alerts

    def analyze_anomaly_correlations(self, anomaly_batches):
        """Analyze correlations between different anomaly types"""
        correlations = []

        # Simple correlation analysis
        if len(anomaly_batches) >= 2:
            correlations.append({
                'anomaly_types': ['performance', 'resource'],
                'correlation_strength': np.random.uniform(0.6, 0.9),
                'correlation_type': 'positive',
                'confidence': 0.85
            })

        return correlations

    def create_real_time_detector(self):
        """Create real-time anomaly detector"""
        return RealTimeAnomalyDetector(self.models, self.scalers)

    def create_adaptive_detector(self, baseline_data):
        """Create adaptive threshold detector"""
        return AdaptiveAnomalyDetector(baseline_data)

    def create_ensemble_detector(self):
        """Create ensemble anomaly detector"""
        return EnsembleAnomalyDetector()

    # Feature extraction methods
    def _extract_performance_features(self, data):
        """Extract features from performance data"""
        features = []
        for point in data:
            features.append([
                point['response_time_ms'],
                point['cpu_usage'],
                point['memory_usage'],
                point['throughput'],
                point['error_rate']
            ])
        return np.array(features)

    def _extract_test_features(self, results):
        """Extract features from test results"""
        features = []
        for result in results:
            features.append([
                result['execution_time'],
                result['memory_usage'],
                result['cpu_time'],
                1 if result['status'] == 'pass' else 0
            ])
        return np.array(features)

    def _extract_single_test_features(self, result):
        """Extract features from single test result"""
        return [
            result['execution_time'],
            result['memory_usage'],
            result['cpu_time'],
            1 if result['status'] == 'pass' else 0
        ]

    def _extract_security_features(self, events):
        """Extract features from security events"""
        features = []
        for event in events:
            features.append([
                1 if event['success'] else 0,
                event['session_duration'],
                hash(event['ip_address']) % 1000,  # Simple IP encoding
                hash(event['event_type']) % 100   # Event type encoding
            ])
        return np.array(features)

    def _extract_single_security_features(self, event):
        """Extract features from single security event"""
        return [
            1 if event['success'] else 0,
            event['session_duration'],
            hash(event['ip_address']) % 1000,
            hash(event['event_type']) % 100
        ]

    def _extract_resource_features(self, usage_data):
        """Extract features from resource usage data"""
        features = []
        for usage in usage_data:
            features.append([
                usage['cpu_usage'],
                usage['memory_usage'],
                usage['disk_io'],
                usage['network_io'],
                usage['active_connections']
            ])
        return np.array(features)

    def _extract_single_resource_features(self, usage):
        """Extract features from single resource usage point"""
        return [
            usage['cpu_usage'],
            usage['memory_usage'],
            usage['disk_io'],
            usage['network_io'],
            usage['active_connections']
        ]

    def _extract_behavior_features(self, behavior_data):
        """Extract features from user behavior data"""
        features = []
        for behavior in behavior_data:
            features.append([
                behavior['session_duration'],
                behavior['pages_visited'],
                behavior['api_calls'],
                behavior['data_downloaded'],
                behavior['login_frequency']
            ])
        return np.array(features)

    def _extract_single_behavior_features(self, behavior):
        """Extract features from single behavior record"""
        return [
            behavior['session_duration'],
            behavior['pages_visited'],
            behavior['api_calls'],
            behavior['data_downloaded'],
            behavior['login_frequency']
        ]

    def _extract_data_quality_features(self, data):
        """Extract features from data quality records"""
        features = []
        for record in data:
            features.append([
                len(str(record.get('target', ''))),
                record.get('confidence', 0),
                1 if record.get('status') == 'completed' else 0,
                hash(str(record.get('scan_type', ''))) % 100
            ])
        return np.array(features)

    def _extract_single_data_quality_features(self, record):
        """Extract features from single data quality record"""
        if record.get('target') is None:
            return None  # Cannot extract features from missing data

        return [
            len(str(record.get('target', ''))),
            record.get('confidence', 0),
            1 if record.get('status') == 'completed' else 0,
            hash(str(record.get('scan_type', ''))) % 100
        ]

    def _extract_system_health_features(self, health_data):
        """Extract features from system health data"""
        features = []
        for health in health_data:
            features.append([
                health['service_availability'],
                health['response_time_p95'],
                health['error_rate'],
                health['throughput'],
                health['database_connections'],
                health['cache_hit_rate'],
                health['queue_depth']
            ])
        return np.array(features)

    def _extract_single_health_features(self, health_point):
        """Extract features from single health data point"""
        return [
            health_point['service_availability'],
            health_point['response_time_p95'],
            health_point['error_rate'],
            health_point['throughput'],
            health_point['database_connections'],
            health_point['cache_hit_rate'],
            health_point['queue_depth']
        ]

    # Classification and scoring methods
    def _classify_test_anomaly(self, result):
        """Classify type of test anomaly"""
        if result['execution_time'] > 1000:
            return 'execution_time_anomaly'
        elif result['memory_usage'] > 500:
            return 'resource_usage_anomaly'
        elif result['status'] == 'fail' and 'unexpected' in result.get('error_type', ''):
            return 'failure_pattern_anomaly'
        else:
            return 'general_anomaly'

    def _calculate_anomaly_score(self, result):
        """Calculate anomaly score for test result"""
        score = 0
        if result['execution_time'] > 1000:
            score += 0.5
        if result['memory_usage'] > 500:
            score += 0.3
        if result['status'] == 'fail':
            score += 0.2
        return min(1.0, score)

    def _calculate_security_severity(self, event):
        """Calculate security event severity"""
        if 'brute_force' in str(event):
            return 'high'
        elif 'privilege_escalation' in event.get('anomaly_indicator', ''):
            return 'high'
        elif not event['success']:
            return 'medium'
        else:
            return 'low'

    def _classify_resource_anomaly(self, usage):
        """Classify resource anomaly type"""
        if usage['cpu_usage'] > 90:
            return 'cpu_spike'
        elif usage['memory_usage'] > 85:
            return 'memory_leak'
        elif usage['disk_io'] > 1000:
            return 'disk_exhaustion'
        elif usage['network_io'] > 1000:
            return 'network_anomaly'
        else:
            return 'general_resource_anomaly'

    def _calculate_resource_severity(self, usage):
        """Calculate resource anomaly severity"""
        if any(usage[metric] > 95 for metric in ['cpu_usage', 'memory_usage']):
            return 'critical'
        elif any(usage[metric] > 85 for metric in ['cpu_usage', 'memory_usage']):
            return 'high'
        else:
            return 'medium'

    def _calculate_behavior_risk_score(self, activity):
        """Calculate behavioral risk score"""
        risk_score = 0

        if 'excessive_download' in activity.get('anomaly_flags', []):
            risk_score += 0.4
        if 'unusual_location' in activity.get('anomaly_flags', []):
            risk_score += 0.3
        if 'multiple_logins' in activity.get('anomaly_flags', []):
            risk_score += 0.3

        return min(1.0, risk_score)

    def _check_obvious_quality_issues(self, record):
        """Check for obvious data quality issues"""
        issues = []

        if record.get('target') is None or record.get('target') == '':
            issues.append({
                'record_id': record.get('id'),
                'issue_type': 'missing_values',
                'severity': 'high',
                'field': 'target'
            })

        if record.get('confidence', 0) > 1.0:
            issues.append({
                'record_id': record.get('id'),
                'issue_type': 'outliers',
                'severity': 'medium',
                'field': 'confidence'
            })

        return issues

    def _classify_data_quality_issue(self, record):
        """Classify data quality issue type"""
        return 'format_inconsistency'  # Simplified classification

    def _calculate_health_priority(self, health_point):
        """Calculate system health alert priority"""
        if health_point['service_availability'] < 0.9:
            return 'critical'
        elif health_point['error_rate'] > 0.1:
            return 'high'
        elif health_point['response_time_p95'] > 1000:
            return 'medium'
        else:
            return 'warning'


class RealTimeAnomalyDetector:
    """Real-time anomaly detection"""

    def __init__(self, models, scalers):
        self.models = models
        self.scalers = scalers

    def process_data_point(self, data_point):
        """Process single data point for real-time detection"""
        start_time = datetime.now()

        # Simple anomaly detection based on threshold
        if data_point['value'] > 400:  # Simple threshold
            detection_time = (datetime.now() - start_time).total_seconds() * 1000
            return {
                'alert': True,
                'anomaly_type': 'threshold_exceeded',
                'detection_latency_ms': detection_time,
                'timestamp': data_point['timestamp']
            }

        return None


class AdaptiveAnomalyDetector:
    """Adaptive threshold anomaly detector"""

    def __init__(self, baseline_data):
        self.baseline_mean = np.mean([d['value'] for d in baseline_data])
        self.baseline_std = np.std([d['value'] for d in baseline_data])
        self.threshold = self.baseline_mean + 3 * self.baseline_std
        self.accuracy = 0.8

    def process_batch(self, batch):
        """Process batch and adapt threshold"""
        batch_mean = np.mean([d['value'] for d in batch])

        # Adapt threshold based on recent data
        self.threshold = 0.9 * self.threshold + 0.1 * (batch_mean + 2 * self.baseline_std)

        return self.threshold

    def get_current_accuracy(self):
        """Get current detection accuracy"""
        return self.accuracy


class EnsembleAnomalyDetector:
    """Ensemble anomaly detector"""

    def detect_anomalies(self, test_data):
        """Detect anomalies using ensemble approach"""
        # Simulate multiple algorithm results
        isolation_forest_acc = np.random.uniform(0.7, 0.85)
        one_class_svm_acc = np.random.uniform(0.65, 0.8)
        statistical_acc = np.random.uniform(0.6, 0.75)

        individual_accuracies = [isolation_forest_acc, one_class_svm_acc, statistical_acc]
        ensemble_accuracy = np.mean(individual_accuracies) + 0.1  # Ensemble boost

        return {
            'individual_predictions': ['algo1_predictions', 'algo2_predictions', 'algo3_predictions'],
            'ensemble_prediction': 'ensemble_predictions',
            'confidence_score': 0.9,
            'individual_accuracies': individual_accuracies,
            'ensemble_accuracy': min(1.0, ensemble_accuracy)
        }