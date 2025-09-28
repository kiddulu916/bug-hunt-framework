"""
Enhanced Test Helper Utilities

Shared utilities for improved testing across all test suites.
"""

import pytest
import time
import tempfile
import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from unittest.mock import Mock, patch
from django.test import TestCase
from django.db import transaction
from contextlib import contextmanager

from tests.fixtures.baseline_data import PerformanceMeasurement


class EnhancedTestCase(TestCase):
    """Enhanced base test case with additional utilities"""

    def setUp(self):
        super().setUp()
        self.temp_files = []

    def tearDown(self):
        # Clean up temporary files
        for temp_file in self.temp_files:
            try:
                temp_file.unlink()
            except Exception:
                pass
        super().tearDown()

    def create_temp_file(self, content: str, suffix: str = '.json') -> Path:
        """Create temporary file with content"""
        temp_file = Path(tempfile.mktemp(suffix=suffix))
        temp_file.write_text(content)
        self.temp_files.append(temp_file)
        return temp_file

    def assert_performance_within_baseline(self, test_name: str, execution_time_ms: float, memory_mb: float = None):
        """Assert performance is within baseline expectations"""
        from tests.fixtures.baseline_data import baseline_manager

        metrics = {'execution_time_ms': execution_time_ms}
        if memory_mb:
            metrics['memory_usage_mb'] = memory_mb

        comparison = baseline_manager.compare_performance(test_name, metrics)

        if comparison.get('overall_status') == 'failed':
            failed_metrics = [k for k, v in comparison['metrics'].items() if v['status'] == 'failed']
            self.fail(f"Performance regression in {test_name}: {failed_metrics}")

    def assert_database_query_count(self, max_queries: int):
        """Assert database query count doesn't exceed limit"""
        @contextmanager
        def query_counter():
            from django.db import connection
            initial_queries = len(connection.queries)
            yield
            final_queries = len(connection.queries)
            query_count = final_queries - initial_queries
            if query_count > max_queries:
                self.fail(f"Too many database queries: {query_count} > {max_queries}")

        return query_counter()

    def create_large_dataset(self, size: str = 'medium'):
        """Create standardized large dataset for testing"""
        from tests.fixtures.large_datasets import large_dataset_generator

        if size == 'small':
            return {
                'targets': 10,
                'scans': 20,
                'vulnerabilities': 100
            }
        elif size == 'medium':
            return {
                'targets': 100,
                'scans': 200,
                'vulnerabilities': 1000
            }
        elif size == 'large':
            return {
                'targets': 1000,
                'scans': 2000,
                'vulnerabilities': 10000
            }


class MockToolExecution:
    """Mock tool execution for testing without external dependencies"""

    @staticmethod
    def mock_nuclei_success():
        """Mock successful Nuclei execution"""
        return {
            'returncode': 0,
            'stdout': json.dumps([
                {
                    "template": "test-template",
                    "info": {"name": "Test Vulnerability", "severity": "medium"},
                    "host": "https://example.com",
                    "matched-at": "https://example.com/test"
                }
            ]),
            'stderr': ''
        }

    @staticmethod
    def mock_nuclei_failure():
        """Mock failed Nuclei execution"""
        return {
            'returncode': 1,
            'stdout': '',
            'stderr': 'Template execution failed'
        }

    @staticmethod
    def mock_nmap_success():
        """Mock successful Nmap execution"""
        return {
            'returncode': 0,
            'stdout': '''
Starting Nmap 7.80
Nmap scan report for example.com (93.184.216.34)
Host is up (0.040s latency).
PORT    STATE SERVICE
80/tcp  open  http
443/tcp open  https
''',
            'stderr': ''
        }


@pytest.fixture
def enhanced_test_case():
    """Fixture providing enhanced test case utilities"""
    return EnhancedTestCase()


@pytest.fixture
def mock_tool_execution():
    """Fixture providing mock tool execution"""
    return MockToolExecution()


@pytest.fixture
def performance_monitor():
    """Fixture for monitoring test performance"""
    def _monitor(test_name: str):
        return PerformanceMeasurement(test_name, None)
    return _monitor


class TestDataValidator:
    """Validates test data integrity and consistency"""

    @staticmethod
    def validate_vulnerability_data(vulnerability_data: Dict[str, Any]) -> bool:
        """Validate vulnerability data structure"""
        required_fields = [
            'vulnerability_name', 'vulnerability_type', 'severity',
            'affected_url', 'confidence_level'
        ]

        for field in required_fields:
            if field not in vulnerability_data:
                return False

        # Validate severity values
        valid_severities = ['critical', 'high', 'medium', 'low', 'info']
        if vulnerability_data['severity'] not in valid_severities:
            return False

        # Validate confidence level
        confidence = vulnerability_data.get('confidence_level', 0)
        if not (0.0 <= confidence <= 1.0):
            return False

        return True

    @staticmethod
    def validate_scan_results(scan_results: Dict[str, Any]) -> bool:
        """Validate scan results structure"""
        required_fields = ['status', 'vulnerabilities', 'execution_time']

        for field in required_fields:
            if field not in scan_results:
                return False

        # Validate vulnerabilities
        if not isinstance(scan_results['vulnerabilities'], list):
            return False

        for vuln in scan_results['vulnerabilities']:
            if not TestDataValidator.validate_vulnerability_data(vuln):
                return False

        return True


@pytest.fixture
def data_validator():
    """Fixture providing data validation utilities"""
    return TestDataValidator()