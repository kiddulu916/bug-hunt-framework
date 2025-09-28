"""
Performance Baseline Datasets

Standardized datasets for establishing performance baselines and
regression testing across different system configurations.
"""

import pytest
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any
from dataclasses import dataclass, asdict
from pathlib import Path

from tests.factories import TargetFactory, ScanSessionFactory, VulnerabilityFactory


@dataclass
class PerformanceBaseline:
    """Performance baseline data structure"""
    test_name: str
    dataset_size: str
    target_count: int
    scan_count: int
    vulnerability_count: int
    expected_execution_time_ms: float
    expected_memory_usage_mb: float
    expected_db_queries: int
    baseline_date: str
    environment_config: Dict[str, Any]
    success_criteria: Dict[str, Any]


class BaselineDataManager:
    """Manages performance baseline datasets and metrics"""

    def __init__(self):
        self.baselines_dir = Path(__file__).parent / 'baselines'
        self.baselines_dir.mkdir(exist_ok=True)

    def create_baseline_datasets(self) -> Dict[str, Any]:
        """Create standardized baseline datasets for different test scenarios"""
        baselines = {}

        # Database Query Performance Baselines
        baselines['db_query_performance'] = self._create_db_query_baselines()

        # API Response Time Baselines
        baselines['api_response_time'] = self._create_api_response_baselines()

        # Scanner Engine Performance Baselines
        baselines['scanner_performance'] = self._create_scanner_performance_baselines()

        # Memory Usage Baselines
        baselines['memory_usage'] = self._create_memory_usage_baselines()

        # Concurrent Operations Baselines
        baselines['concurrent_operations'] = self._create_concurrent_operation_baselines()

        return baselines

    def _create_db_query_baselines(self) -> List[PerformanceBaseline]:
        """Create database query performance baselines"""
        baselines = []

        # Small dataset baseline
        small_baseline = PerformanceBaseline(
            test_name='db_query_small_dataset',
            dataset_size='small',
            target_count=10,
            scan_count=20,
            vulnerability_count=100,
            expected_execution_time_ms=50.0,
            expected_memory_usage_mb=10.0,
            expected_db_queries=5,
            baseline_date=datetime.now().isoformat(),
            environment_config={
                'database': 'postgresql',
                'connection_pool_size': 10,
                'shared_buffers': '128MB'
            },
            success_criteria={
                'max_execution_time_ms': 100.0,
                'max_memory_usage_mb': 20.0,
                'max_db_queries': 10
            }
        )
        baselines.append(small_baseline)

        # Medium dataset baseline
        medium_baseline = PerformanceBaseline(
            test_name='db_query_medium_dataset',
            dataset_size='medium',
            target_count=100,
            scan_count=200,
            vulnerability_count=1000,
            expected_execution_time_ms=200.0,
            expected_memory_usage_mb=50.0,
            expected_db_queries=15,
            baseline_date=datetime.now().isoformat(),
            environment_config={
                'database': 'postgresql',
                'connection_pool_size': 20,
                'shared_buffers': '256MB'
            },
            success_criteria={
                'max_execution_time_ms': 500.0,
                'max_memory_usage_mb': 100.0,
                'max_db_queries': 30
            }
        )
        baselines.append(medium_baseline)

        # Large dataset baseline
        large_baseline = PerformanceBaseline(
            test_name='db_query_large_dataset',
            dataset_size='large',
            target_count=1000,
            scan_count=2000,
            vulnerability_count=10000,
            expected_execution_time_ms=1000.0,
            expected_memory_usage_mb=200.0,
            expected_db_queries=50,
            baseline_date=datetime.now().isoformat(),
            environment_config={
                'database': 'postgresql',
                'connection_pool_size': 50,
                'shared_buffers': '512MB'
            },
            success_criteria={
                'max_execution_time_ms': 2000.0,
                'max_memory_usage_mb': 400.0,
                'max_db_queries': 100
            }
        )
        baselines.append(large_baseline)

        return baselines

    def _create_api_response_baselines(self) -> List[PerformanceBaseline]:
        """Create API response time baselines"""
        baselines = []

        # API endpoint performance baselines
        endpoints = [
            {
                'name': 'list_targets',
                'expected_time_ms': 100.0,
                'max_time_ms': 250.0,
                'dataset_size': 'medium'
            },
            {
                'name': 'list_vulnerabilities',
                'expected_time_ms': 150.0,
                'max_time_ms': 300.0,
                'dataset_size': 'medium'
            },
            {
                'name': 'vulnerability_search',
                'expected_time_ms': 200.0,
                'max_time_ms': 500.0,
                'dataset_size': 'large'
            },
            {
                'name': 'scan_statistics',
                'expected_time_ms': 300.0,
                'max_time_ms': 600.0,
                'dataset_size': 'large'
            }
        ]

        for endpoint in endpoints:
            baseline = PerformanceBaseline(
                test_name=f'api_{endpoint["name"]}',
                dataset_size=endpoint['dataset_size'],
                target_count=100 if endpoint['dataset_size'] == 'medium' else 1000,
                scan_count=200 if endpoint['dataset_size'] == 'medium' else 2000,
                vulnerability_count=1000 if endpoint['dataset_size'] == 'medium' else 10000,
                expected_execution_time_ms=endpoint['expected_time_ms'],
                expected_memory_usage_mb=25.0,
                expected_db_queries=10,
                baseline_date=datetime.now().isoformat(),
                environment_config={
                    'api_framework': 'fastapi',
                    'worker_processes': 4,
                    'worker_connections': 1000
                },
                success_criteria={
                    'max_execution_time_ms': endpoint['max_time_ms'],
                    'max_memory_usage_mb': 50.0,
                    'max_db_queries': 20
                }
            )
            baselines.append(baseline)

        return baselines

    def _create_scanner_performance_baselines(self) -> List[PerformanceBaseline]:
        """Create scanner engine performance baselines"""
        baselines = []

        scanner_engines = [
            {
                'name': 'nuclei_engine',
                'expected_time_ms': 5000.0,  # 5 seconds
                'max_time_ms': 15000.0,      # 15 seconds
                'memory_mb': 100.0
            },
            {
                'name': 'custom_web_engine',
                'expected_time_ms': 8000.0,  # 8 seconds
                'max_time_ms': 20000.0,      # 20 seconds
                'memory_mb': 150.0
            },
            {
                'name': 'recon_engine',
                'expected_time_ms': 10000.0, # 10 seconds
                'max_time_ms': 30000.0,      # 30 seconds
                'memory_mb': 200.0
            }
        ]

        for scanner in scanner_engines:
            baseline = PerformanceBaseline(
                test_name=f'scanner_{scanner["name"]}',
                dataset_size='standard',
                target_count=1,
                scan_count=1,
                vulnerability_count=0,  # Varies by scanner
                expected_execution_time_ms=scanner['expected_time_ms'],
                expected_memory_usage_mb=scanner['memory_mb'],
                expected_db_queries=5,
                baseline_date=datetime.now().isoformat(),
                environment_config={
                    'scanner_engine': scanner['name'],
                    'concurrency': 25,
                    'rate_limit': 150,
                    'timeout': 30
                },
                success_criteria={
                    'max_execution_time_ms': scanner['max_time_ms'],
                    'max_memory_usage_mb': scanner['memory_mb'] * 2,
                    'max_db_queries': 15
                }
            )
            baselines.append(baseline)

        return baselines

    def _create_memory_usage_baselines(self) -> List[PerformanceBaseline]:
        """Create memory usage baselines for different operations"""
        baselines = []

        memory_scenarios = [
            {
                'name': 'bulk_vulnerability_creation',
                'count': 1000,
                'expected_memory_mb': 50.0,
                'max_memory_mb': 100.0
            },
            {
                'name': 'large_report_generation',
                'count': 1,
                'expected_memory_mb': 200.0,
                'max_memory_mb': 400.0
            },
            {
                'name': 'concurrent_scan_execution',
                'count': 10,
                'expected_memory_mb': 300.0,
                'max_memory_mb': 600.0
            }
        ]

        for scenario in memory_scenarios:
            baseline = PerformanceBaseline(
                test_name=f'memory_{scenario["name"]}',
                dataset_size='variable',
                target_count=scenario['count'] if 'scan' in scenario['name'] else 1,
                scan_count=scenario['count'] if 'scan' in scenario['name'] else 1,
                vulnerability_count=scenario['count'] if 'vulnerability' in scenario['name'] else 0,
                expected_execution_time_ms=1000.0,
                expected_memory_usage_mb=scenario['expected_memory_mb'],
                expected_db_queries=10,
                baseline_date=datetime.now().isoformat(),
                environment_config={
                    'operation_type': scenario['name'],
                    'batch_size': 100
                },
                success_criteria={
                    'max_execution_time_ms': 5000.0,
                    'max_memory_usage_mb': scenario['max_memory_mb'],
                    'max_db_queries': 50
                }
            )
            baselines.append(baseline)

        return baselines

    def _create_concurrent_operation_baselines(self) -> List[PerformanceBaseline]:
        """Create concurrent operation performance baselines"""
        baselines = []

        concurrent_scenarios = [
            {
                'name': 'concurrent_api_requests',
                'concurrency': 10,
                'expected_time_ms': 500.0,
                'max_time_ms': 1000.0
            },
            {
                'name': 'concurrent_database_queries',
                'concurrency': 20,
                'expected_time_ms': 200.0,
                'max_time_ms': 500.0
            },
            {
                'name': 'concurrent_scan_sessions',
                'concurrency': 5,
                'expected_time_ms': 10000.0,
                'max_time_ms': 20000.0
            }
        ]

        for scenario in concurrent_scenarios:
            baseline = PerformanceBaseline(
                test_name=f'concurrent_{scenario["name"]}',
                dataset_size='medium',
                target_count=100,
                scan_count=scenario['concurrency'],
                vulnerability_count=500,
                expected_execution_time_ms=scenario['expected_time_ms'],
                expected_memory_usage_mb=100.0,
                expected_db_queries=scenario['concurrency'] * 5,
                baseline_date=datetime.now().isoformat(),
                environment_config={
                    'concurrency_level': scenario['concurrency'],
                    'operation_type': scenario['name']
                },
                success_criteria={
                    'max_execution_time_ms': scenario['max_time_ms'],
                    'max_memory_usage_mb': 200.0,
                    'max_db_queries': scenario['concurrency'] * 10
                }
            )
            baselines.append(baseline)

        return baselines

    def save_baseline(self, baseline: PerformanceBaseline) -> Path:
        """Save baseline to JSON file"""
        filename = f"{baseline.test_name}_{baseline.dataset_size}_{baseline.baseline_date[:10]}.json"
        filepath = self.baselines_dir / filename

        with open(filepath, 'w') as f:
            json.dump(asdict(baseline), f, indent=2)

        return filepath

    def load_baseline(self, test_name: str, dataset_size: str = None) -> PerformanceBaseline:
        """Load most recent baseline for a test"""
        pattern = f"{test_name}_{dataset_size}_*.json" if dataset_size else f"{test_name}_*.json"

        baseline_files = list(self.baselines_dir.glob(pattern))
        if not baseline_files:
            raise FileNotFoundError(f"No baseline found for {test_name}")

        # Get most recent baseline
        latest_file = max(baseline_files, key=lambda x: x.stat().st_mtime)

        with open(latest_file, 'r') as f:
            baseline_data = json.load(f)

        return PerformanceBaseline(**baseline_data)

    def compare_performance(self, test_name: str, actual_metrics: Dict[str, float]) -> Dict[str, Any]:
        """Compare actual performance against baseline"""
        try:
            baseline = self.load_baseline(test_name)
        except FileNotFoundError:
            return {
                'status': 'no_baseline',
                'message': f'No baseline found for {test_name}'
            }

        comparison = {
            'test_name': test_name,
            'baseline_date': baseline.baseline_date,
            'comparison_date': datetime.now().isoformat(),
            'metrics': {},
            'overall_status': 'passed'
        }

        # Compare each metric
        for metric, actual_value in actual_metrics.items():
            expected_key = f'expected_{metric}'
            max_key = f'max_{metric}'

            if hasattr(baseline, expected_key):
                expected_value = getattr(baseline, expected_key)
                max_value = baseline.success_criteria.get(max_key, expected_value * 2)

                metric_comparison = {
                    'actual': actual_value,
                    'expected': expected_value,
                    'max_allowed': max_value,
                    'difference_pct': ((actual_value - expected_value) / expected_value) * 100,
                    'status': 'passed' if actual_value <= max_value else 'failed'
                }

                if metric_comparison['status'] == 'failed':
                    comparison['overall_status'] = 'failed'

                comparison['metrics'][metric] = metric_comparison

        return comparison

    def generate_baseline_report(self, baselines: List[PerformanceBaseline]) -> str:
        """Generate a summary report of all baselines"""
        report_lines = [
            "# Performance Baseline Report",
            f"Generated: {datetime.now().isoformat()}",
            f"Total Baselines: {len(baselines)}",
            ""
        ]

        # Group by test category
        categories = {}
        for baseline in baselines:
            category = baseline.test_name.split('_')[0]
            if category not in categories:
                categories[category] = []
            categories[category].append(baseline)

        for category, baseline_list in categories.items():
            report_lines.extend([
                f"## {category.title()} Baselines",
                ""
            ])

            for baseline in baseline_list:
                report_lines.extend([
                    f"### {baseline.test_name}",
                    f"- Dataset Size: {baseline.dataset_size}",
                    f"- Expected Execution Time: {baseline.expected_execution_time_ms}ms",
                    f"- Expected Memory Usage: {baseline.expected_memory_usage_mb}MB",
                    f"- Expected DB Queries: {baseline.expected_db_queries}",
                    f"- Success Criteria: Max {baseline.success_criteria['max_execution_time_ms']}ms",
                    ""
                ])

        return "\n".join(report_lines)


# Global baseline manager instance
baseline_manager = BaselineDataManager()


@pytest.fixture(scope='session')
def performance_baselines():
    """Fixture providing performance baselines"""
    return baseline_manager.create_baseline_datasets()


@pytest.fixture(scope='function')
def baseline_comparator():
    """Fixture providing baseline comparison functionality"""
    return baseline_manager


@pytest.fixture(scope='session')
def benchmark_datasets():
    """Create standardized benchmark datasets with known performance characteristics"""
    datasets = {}

    # Quick benchmark (for CI/CD)
    datasets['quick'] = {
        'targets': TargetFactory.create_batch(5),
        'expected_query_time_ms': 50,
        'expected_api_time_ms': 100
    }

    # Standard benchmark (for regular testing)
    datasets['standard'] = {
        'targets': TargetFactory.create_batch(50),
        'expected_query_time_ms': 200,
        'expected_api_time_ms': 300
    }

    # Comprehensive benchmark (for performance validation)
    datasets['comprehensive'] = {
        'targets': TargetFactory.create_batch(200),
        'expected_query_time_ms': 500,
        'expected_api_time_ms': 750
    }

    return datasets


class PerformanceMeasurement:
    """Context manager for measuring performance metrics"""

    def __init__(self, test_name: str, baseline_manager: BaselineDataManager):
        self.test_name = test_name
        self.baseline_manager = baseline_manager
        self.start_time = None
        self.start_memory = None

    def __enter__(self):
        import psutil
        import os

        self.start_time = time.perf_counter()
        process = psutil.Process(os.getpid())
        self.start_memory = process.memory_info().rss / 1024 / 1024  # MB

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        import psutil
        import os

        end_time = time.perf_counter()
        process = psutil.Process(os.getpid())
        end_memory = process.memory_info().rss / 1024 / 1024  # MB

        execution_time_ms = (end_time - self.start_time) * 1000
        memory_usage_mb = end_memory - self.start_memory

        # Compare against baseline
        actual_metrics = {
            'execution_time_ms': execution_time_ms,
            'memory_usage_mb': memory_usage_mb
        }

        comparison = self.baseline_manager.compare_performance(
            self.test_name, actual_metrics
        )

        # Store results for test validation
        self.results = {
            'execution_time_ms': execution_time_ms,
            'memory_usage_mb': memory_usage_mb,
            'baseline_comparison': comparison
        }


@pytest.fixture
def performance_measurement():
    """Fixture for measuring test performance"""
    def _measurement(test_name: str):
        return PerformanceMeasurement(test_name, baseline_manager)
    return _measurement