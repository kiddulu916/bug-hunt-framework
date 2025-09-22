"""
Performance tests for Bug Bounty Automation Platform
"""

import pytest
import time
import asyncio
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import Mock, patch
from django.test import TestCase, TransactionTestCase
from django.db import transaction, connections
from django.core.management import call_command

from apps.targets.models import Target
from apps.scanning.models import ScanSession, ToolExecution
from apps.vulnerabilities.models import Vulnerability

from tests.factories import TargetFactory, ScanSessionFactory, VulnerabilityFactory
from services.scanning_service import ScanningService
from services.exploitation_service import ExploitationService


@pytest.mark.performance
@pytest.mark.django_db
class TestDatabasePerformance(TestCase):
    """Test database query performance and optimization"""

    def setUp(self):
        # Create test data for performance testing
        self.targets = TargetFactory.create_batch(100)
        self.scan_sessions = []
        self.vulnerabilities = []

        for target in self.targets:
            scan_session = ScanSessionFactory(target=target)
            self.scan_sessions.append(scan_session)

            # Create multiple vulnerabilities per scan session
            vulns = VulnerabilityFactory.create_batch(10, scan_session=scan_session)
            self.vulnerabilities.extend(vulns)

    def test_target_query_performance(self):
        """Test target query performance with large dataset"""

        start_time = time.time()

        # Query all targets with related data
        targets = Target.objects.select_related('platform').prefetch_related(
            'scan_sessions__vulnerabilities'
        ).all()

        # Force evaluation
        target_count = len(list(targets))

        end_time = time.time()
        query_time = end_time - start_time

        # Performance assertion - should complete in under 1 second
        self.assertLess(query_time, 1.0, f"Target query took {query_time:.2f}s, expected < 1.0s")
        self.assertEqual(target_count, 100)

    def test_vulnerability_aggregation_performance(self):
        """Test vulnerability aggregation query performance"""

        start_time = time.time()

        # Complex aggregation query
        from django.db.models import Count, Avg
        vulnerability_stats = Vulnerability.objects.values(
            'vulnerability_type', 'severity'
        ).annotate(
            count=Count('id'),
            avg_cvss=Avg('cvss_score')
        ).order_by('vulnerability_type', 'severity')

        # Force evaluation
        stats_list = list(vulnerability_stats)

        end_time = time.time()
        query_time = end_time - start_time

        # Performance assertion
        self.assertLess(query_time, 0.5, f"Aggregation query took {query_time:.2f}s, expected < 0.5s")
        self.assertGreater(len(stats_list), 0)

    def test_bulk_insert_performance(self):
        """Test bulk insert performance for vulnerabilities"""

        # Prepare bulk vulnerability data
        scan_session = ScanSessionFactory()
        vulnerability_data = []

        for i in range(1000):
            vulnerability_data.append(Vulnerability(
                scan_session=scan_session,
                vulnerability_name=f'Test Vulnerability {i}',
                vulnerability_type='xss_reflected',
                severity='medium',
                affected_url=f'https://example.com/page{i}',
                confidence_level=0.8
            ))

        start_time = time.time()

        # Bulk create vulnerabilities
        Vulnerability.objects.bulk_create(vulnerability_data, batch_size=100)

        end_time = time.time()
        insert_time = end_time - start_time

        # Performance assertion - should complete in under 2 seconds
        self.assertLess(insert_time, 2.0, f"Bulk insert took {insert_time:.2f}s, expected < 2.0s")

        # Verify all records were created
        created_count = Vulnerability.objects.filter(scan_session=scan_session).count()
        self.assertEqual(created_count, 1000)

    @pytest.mark.benchmark
    def test_database_connection_pooling(self):
        """Test database connection pool performance"""

        def query_database():
            """Simple database query function"""
            return Target.objects.count()

        start_time = time.time()

        # Execute multiple concurrent database queries
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(query_database) for _ in range(50)]
            results = [future.result() for future in futures]

        end_time = time.time()
        concurrent_time = end_time - start_time

        # Performance assertion
        self.assertLess(concurrent_time, 5.0, f"Concurrent queries took {concurrent_time:.2f}s")
        self.assertEqual(len(results), 50)


@pytest.mark.performance
@pytest.mark.django_db
class TestScanningPerformance(TransactionTestCase):
    """Test scanning service performance"""

    def setUp(self):
        self.targets = TargetFactory.create_batch(10)
        self.scanning_service = ScanningService()

    @patch('services.scanner_engines.nuclei_engine.NucleiEngine.execute_scan')
    def test_parallel_scan_performance(self, mock_nuclei):
        """Test parallel scanning performance"""

        # Mock fast scan results
        mock_nuclei.return_value = {
            'status': 'completed',
            'vulnerabilities': [{'type': 'test', 'severity': 'low'}]
        }

        start_time = time.time()

        # Execute parallel scans
        scan_futures = []
        for target in self.targets:
            scan_session = ScanSessionFactory(target=target)
            future = self.scanning_service.execute_scan_async(scan_session.id)
            scan_futures.append(future)

        # Wait for all scans to complete
        results = asyncio.gather(*scan_futures)

        end_time = time.time()
        parallel_time = end_time - start_time

        # Performance assertion - parallel should be faster than sequential
        self.assertLess(parallel_time, 10.0, f"Parallel scans took {parallel_time:.2f}s")

    def test_scan_result_processing_performance(self):
        """Test scan result processing performance"""

        # Create large scan result dataset
        scan_session = ScanSessionFactory()
        large_scan_results = {
            'vulnerabilities': [
                {
                    'name': f'Vulnerability {i}',
                    'type': 'xss_reflected',
                    'severity': 'medium',
                    'url': f'https://example.com/page{i}',
                    'confidence': 0.8
                } for i in range(500)
            ]
        }

        start_time = time.time()

        # Process scan results
        processed_count = self.scanning_service.process_scan_results(
            scan_session.id, large_scan_results
        )

        end_time = time.time()
        processing_time = end_time - start_time

        # Performance assertion
        self.assertLess(processing_time, 3.0, f"Result processing took {processing_time:.2f}s")
        self.assertEqual(processed_count, 500)

    @pytest.mark.benchmark
    def test_memory_usage_during_large_scan(self):
        """Test memory usage during large scan operations"""

        import psutil
        import os

        process = psutil.Process(os.getpid())
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB

        # Create large scan session with many tool executions
        scan_session = ScanSessionFactory()

        # Simulate large scan with many results
        for i in range(100):
            ToolExecution.objects.create(
                scan_session=scan_session,
                tool_name=f'test_tool_{i}',
                tool_category='vulnerability_scanning',
                command_executed=f'test_command_{i}',
                status='completed',
                raw_output='Large scan output ' * 1000,  # Simulate large output
                parsed_results_count=10
            )

        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        memory_increase = final_memory - initial_memory

        # Memory usage assertion - should not exceed 100MB increase
        self.assertLess(memory_increase, 100, f"Memory increased by {memory_increase:.2f}MB")


@pytest.mark.performance
@pytest.mark.django_db
class TestAPIPerformance(TestCase):
    """Test API endpoint performance"""

    def setUp(self):
        from rest_framework.test import APIClient
        from django.contrib.auth import get_user_model
        from rest_framework_simplejwt.tokens import RefreshToken

        User = get_user_model()
        self.user = User.objects.create_user(
            username='perf_test',
            email='perf@test.com',
            password='testpass'
        )

        self.client = APIClient()
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Create test data
        self.targets = TargetFactory.create_batch(50)

    def test_target_list_api_performance(self):
        """Test target list API performance with pagination"""

        start_time = time.time()

        # Request target list with pagination
        response = self.client.get('/api/targets/?page=1&page_size=20')

        end_time = time.time()
        api_time = end_time - start_time

        # Performance assertion
        self.assertLess(api_time, 1.0, f"Target list API took {api_time:.2f}s")
        self.assertEqual(response.status_code, 200)
        self.assertIn('results', response.data)

    def test_vulnerability_search_api_performance(self):
        """Test vulnerability search API performance"""

        # Create vulnerabilities for searching
        scan_sessions = [ScanSessionFactory(target=target) for target in self.targets[:10]]
        for session in scan_sessions:
            VulnerabilityFactory.create_batch(5, scan_session=session)

        start_time = time.time()

        # Search vulnerabilities
        response = self.client.get('/api/vulnerabilities/?search=sql&severity=high')

        end_time = time.time()
        search_time = end_time - start_time

        # Performance assertion
        self.assertLess(search_time, 2.0, f"Vulnerability search took {search_time:.2f}s")
        self.assertEqual(response.status_code, 200)

    def test_concurrent_api_requests_performance(self):
        """Test concurrent API request handling"""

        def make_api_request():
            """Make API request"""
            response = self.client.get('/api/targets/')
            return response.status_code

        start_time = time.time()

        # Make concurrent API requests
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(make_api_request) for _ in range(100)]
            status_codes = [future.result() for future in futures]

        end_time = time.time()
        concurrent_time = end_time - start_time

        # Performance assertion
        self.assertLess(concurrent_time, 10.0, f"Concurrent API requests took {concurrent_time:.2f}s")
        self.assertTrue(all(code == 200 for code in status_codes))


@pytest.mark.performance
class TestAsyncPerformance:
    """Test asynchronous operation performance"""

    @pytest.mark.asyncio
    async def test_async_exploitation_performance(self):
        """Test asynchronous exploitation performance"""

        async def mock_exploit_vulnerability(vuln_id):
            """Mock exploitation function"""
            await asyncio.sleep(0.1)  # Simulate work
            return {'success': True, 'vulnerability_id': vuln_id}

        start_time = time.time()

        # Execute parallel exploitations
        vulnerability_ids = list(range(1, 51))  # 50 vulnerabilities
        tasks = [mock_exploit_vulnerability(vid) for vid in vulnerability_ids]
        results = await asyncio.gather(*tasks)

        end_time = time.time()
        async_time = end_time - start_time

        # Performance assertion - parallel should be much faster than sequential
        self.assertLess(async_time, 2.0, f"Async exploitations took {async_time:.2f}s")
        self.assertEqual(len(results), 50)

    @pytest.mark.asyncio
    async def test_async_scan_coordination_performance(self):
        """Test asynchronous scan coordination performance"""

        async def mock_scan_engine(engine_name, duration=0.2):
            """Mock scan engine"""
            await asyncio.sleep(duration)
            return {
                'engine': engine_name,
                'status': 'completed',
                'vulnerabilities_found': 5
            }

        start_time = time.time()

        # Coordinate multiple scan engines
        engines = ['nuclei', 'custom_web', 'custom_infra', 'custom_api']
        tasks = [mock_scan_engine(engine) for engine in engines]
        results = await asyncio.gather(*tasks)

        end_time = time.time()
        coordination_time = end_time - start_time

        # Performance assertion
        self.assertLess(coordination_time, 1.0, f"Scan coordination took {coordination_time:.2f}s")
        self.assertEqual(len(results), 4)


@pytest.mark.performance
class TestCachePerformance(TestCase):
    """Test caching performance"""

    def setUp(self):
        from django.core.cache import cache
        self.cache = cache

    def test_vulnerability_cache_performance(self):
        """Test vulnerability data caching performance"""

        # Create test vulnerabilities
        scan_session = ScanSessionFactory()
        vulnerabilities = VulnerabilityFactory.create_batch(100, scan_session=scan_session)

        # Test cache miss performance
        cache_key = f'scan_vulnerabilities_{scan_session.id}'

        start_time = time.time()
        cached_data = self.cache.get(cache_key)
        if cached_data is None:
            # Simulate expensive query
            vuln_data = list(Vulnerability.objects.filter(
                scan_session=scan_session
            ).values())
            self.cache.set(cache_key, vuln_data, timeout=300)
            cached_data = vuln_data

        end_time = time.time()
        cache_miss_time = end_time - start_time

        # Test cache hit performance
        start_time = time.time()
        cached_data = self.cache.get(cache_key)
        end_time = time.time()
        cache_hit_time = end_time - start_time

        # Performance assertions
        self.assertLess(cache_miss_time, 0.5, f"Cache miss took {cache_miss_time:.2f}s")
        self.assertLess(cache_hit_time, 0.01, f"Cache hit took {cache_hit_time:.2f}s")
        self.assertEqual(len(cached_data), 100)

    def test_scan_result_cache_invalidation_performance(self):
        """Test cache invalidation performance"""

        # Setup cache data
        scan_session = ScanSessionFactory()
        cache_keys = [f'scan_data_{scan_session.id}_{i}' for i in range(50)]

        for key in cache_keys:
            self.cache.set(key, {'data': 'test'}, timeout=300)

        start_time = time.time()

        # Invalidate multiple cache keys
        self.cache.delete_many(cache_keys)

        end_time = time.time()
        invalidation_time = end_time - start_time

        # Performance assertion
        self.assertLess(invalidation_time, 0.1, f"Cache invalidation took {invalidation_time:.2f}s")


@pytest.mark.performance
@pytest.mark.benchmark
def test_scan_throughput_benchmark():
    """Benchmark scan throughput"""

    def simulate_scan():
        """Simulate a complete scan cycle"""
        time.sleep(0.01)  # Simulate scan work
        return {'vulnerabilities_found': 3}

    start_time = time.time()

    # Execute many scans to measure throughput
    results = []
    for _ in range(1000):
        result = simulate_scan()
        results.append(result)

    end_time = time.time()
    total_time = end_time - start_time

    # Calculate throughput
    throughput = len(results) / total_time

    # Benchmark assertion - should handle at least 50 scans per second
    assert throughput > 50, f"Scan throughput: {throughput:.2f} scans/sec, expected > 50"


@pytest.mark.performance
@pytest.mark.load_test
class TestLoadTesting(TestCase):
    """Load testing scenarios"""

    def test_high_volume_vulnerability_creation(self):
        """Test system behavior under high vulnerability creation load"""

        scan_sessions = ScanSessionFactory.create_batch(10)

        start_time = time.time()

        # Create high volume of vulnerabilities
        vulnerability_count = 0
        for session in scan_sessions:
            vulnerabilities = VulnerabilityFactory.create_batch(200, scan_session=session)
            vulnerability_count += len(vulnerabilities)

        end_time = time.time()
        creation_time = end_time - start_time

        # Load test assertion
        self.assertLess(creation_time, 30.0, f"High volume creation took {creation_time:.2f}s")
        self.assertEqual(vulnerability_count, 2000)

    def test_concurrent_scan_execution_load(self):
        """Test concurrent scan execution under load"""

        def execute_mock_scan(target_id):
            """Mock scan execution"""
            time.sleep(0.1)  # Simulate scan work
            return {'target_id': target_id, 'status': 'completed'}

        targets = TargetFactory.create_batch(20)

        start_time = time.time()

        # Execute concurrent scans
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(execute_mock_scan, target.id) for target in targets]
            results = [future.result() for future in futures]

        end_time = time.time()
        concurrent_time = end_time - start_time

        # Load test assertion
        self.assertLess(concurrent_time, 5.0, f"Concurrent load took {concurrent_time:.2f}s")
        self.assertEqual(len(results), 20)