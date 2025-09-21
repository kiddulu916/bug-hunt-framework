"""
Unit tests for Scanning models
"""

import pytest
from datetime import datetime, timedelta
from django.test import TestCase
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.utils import timezone

from apps.scanning.models import ScanSession, ScanStatus, ToolExecution, ToolStatus
from tests.factories import (
    ScanSessionFactory, ToolExecutionFactory, TargetFactory, VulnerabilityFactory
)
from tests.test_utils import DatabaseTestMixin


@pytest.mark.unit
class ScanSessionModelTest(TestCase, DatabaseTestMixin):
    """Test ScanSession model functionality"""

    def setUp(self):
        self.target = TargetFactory.create()
        self.scan_session_data = {
            'target': self.target,
            'session_name': 'Test Scan Session',
            'status': ScanStatus.QUEUED,
            'scan_config': {
                'tools': ['nuclei', 'nmap', 'amass'],
                'intensity': 'medium',
                'timeout': 3600
            },
            'methodology_phases': [
                'reconnaissance', 'enumeration', 'vulnerability_scanning',
                'exploitation', 'post_exploitation', 'reporting'
            ]
        }

    def test_scan_session_creation(self):
        """Test basic scan session creation"""
        scan_session = ScanSession.objects.create(**self.scan_session_data)

        self.assertEqual(scan_session.target, self.target)
        self.assertEqual(scan_session.session_name, 'Test Scan Session')
        self.assertEqual(scan_session.status, ScanStatus.QUEUED)
        self.assertEqual(scan_session.scan_config['tools'], ['nuclei', 'nmap', 'amass'])
        self.assertEqual(len(scan_session.methodology_phases), 6)
        self.assertIsNotNone(scan_session.id)
        self.assertIsNotNone(scan_session.created_at)
        self.assertIsNotNone(scan_session.updated_at)

    def test_scan_session_string_representation(self):
        """Test scan session string representation"""
        scan_session = ScanSession.objects.create(**self.scan_session_data)
        expected_str = f"Test Scan Session - {self.target.target_name}"
        self.assertEqual(str(scan_session), expected_str)

    def test_scan_session_required_fields(self):
        """Test that required fields are enforced"""
        # Missing target
        incomplete_data = self.scan_session_data.copy()
        del incomplete_data['target']

        with self.assertRaises(IntegrityError):
            ScanSession.objects.create(**incomplete_data)

        # Missing session_name
        incomplete_data = self.scan_session_data.copy()
        del incomplete_data['session_name']

        with self.assertRaises(IntegrityError):
            ScanSession.objects.create(**incomplete_data)

    def test_scan_session_status_choices(self):
        """Test status choice validation"""
        valid_statuses = [
            ScanStatus.QUEUED,
            ScanStatus.RUNNING,
            ScanStatus.PAUSED,
            ScanStatus.COMPLETED,
            ScanStatus.FAILED,
            ScanStatus.CANCELLED
        ]

        for status in valid_statuses:
            session_data = self.scan_session_data.copy()
            session_data['session_name'] = f'Test Session {status}'
            session_data['status'] = status

            scan_session = ScanSession.objects.create(**session_data)
            self.assertEqual(scan_session.status, status)

    def test_scan_session_default_values(self):
        """Test model default values"""
        minimal_data = {
            'target': self.target,
            'session_name': 'Minimal Session'
        }

        scan_session = ScanSession.objects.create(**minimal_data)

        # Check default values
        self.assertEqual(scan_session.status, ScanStatus.QUEUED)
        self.assertEqual(scan_session.scan_config, {})
        self.assertEqual(scan_session.methodology_phases, [])
        self.assertEqual(scan_session.phase_progress, {})
        self.assertEqual(scan_session.total_progress, 0.0)
        self.assertEqual(scan_session.total_subdomains_found, 0)
        self.assertEqual(scan_session.total_endpoints_found, 0)
        self.assertEqual(scan_session.total_vulnerabilities, 0)
        self.assertEqual(scan_session.critical_vulnerabilities, 0)
        self.assertEqual(scan_session.high_vulnerabilities, 0)

    def test_scan_session_json_fields(self):
        """Test JSON field functionality"""
        session_data = self.scan_session_data.copy()
        session_data['scan_config'] = {
            'tools': ['nuclei', 'nmap', 'amass', 'subfinder'],
            'intensity': 'high',
            'concurrent_scans': 10,
            'timeout': 7200,
            'nuclei_config': {
                'templates': '/nuclei-templates/',
                'concurrency': 25,
                'rate_limit': 150
            },
            'nmap_config': {
                'scan_type': 'stealth',
                'port_range': '1-65535',
                'timing': 'T4'
            }
        }

        session_data['phase_progress'] = {
            'reconnaissance': 100,
            'enumeration': 75,
            'vulnerability_scanning': 50,
            'exploitation': 25,
            'post_exploitation': 0,
            'reporting': 0
        }

        scan_session = ScanSession.objects.create(**session_data)

        # Test nested JSON structure
        self.assertEqual(len(scan_session.scan_config['tools']), 4)
        self.assertEqual(scan_session.scan_config['intensity'], 'high')
        self.assertEqual(scan_session.scan_config['nuclei_config']['concurrency'], 25)
        self.assertEqual(scan_session.scan_config['nmap_config']['timing'], 'T4')

        # Test phase progress
        self.assertEqual(scan_session.phase_progress['reconnaissance'], 100)
        self.assertEqual(scan_session.phase_progress['exploitation'], 25)

    def test_scan_session_timing_fields(self):
        """Test timing-related fields"""
        scan_session = ScanSession.objects.create(**self.scan_session_data)

        # Initially timing fields should be None
        self.assertIsNone(scan_session.started_at)
        self.assertIsNone(scan_session.completed_at)
        self.assertIsNone(scan_session.estimated_completion)

        # Set timing fields
        now = timezone.now()
        estimated_end = now + timedelta(hours=2)

        scan_session.started_at = now
        scan_session.estimated_completion = estimated_end
        scan_session.save()

        scan_session.refresh_from_db()
        self.assertEqual(scan_session.started_at, now)
        self.assertEqual(scan_session.estimated_completion, estimated_end)

    def test_scan_session_duration_property(self):
        """Test duration property calculation"""
        scan_session = ScanSession.objects.create(**self.scan_session_data)

        # Without timing data, duration should be None
        self.assertIsNone(scan_session.duration)

        # With only start time, duration should be None
        scan_session.started_at = timezone.now()
        scan_session.save()
        self.assertIsNone(scan_session.duration)

        # With both start and end times, should calculate duration
        start_time = timezone.now() - timedelta(hours=2)
        end_time = timezone.now()

        scan_session.started_at = start_time
        scan_session.completed_at = end_time
        scan_session.save()

        duration = scan_session.duration
        self.assertIsNotNone(duration)
        self.assertAlmostEqual(duration.total_seconds(), 7200, delta=60)  # ~2 hours

    def test_scan_session_is_running_property(self):
        """Test is_running property"""
        scan_session = ScanSession.objects.create(**self.scan_session_data)

        # Initially queued, not running
        self.assertFalse(scan_session.is_running)

        # Set to running
        scan_session.status = ScanStatus.RUNNING
        scan_session.save()
        self.assertTrue(scan_session.is_running)

        # Set to completed
        scan_session.status = ScanStatus.COMPLETED
        scan_session.save()
        self.assertFalse(scan_session.is_running)

    def test_scan_session_vulnerability_summary_property(self):
        """Test vulnerability_summary property"""
        scan_session = ScanSession.objects.create(**self.scan_session_data)

        # Create vulnerabilities with different severities
        VulnerabilityFactory.create(scan_session=scan_session, severity='critical')
        VulnerabilityFactory.create(scan_session=scan_session, severity='critical')
        VulnerabilityFactory.create(scan_session=scan_session, severity='high')
        VulnerabilityFactory.create(scan_session=scan_session, severity='high')
        VulnerabilityFactory.create(scan_session=scan_session, severity='high')
        VulnerabilityFactory.create(scan_session=scan_session, severity='medium')
        VulnerabilityFactory.create(scan_session=scan_session, severity='low')
        VulnerabilityFactory.create(scan_session=scan_session, severity='info')

        # Update session counters (normally done by signals/services)
        scan_session.total_vulnerabilities = 8
        scan_session.critical_vulnerabilities = 2
        scan_session.high_vulnerabilities = 3
        scan_session.save()

        summary = scan_session.vulnerability_summary

        self.assertEqual(summary['total'], 8)
        self.assertEqual(summary['critical'], 2)
        self.assertEqual(summary['high'], 3)
        self.assertEqual(summary['medium'], 1)
        self.assertEqual(summary['low'], 1)
        self.assertEqual(summary['info'], 1)

    def test_scan_session_ordering(self):
        """Test model ordering (should be by -created_at)"""
        # Create multiple scan sessions
        session1 = ScanSessionFactory.create(target=self.target)
        session2 = ScanSessionFactory.create(target=self.target)
        session3 = ScanSessionFactory.create(target=self.target)

        # Get all sessions (should be ordered by -created_at)
        sessions = list(ScanSession.objects.all())

        # The most recently created should be first
        self.assertEqual(sessions[0], session3)
        self.assertEqual(sessions[1], session2)
        self.assertEqual(sessions[2], session1)

    def test_scan_session_relationships(self):
        """Test scan session relationships with other models"""
        scan_session = ScanSession.objects.create(**self.scan_session_data)

        # Test target relationship
        self.assertEqual(scan_session.target, self.target)

        # Test reverse relationship from target
        self.assertIn(scan_session, self.target.scan_sessions.all())

        # Test tool_executions relationship exists
        self.assertTrue(hasattr(scan_session, 'tool_executions'))
        self.assertEqual(scan_session.tool_executions.count(), 0)

        # Test vulnerabilities relationship exists
        self.assertTrue(hasattr(scan_session, 'vulnerabilities'))
        self.assertEqual(scan_session.vulnerabilities.count(), 0)

    def test_scan_session_indexing(self):
        """Test that database indexes are created correctly"""
        # Create scan sessions with different attributes
        ScanSessionFactory.create_batch(3, target=self.target, status=ScanStatus.COMPLETED)
        ScanSessionFactory.create_batch(2, target=self.target, status=ScanStatus.RUNNING)

        # These queries should be efficient due to indexes
        completed_sessions = ScanSession.objects.filter(status=ScanStatus.COMPLETED)
        target_sessions = ScanSession.objects.filter(target=self.target)

        self.assertEqual(completed_sessions.count(), 3)
        self.assertEqual(target_sessions.count(), 5)

    def test_scan_session_db_table_name(self):
        """Test that the database table name is correct"""
        scan_session = ScanSession.objects.create(**self.scan_session_data)
        self.assertEqual(scan_session._meta.db_table, 'scan_sessions')


@pytest.mark.unit
class ToolExecutionModelTest(TestCase, DatabaseTestMixin):
    """Test ToolExecution model functionality"""

    def setUp(self):
        self.target = TargetFactory.create()
        self.scan_session = ScanSessionFactory.create(target=self.target)

        self.tool_execution_data = {
            'scan_session': self.scan_session,
            'tool_name': 'nuclei',
            'tool_category': 'vulnerability_scanning',
            'command_executed': 'nuclei -u https://example.com -t /nuclei-templates/',
            'status': ToolStatus.PENDING,
            'tool_parameters': {
                'templates': '/nuclei-templates/',
                'concurrency': 25,
                'rate_limit': 150,
                'timeout': 30
            }
        }

    def test_tool_execution_creation(self):
        """Test basic tool execution creation"""
        tool_execution = ToolExecution.objects.create(**self.tool_execution_data)

        self.assertEqual(tool_execution.scan_session, self.scan_session)
        self.assertEqual(tool_execution.tool_name, 'nuclei')
        self.assertEqual(tool_execution.tool_category, 'vulnerability_scanning')
        self.assertEqual(tool_execution.status, ToolStatus.PENDING)
        self.assertIsNotNone(tool_execution.id)
        self.assertIsNotNone(tool_execution.created_at)

    def test_tool_execution_string_representation(self):
        """Test tool execution string representation"""
        tool_execution = ToolExecution.objects.create(**self.tool_execution_data)
        expected_str = f"nuclei - {self.scan_session.session_name}"
        self.assertEqual(str(tool_execution), expected_str)

    def test_tool_execution_required_fields(self):
        """Test that required fields are enforced"""
        # Missing scan_session
        incomplete_data = self.tool_execution_data.copy()
        del incomplete_data['scan_session']

        with self.assertRaises(IntegrityError):
            ToolExecution.objects.create(**incomplete_data)

        # Missing tool_name
        incomplete_data = self.tool_execution_data.copy()
        del incomplete_data['tool_name']

        with self.assertRaises(IntegrityError):
            ToolExecution.objects.create(**incomplete_data)

    def test_tool_execution_status_choices(self):
        """Test status choice validation"""
        valid_statuses = [
            ToolStatus.PENDING,
            ToolStatus.RUNNING,
            ToolStatus.COMPLETED,
            ToolStatus.FAILED,
            ToolStatus.SKIPPED
        ]

        for status in valid_statuses:
            execution_data = self.tool_execution_data.copy()
            execution_data['tool_name'] = f'tool_{status}'
            execution_data['status'] = status

            tool_execution = ToolExecution.objects.create(**execution_data)
            self.assertEqual(tool_execution.status, status)

    def test_tool_execution_default_values(self):
        """Test model default values"""
        minimal_data = {
            'scan_session': self.scan_session,
            'tool_name': 'minimal_tool',
            'tool_category': 'other',
            'command_executed': 'minimal_tool --help'
        }

        tool_execution = ToolExecution.objects.create(**minimal_data)

        # Check default values
        self.assertEqual(tool_execution.status, ToolStatus.PENDING)
        self.assertEqual(tool_execution.tool_parameters, {})
        self.assertEqual(tool_execution.parsed_results_count, 0)
        self.assertEqual(tool_execution.raw_output, '')
        self.assertEqual(tool_execution.error_message, '')

    def test_tool_execution_timing_fields(self):
        """Test timing-related fields"""
        tool_execution = ToolExecution.objects.create(**self.tool_execution_data)

        # Initially timing fields should be None
        self.assertIsNone(tool_execution.started_at)
        self.assertIsNone(tool_execution.completed_at)
        self.assertIsNone(tool_execution.execution_time_seconds)

        # Set timing fields
        now = timezone.now()
        end_time = now + timedelta(seconds=45)

        tool_execution.started_at = now
        tool_execution.completed_at = end_time
        tool_execution.execution_time_seconds = 45.2
        tool_execution.save()

        tool_execution.refresh_from_db()
        self.assertEqual(tool_execution.started_at, now)
        self.assertEqual(tool_execution.completed_at, end_time)
        self.assertEqual(tool_execution.execution_time_seconds, 45.2)

    def test_tool_execution_duration_property(self):
        """Test duration property calculation"""
        tool_execution = ToolExecution.objects.create(**self.tool_execution_data)

        # Without timing data, duration should be None
        self.assertIsNone(tool_execution.duration)

        # With only start time, duration should be None
        tool_execution.started_at = timezone.now()
        tool_execution.save()
        self.assertIsNone(tool_execution.duration)

        # With both start and end times, should calculate duration
        start_time = timezone.now() - timedelta(seconds=45)
        end_time = timezone.now()

        tool_execution.started_at = start_time
        tool_execution.completed_at = end_time
        tool_execution.save()

        duration = tool_execution.duration
        self.assertIsNotNone(duration)
        self.assertAlmostEqual(duration.total_seconds(), 45, delta=5)

    def test_tool_execution_success_rate_property(self):
        """Test success_rate property"""
        # Create multiple executions for the same tool
        ToolExecutionFactory.create(
            scan_session=self.scan_session,
            tool_name='test_tool',
            status=ToolStatus.COMPLETED
        )
        ToolExecutionFactory.create(
            scan_session=self.scan_session,
            tool_name='test_tool',
            status=ToolStatus.COMPLETED
        )
        ToolExecutionFactory.create(
            scan_session=self.scan_session,
            tool_name='test_tool',
            status=ToolStatus.FAILED
        )
        test_execution = ToolExecutionFactory.create(
            scan_session=self.scan_session,
            tool_name='test_tool',
            status=ToolStatus.COMPLETED
        )

        # 3 out of 4 executions successful = 75%
        self.assertEqual(test_execution.success_rate, 75.0)

        # Create executions for different tool
        ToolExecutionFactory.create(
            scan_session=self.scan_session,
            tool_name='other_tool',
            status=ToolStatus.FAILED
        )

        # Success rate for test_tool should remain the same
        self.assertEqual(test_execution.success_rate, 75.0)

    def test_tool_execution_json_fields(self):
        """Test JSON field functionality"""
        execution_data = self.tool_execution_data.copy()
        execution_data['tool_parameters'] = {
            'general': {
                'concurrency': 25,
                'rate_limit': 150,
                'timeout': 30,
                'retries': 3
            },
            'nuclei_specific': {
                'templates': ['/nuclei-templates/cves/', '/nuclei-templates/exposures/'],
                'exclude_templates': ['/nuclei-templates/dos/'],
                'severity': ['medium', 'high', 'critical'],
                'tags': ['sqli', 'xss', 'rce']
            },
            'output': {
                'format': 'json',
                'file': '/tmp/nuclei_output.json',
                'no_color': True
            }
        }

        tool_execution = ToolExecution.objects.create(**execution_data)

        # Test nested JSON structure
        self.assertEqual(tool_execution.tool_parameters['general']['concurrency'], 25)
        self.assertEqual(len(tool_execution.tool_parameters['nuclei_specific']['templates']), 2)
        self.assertIn('xss', tool_execution.tool_parameters['nuclei_specific']['tags'])
        self.assertTrue(tool_execution.tool_parameters['output']['no_color'])

    def test_tool_execution_results_fields(self):
        """Test result-related fields"""
        execution_data = self.tool_execution_data.copy()
        execution_data.update({
            'status': ToolStatus.COMPLETED,
            'output_file_path': '/tmp/nuclei_results.json',
            'raw_output': '''[INFO] Using Nuclei Engine 2.9.4
[INFO] Using Nuclei Templates 9.5.2
[INFO] Templates loaded: 4829
[INFO] Targets loaded: 1
[INFO] Running templates against 1 targets
[MEDIUM] [ssl-issuer] [ssl] [https://example.com] [CN=Example Organization]
[HIGH] [xss-reflected] [xss] [https://example.com/search?q=test] [Parameter: q]''',
            'parsed_results_count': 2,
            'execution_time_seconds': 45.67
        })

        tool_execution = ToolExecution.objects.create(**execution_data)

        self.assertEqual(tool_execution.status, ToolStatus.COMPLETED)
        self.assertEqual(tool_execution.output_file_path, '/tmp/nuclei_results.json')
        self.assertIn('[HIGH] [xss-reflected]', tool_execution.raw_output)
        self.assertEqual(tool_execution.parsed_results_count, 2)
        self.assertEqual(tool_execution.execution_time_seconds, 45.67)

    def test_tool_execution_error_handling(self):
        """Test error handling fields"""
        execution_data = self.tool_execution_data.copy()
        execution_data.update({
            'status': ToolStatus.FAILED,
            'error_message': 'Connection timeout: Unable to connect to target after 30 seconds',
            'raw_output': 'nuclei: error: could not connect to target\nTimeout occurred',
            'execution_time_seconds': 30.0
        })

        tool_execution = ToolExecution.objects.create(**execution_data)

        self.assertEqual(tool_execution.status, ToolStatus.FAILED)
        self.assertIn('Connection timeout', tool_execution.error_message)
        self.assertIn('could not connect', tool_execution.raw_output)

    def test_tool_execution_ordering(self):
        """Test model ordering (should be by -created_at)"""
        # Create multiple tool executions
        execution1 = ToolExecutionFactory.create(scan_session=self.scan_session)
        execution2 = ToolExecutionFactory.create(scan_session=self.scan_session)
        execution3 = ToolExecutionFactory.create(scan_session=self.scan_session)

        # Get all executions (should be ordered by -created_at)
        executions = list(ToolExecution.objects.all())

        # The most recently created should be first
        self.assertEqual(executions[0], execution3)
        self.assertEqual(executions[1], execution2)
        self.assertEqual(executions[2], execution1)

    def test_tool_execution_relationships(self):
        """Test tool execution relationships"""
        tool_execution = ToolExecution.objects.create(**self.tool_execution_data)

        # Test scan_session relationship
        self.assertEqual(tool_execution.scan_session, self.scan_session)

        # Test reverse relationship from scan_session
        self.assertIn(tool_execution, self.scan_session.tool_executions.all())

    def test_tool_execution_indexing(self):
        """Test that database indexes are created correctly"""
        # Create tool executions with different attributes
        ToolExecutionFactory.create_batch(
            3, scan_session=self.scan_session, tool_name='nuclei'
        )
        ToolExecutionFactory.create_batch(
            2, scan_session=self.scan_session, tool_category='reconnaissance'
        )
        ToolExecutionFactory.create_batch(
            2, scan_session=self.scan_session, status=ToolStatus.COMPLETED
        )

        # These queries should be efficient due to indexes
        nuclei_executions = ToolExecution.objects.filter(tool_name='nuclei')
        recon_executions = ToolExecution.objects.filter(tool_category='reconnaissance')
        completed_executions = ToolExecution.objects.filter(status=ToolStatus.COMPLETED)

        self.assertEqual(nuclei_executions.count(), 3)
        self.assertEqual(recon_executions.count(), 2)
        self.assertEqual(completed_executions.count(), 2)

    def test_tool_execution_db_table_name(self):
        """Test that the database table name is correct"""
        tool_execution = ToolExecution.objects.create(**self.tool_execution_data)
        self.assertEqual(tool_execution._meta.db_table, 'tool_executions')


@pytest.mark.unit
class ScanningChoicesTest(TestCase):
    """Test scanning model choices"""

    def test_scan_status_choices(self):
        """Test ScanStatus choices"""
        expected_choices = {
            'queued': 'Queued',
            'running': 'Running',
            'paused': 'Paused',
            'completed': 'Completed',
            'failed': 'Failed',
            'cancelled': 'Cancelled'
        }

        for choice_value, choice_label in ScanStatus.choices:
            self.assertIn(choice_value, expected_choices)
            self.assertEqual(expected_choices[choice_value], choice_label)

    def test_tool_status_choices(self):
        """Test ToolStatus choices"""
        expected_choices = {
            'pending': 'Pending',
            'running': 'Running',
            'completed': 'Completed',
            'failed': 'Failed',
            'skipped': 'Skipped'
        }

        for choice_value, choice_label in ToolStatus.choices:
            self.assertIn(choice_value, expected_choices)
            self.assertEqual(expected_choices[choice_value], choice_label)


@pytest.mark.unit
class ScanningFactoryTest(TestCase):
    """Test scanning factory functionality"""

    def test_scan_session_factory_creation(self):
        """Test that ScanSessionFactory creates valid scan sessions"""
        scan_session = ScanSessionFactory.create()

        self.assertIsInstance(scan_session, ScanSession)
        self.assertIsNotNone(scan_session.target)
        self.assertIsNotNone(scan_session.session_name)
        self.assertIsNotNone(scan_session.status)

    def test_tool_execution_factory_creation(self):
        """Test that ToolExecutionFactory creates valid tool executions"""
        tool_execution = ToolExecutionFactory.create()

        self.assertIsInstance(tool_execution, ToolExecution)
        self.assertIsNotNone(tool_execution.scan_session)
        self.assertIsNotNone(tool_execution.tool_name)
        self.assertIsNotNone(tool_execution.tool_category)

    def test_scan_session_factory_realistic_data(self):
        """Test that factory generates realistic data"""
        scan_session = ScanSessionFactory.create()

        # Progress should be between 0 and 100
        self.assertGreaterEqual(scan_session.total_progress, 0.0)
        self.assertLessEqual(scan_session.total_progress, 100.0)

        # Counts should be non-negative
        self.assertGreaterEqual(scan_session.total_subdomains_found, 0)
        self.assertGreaterEqual(scan_session.total_endpoints_found, 0)
        self.assertGreaterEqual(scan_session.total_vulnerabilities, 0)

        # Scan config should contain tools
        self.assertIn('tools', scan_session.scan_config)
        self.assertIsInstance(scan_session.scan_config['tools'], list)

    def test_completed_scan_session_factory(self):
        """Test CompletedScanSessionFactory trait"""
        from tests.factories import CompletedScanSessionFactory

        completed_scan = CompletedScanSessionFactory.create()

        self.assertEqual(completed_scan.status, ScanStatus.COMPLETED)
        self.assertEqual(completed_scan.total_progress, 100.0)

        # All phases should be 100% complete
        for phase_progress in completed_scan.phase_progress.values():
            self.assertEqual(phase_progress, 100)