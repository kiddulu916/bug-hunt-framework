"""
Integration tests for Scanning API endpoints
"""

import pytest
import json
from unittest.mock import Mock, patch, AsyncMock
from django.test import TransactionTestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.scanning.models import ScanSession, ScanStatus, ToolExecution, ToolStatus
from apps.targets.models import Target
from tests.factories import UserFactory, TargetFactory, ScanSessionFactory, ToolExecutionFactory


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
class TestScanningAPIEndpoints(TransactionTestCase):
    """Test scanning API endpoints"""

    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory()
        self.target = TargetFactory()

        # Authenticate client
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    def test_create_scan_session(self):
        """Test creating a new scan session"""
        scan_data = {
            'target_id': self.target.id,
            'session_name': 'Test Comprehensive Scan',
            'scan_config': {
                'tools': ['nuclei', 'nmap', 'amass'],
                'intensity': 'medium',
                'concurrent_scans': 5
            },
            'methodology_phases': ['reconnaissance', 'scanning', 'exploitation']
        }

        response = self.client.post('/api/scanning/', scan_data, format='json')
        self.assertEqual(response.status_code, 201)

        # Verify scan session was created
        scan_session = ScanSession.objects.get(id=response.data['id'])
        self.assertEqual(scan_session.session_name, 'Test Comprehensive Scan')
        self.assertEqual(scan_session.target, self.target)
        self.assertEqual(scan_session.status, ScanStatus.QUEUED)

    def test_list_scan_sessions(self):
        """Test listing scan sessions"""
        scan_sessions = ScanSessionFactory.create_batch(3, target=self.target)

        response = self.client.get('/api/scanning/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 3)

    def test_retrieve_scan_session(self):
        """Test retrieving a specific scan session"""
        scan_session = ScanSessionFactory(target=self.target)

        response = self.client.get(f'/api/scanning/{scan_session.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['id'], scan_session.id)
        self.assertEqual(response.data['session_name'], scan_session.session_name)

    def test_update_scan_session(self):
        """Test updating a scan session"""
        scan_session = ScanSessionFactory(
            target=self.target,
            status=ScanStatus.QUEUED
        )

        update_data = {
            'status': ScanStatus.RUNNING,
            'current_phase': 'vulnerability_scanning',
            'total_progress': 25.5
        }

        response = self.client.patch(
            f'/api/scanning/{scan_session.id}/',
            update_data,
            format='json'
        )
        self.assertEqual(response.status_code, 200)

        # Verify update
        scan_session.refresh_from_db()
        self.assertEqual(scan_session.status, ScanStatus.RUNNING)
        self.assertEqual(scan_session.current_phase, 'vulnerability_scanning')
        self.assertEqual(scan_session.total_progress, 25.5)

    @patch('services.scanning_service.ScanningService.start_scan')
    def test_start_scan(self, mock_start_scan):
        """Test starting a scan session"""
        mock_start_scan.return_value = {'task_id': 'test-task-123', 'status': 'started'}

        scan_session = ScanSessionFactory(target=self.target, status=ScanStatus.QUEUED)

        response = self.client.post(f'/api/scanning/{scan_session.id}/start/')
        self.assertEqual(response.status_code, 200)
        self.assertIn('task_id', response.data)

        mock_start_scan.assert_called_once_with(scan_session.id)

    @patch('services.scanning_service.ScanningService.stop_scan')
    def test_stop_scan(self, mock_stop_scan):
        """Test stopping a running scan session"""
        mock_stop_scan.return_value = {'status': 'stopped'}

        scan_session = ScanSessionFactory(target=self.target, status=ScanStatus.RUNNING)

        response = self.client.post(f'/api/scanning/{scan_session.id}/stop/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['status'], 'stopped')

        mock_stop_scan.assert_called_once_with(scan_session.id)

    @patch('services.scanning_service.ScanningService.pause_scan')
    def test_pause_scan(self, mock_pause_scan):
        """Test pausing a running scan session"""
        mock_pause_scan.return_value = {'status': 'paused'}

        scan_session = ScanSessionFactory(target=self.target, status=ScanStatus.RUNNING)

        response = self.client.post(f'/api/scanning/{scan_session.id}/pause/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['status'], 'paused')

        mock_pause_scan.assert_called_once_with(scan_session.id)

    @patch('services.scanning_service.ScanningService.resume_scan')
    def test_resume_scan(self, mock_resume_scan):
        """Test resuming a paused scan session"""
        mock_resume_scan.return_value = {'status': 'resumed'}

        scan_session = ScanSessionFactory(target=self.target, status=ScanStatus.PAUSED)

        response = self.client.post(f'/api/scanning/{scan_session.id}/resume/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['status'], 'resumed')

        mock_resume_scan.assert_called_once_with(scan_session.id)

    def test_scan_progress(self):
        """Test getting scan progress"""
        scan_session = ScanSessionFactory(
            target=self.target,
            status=ScanStatus.RUNNING,
            total_progress=45.5,
            current_phase='vulnerability_scanning',
            phase_progress={
                'reconnaissance': 100,
                'vulnerability_scanning': 45,
                'exploitation': 0
            }
        )

        response = self.client.get(f'/api/scanning/{scan_session.id}/progress/')
        self.assertEqual(response.status_code, 200)

        progress_data = response.data
        self.assertEqual(progress_data['total_progress'], 45.5)
        self.assertEqual(progress_data['current_phase'], 'vulnerability_scanning')
        self.assertIn('phase_progress', progress_data)
        self.assertIn('estimated_time_remaining', progress_data)

    def test_scan_results(self):
        """Test getting scan results"""
        scan_session = ScanSessionFactory(target=self.target)

        # Create tool executions and vulnerabilities
        tool_executions = ToolExecutionFactory.create_batch(3, scan_session=scan_session)

        response = self.client.get(f'/api/scanning/{scan_session.id}/results/')
        self.assertEqual(response.status_code, 200)

        results = response.data
        self.assertIn('tool_executions', results)
        self.assertIn('vulnerabilities_summary', results)
        self.assertEqual(len(results['tool_executions']), 3)

    def test_scan_logs(self):
        """Test getting scan logs"""
        scan_session = ScanSessionFactory(target=self.target)

        response = self.client.get(f'/api/scanning/{scan_session.id}/logs/')
        self.assertEqual(response.status_code, 200)

        logs_data = response.data
        self.assertIn('logs', logs_data)
        self.assertIn('total_entries', logs_data)

    def test_filter_scans_by_status(self):
        """Test filtering scan sessions by status"""
        ScanSessionFactory.create_batch(2, target=self.target, status=ScanStatus.COMPLETED)
        ScanSessionFactory.create_batch(3, target=self.target, status=ScanStatus.RUNNING)
        ScanSessionFactory.create_batch(1, target=self.target, status=ScanStatus.FAILED)

        # Filter by completed status
        response = self.client.get('/api/scanning/?status=completed')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 2)

        # Filter by running status
        response = self.client.get('/api/scanning/?status=running')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 3)

    def test_filter_scans_by_target(self):
        """Test filtering scan sessions by target"""
        other_target = TargetFactory()

        ScanSessionFactory.create_batch(2, target=self.target)
        ScanSessionFactory.create_batch(3, target=other_target)

        response = self.client.get(f'/api/scanning/?target={self.target.id}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 2)

    def test_search_scans(self):
        """Test searching scan sessions"""
        ScanSessionFactory(target=self.target, session_name='SQL Injection Test')
        ScanSessionFactory(target=self.target, session_name='XSS Vulnerability Scan')

        response = self.client.get('/api/scanning/?search=SQL')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)
        self.assertIn('SQL', response.data['results'][0]['session_name'])

    @patch('services.scan_scheduler.ScanScheduler.schedule_parallel_scans')
    def test_parallel_scanning(self, mock_scheduler):
        """Test scheduling parallel scans"""
        targets = TargetFactory.create_batch(3)
        target_ids = [t.id for t in targets]

        mock_scheduler.return_value = {
            'scheduled_scans': len(target_ids),
            'scan_session_ids': [1, 2, 3]
        }

        parallel_data = {
            'target_ids': target_ids,
            'scan_config': {
                'tools': ['nuclei', 'nmap'],
                'intensity': 'medium'
            },
            'session_name': 'Parallel Security Scan'
        }

        response = self.client.post('/api/scanning/parallel/', parallel_data, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['scheduled_scans'], 3)

    @patch('services.scanning_service.ScanningService.validate_scan_config')
    def test_validate_scan_config(self, mock_validate):
        """Test scan configuration validation"""
        mock_validate.return_value = {
            'valid': True,
            'warnings': [],
            'estimated_duration': '2 hours'
        }

        config_data = {
            'tools': ['nuclei', 'nmap', 'custom_web'],
            'intensity': 'aggressive',
            'concurrent_scans': 10,
            'target_id': self.target.id
        }

        response = self.client.post('/api/scanning/validate-config/', config_data, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['valid'])

    def test_scan_templates(self):
        """Test getting available scan templates"""
        response = self.client.get('/api/scanning/templates/')
        self.assertEqual(response.status_code, 200)

        templates = response.data
        self.assertIn('templates', templates)
        self.assertIsInstance(templates['templates'], list)

    def test_scan_statistics(self):
        """Test scan statistics endpoint"""
        # Create scans with different statuses
        ScanSessionFactory.create_batch(2, target=self.target, status=ScanStatus.COMPLETED)
        ScanSessionFactory.create_batch(1, target=self.target, status=ScanStatus.RUNNING)
        ScanSessionFactory.create_batch(1, target=self.target, status=ScanStatus.FAILED)

        response = self.client.get('/api/scanning/statistics/')
        self.assertEqual(response.status_code, 200)

        stats = response.data
        self.assertEqual(stats['total'], 4)
        self.assertEqual(stats['completed'], 2)
        self.assertEqual(stats['running'], 1)
        self.assertEqual(stats['failed'], 1)

    def test_clone_scan_session(self):
        """Test cloning an existing scan session"""
        original_scan = ScanSessionFactory(
            target=self.target,
            session_name='Original Scan',
            scan_config={'tools': ['nuclei'], 'intensity': 'medium'}
        )

        clone_data = {
            'new_session_name': 'Cloned Scan Session'
        }

        response = self.client.post(
            f'/api/scanning/{original_scan.id}/clone/',
            clone_data,
            format='json'
        )
        self.assertEqual(response.status_code, 201)

        # Verify clone was created
        cloned_scan = ScanSession.objects.get(id=response.data['id'])
        self.assertEqual(cloned_scan.session_name, 'Cloned Scan Session')
        self.assertEqual(cloned_scan.scan_config, original_scan.scan_config)
        self.assertEqual(cloned_scan.target, original_scan.target)

    def test_scan_export(self):
        """Test exporting scan results"""
        scan_session = ScanSessionFactory(target=self.target)

        # Test JSON export
        response = self.client.get(f'/api/scanning/{scan_session.id}/export/?format=json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')

        # Test CSV export
        response = self.client.get(f'/api/scanning/{scan_session.id}/export/?format=csv')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')

    def test_unauthorized_access(self):
        """Test unauthorized access to scanning endpoints"""
        self.client.credentials()

        response = self.client.get('/api/scanning/')
        self.assertEqual(response.status_code, 401)

    def test_invalid_scan_data(self):
        """Test creating scan with invalid data"""
        invalid_data = {
            'target_id': 999999,  # Non-existent target
            'session_name': '',   # Empty name
            'scan_config': 'invalid_config'  # Should be dict
        }

        response = self.client.post('/api/scanning/', invalid_data, format='json')
        self.assertEqual(response.status_code, 400)

    def test_scan_session_pagination(self):
        """Test scan session list pagination"""
        ScanSessionFactory.create_batch(25, target=self.target)

        response = self.client.get('/api/scanning/?page=1&page_size=10')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 10)
        self.assertIsNotNone(response.data['next'])

    def test_scan_session_ordering(self):
        """Test scan session list ordering"""
        scan1 = ScanSessionFactory(target=self.target, total_progress=25.0)
        scan2 = ScanSessionFactory(target=self.target, total_progress=75.0)
        scan3 = ScanSessionFactory(target=self.target, total_progress=50.0)

        # Test ordering by progress (descending)
        response = self.client.get('/api/scanning/?ordering=-total_progress')
        self.assertEqual(response.status_code, 200)

        results = response.data['results']
        self.assertEqual(results[0]['id'], scan2.id)  # 75% first
        self.assertEqual(results[1]['id'], scan3.id)  # 50% second
        self.assertEqual(results[2]['id'], scan1.id)  # 25% last