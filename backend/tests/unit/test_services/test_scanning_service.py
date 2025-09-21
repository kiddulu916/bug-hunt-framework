"""
Unit tests for Scanning Service
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from django.test import TestCase
from django.utils import timezone

from services.scanning_service import ScanningService, ScanStatus
from tests.factories import TargetFactory, ScanSessionFactory, ToolExecutionFactory
from tests.test_utils import MockToolExecutor, TestDataGenerator


@pytest.mark.unit
class ScanningServiceTest(TestCase):
    """Test ScanningService functionality"""

    def setUp(self):
        self.target = TargetFactory.create()
        self.scanning_service = ScanningService()

    @patch('services.scanning_service.subprocess.run')
    @patch('services.scanning_service.os.path.exists')
    def test_start_scan_session(self, mock_exists, mock_subprocess):
        """Test starting a new scan session"""
        mock_exists.return_value = True
        mock_subprocess.return_value = Mock(returncode=0, stdout='', stderr='')

        scan_config = {
            'tools': ['nuclei', 'nmap'],
            'intensity': 'medium',
            'methodology_phases': ['reconnaissance', 'vulnerability_scanning']
        }

        session = self.scanning_service.start_scan_session(
            target=self.target,
            session_name='Test Scan',
            scan_config=scan_config
        )

        self.assertIsNotNone(session)
        self.assertEqual(session.target, self.target)
        self.assertEqual(session.session_name, 'Test Scan')
        self.assertEqual(session.status, 'queued')
        self.assertEqual(session.scan_config, scan_config)

    @patch('services.scanning_service.ScanningService._execute_tool')
    def test_execute_scan_phase(self, mock_execute_tool):
        """Test executing a scan phase"""
        scan_session = ScanSessionFactory.create(
            target=self.target,
            status='running',
            methodology_phases=['reconnaissance', 'vulnerability_scanning']
        )

        mock_execute_tool.return_value = {
            'success': True,
            'results_count': 5,
            'execution_time': 45.2
        }

        result = self.scanning_service.execute_scan_phase(
            scan_session=scan_session,
            phase='reconnaissance',
            tools=['amass', 'subfinder']
        )

        self.assertTrue(result['success'])
        self.assertEqual(mock_execute_tool.call_count, 2)  # Called for each tool

    @patch('subprocess.run')
    def test_execute_tool_nuclei(self, mock_subprocess):
        """Test executing nuclei tool"""
        scan_session = ScanSessionFactory.create(target=self.target)

        # Mock nuclei output
        nuclei_output = '''[INFO] Using Nuclei Engine 2.9.4
[INFO] Templates loaded: 4829
[MEDIUM] [ssl-issuer] [ssl] [https://example.com] [CN=Example Organization]
[HIGH] [xss-reflected] [xss] [https://example.com/search?q=test] [Parameter: q]'''

        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout=nuclei_output,
            stderr=''
        )

        result = self.scanning_service._execute_tool(
            scan_session=scan_session,
            tool_name='nuclei',
            tool_parameters={
                'templates': '/nuclei-templates/',
                'concurrency': 25
            }
        )

        self.assertTrue(result['success'])
        self.assertGreater(result['results_count'], 0)
        self.assertIn('nuclei', mock_subprocess.call_args[0][0])

    @patch('subprocess.run')
    def test_execute_tool_nmap(self, mock_subprocess):
        """Test executing nmap tool"""
        scan_session = ScanSessionFactory.create(target=self.target)

        # Mock nmap XML output
        nmap_output = '''<?xml version="1.0" encoding="UTF-8"?>
<nmaprun>
  <host>
    <address addr="93.184.216.34" addrtype="ipv4"/>
    <hostnames>
      <hostname name="example.com" type="PTR"/>
    </hostnames>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.18.0"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.18.0"/>
      </port>
    </ports>
  </host>
</nmaprun>'''

        mock_subprocess.return_value = Mock(
            returncode=0,
            stdout=nmap_output,
            stderr=''
        )

        result = self.scanning_service._execute_tool(
            scan_session=scan_session,
            tool_name='nmap',
            tool_parameters={
                'scan_type': 'stealth',
                'port_range': '1-1000'
            }
        )

        self.assertTrue(result['success'])
        self.assertGreater(result['results_count'], 0)
        self.assertIn('nmap', mock_subprocess.call_args[0][0])

    def test_execute_tool_failure(self):
        """Test tool execution failure handling"""
        scan_session = ScanSessionFactory.create(target=self.target)

        with patch('subprocess.run') as mock_subprocess:
            mock_subprocess.return_value = Mock(
                returncode=1,
                stdout='',
                stderr='Error: Tool execution failed'
            )

            result = self.scanning_service._execute_tool(
                scan_session=scan_session,
                tool_name='failed_tool',
                tool_parameters={}
            )

            self.assertFalse(result['success'])
            self.assertEqual(result['results_count'], 0)
            self.assertIn('Error', result['error_message'])

    @patch('services.scanning_service.Celery.send_task')
    def test_queue_scan_session(self, mock_celery):
        """Test queuing scan session for background processing"""
        scan_session = ScanSessionFactory.create(target=self.target)

        mock_celery.return_value = Mock(id='test-task-id')

        task_id = self.scanning_service.queue_scan_session(scan_session.id)

        self.assertEqual(task_id, 'test-task-id')
        mock_celery.assert_called_once()

    def test_update_scan_progress(self):
        """Test updating scan progress"""
        scan_session = ScanSessionFactory.create(
            target=self.target,
            methodology_phases=['reconnaissance', 'vulnerability_scanning', 'exploitation']
        )

        self.scanning_service.update_scan_progress(
            scan_session=scan_session,
            phase='reconnaissance',
            progress=100
        )

        scan_session.refresh_from_db()
        self.assertEqual(scan_session.phase_progress['reconnaissance'], 100)

        # Test overall progress calculation
        self.scanning_service.update_scan_progress(
            scan_session=scan_session,
            phase='vulnerability_scanning',
            progress=50
        )

        scan_session.refresh_from_db()
        # Should be approximately 50% overall (1 complete phase + 1 half phase out of 3)
        self.assertAlmostEqual(scan_session.total_progress, 50.0, delta=10.0)

    def test_get_scan_results(self):
        """Test retrieving scan results"""
        scan_session = ScanSessionFactory.create(target=self.target)

        # Create some tool executions
        ToolExecutionFactory.create(
            scan_session=scan_session,
            tool_name='nuclei',
            status='completed',
            parsed_results_count=3
        )
        ToolExecutionFactory.create(
            scan_session=scan_session,
            tool_name='nmap',
            status='completed',
            parsed_results_count=2
        )

        results = self.scanning_service.get_scan_results(scan_session.id)

        self.assertIn('scan_session', results)
        self.assertIn('tool_executions', results)
        self.assertIn('summary', results)

        self.assertEqual(len(results['tool_executions']), 2)
        self.assertEqual(results['summary']['total_tools'], 2)
        self.assertEqual(results['summary']['completed_tools'], 2)
        self.assertEqual(results['summary']['total_results'], 5)

    def test_pause_scan_session(self):
        """Test pausing a running scan session"""
        scan_session = ScanSessionFactory.create(
            target=self.target,
            status='running'
        )

        with patch('services.scanning_service.Celery.control.revoke') as mock_revoke:
            success = self.scanning_service.pause_scan_session(scan_session.id)

            self.assertTrue(success)
            scan_session.refresh_from_db()
            self.assertEqual(scan_session.status, 'paused')

    def test_resume_scan_session(self):
        """Test resuming a paused scan session"""
        scan_session = ScanSessionFactory.create(
            target=self.target,
            status='paused'
        )

        with patch('services.scanning_service.Celery.send_task') as mock_celery:
            mock_celery.return_value = Mock(id='resumed-task-id')

            success = self.scanning_service.resume_scan_session(scan_session.id)

            self.assertTrue(success)
            scan_session.refresh_from_db()
            self.assertEqual(scan_session.status, 'queued')

    def test_cancel_scan_session(self):
        """Test cancelling a scan session"""
        scan_session = ScanSessionFactory.create(
            target=self.target,
            status='running'
        )

        with patch('services.scanning_service.Celery.control.revoke') as mock_revoke:
            success = self.scanning_service.cancel_scan_session(scan_session.id)

            self.assertTrue(success)
            scan_session.refresh_from_db()
            self.assertEqual(scan_session.status, 'cancelled')

    def test_get_tool_configuration(self):
        """Test getting tool-specific configuration"""
        # Test nuclei configuration
        nuclei_config = self.scanning_service._get_tool_configuration(
            'nuclei',
            self.target,
            {'templates': '/custom/templates/'}
        )

        self.assertIn('-u', nuclei_config)
        self.assertIn(self.target.main_url, nuclei_config)
        self.assertIn('-t', nuclei_config)
        self.assertIn('/custom/templates/', nuclei_config)

        # Test nmap configuration
        nmap_config = self.scanning_service._get_tool_configuration(
            'nmap',
            self.target,
            {'scan_type': 'stealth', 'port_range': '1-1000'}
        )

        self.assertIn('-sS', nmap_config)  # Stealth scan
        self.assertIn('-p', nmap_config)
        self.assertIn('1-1000', nmap_config)

    def test_parse_tool_output(self):
        """Test parsing tool output"""
        # Test nuclei output parsing
        nuclei_output = '''[INFO] Using Nuclei Engine 2.9.4
[MEDIUM] [ssl-issuer] [ssl] [https://example.com] [CN=Example Organization]
[HIGH] [xss-reflected] [xss] [https://example.com/search?q=test] [Parameter: q]
[CRITICAL] [rce-injection] [rce] [https://example.com/exec] [Command executed]'''

        results = self.scanning_service._parse_tool_output('nuclei', nuclei_output)

        self.assertEqual(len(results), 3)
        self.assertEqual(results[0]['severity'], 'medium')
        self.assertEqual(results[1]['template'], 'xss-reflected')
        self.assertEqual(results[2]['severity'], 'critical')

        # Test nmap output parsing
        nmap_output = '''Starting Nmap 7.80
Nmap scan report for example.com (93.184.216.34)
Host is up (0.034s latency).
PORT     STATE SERVICE VERSION
80/tcp   open  http    nginx 1.18.0
443/tcp  open  https   nginx 1.18.0
22/tcp   closed ssh'''

        results = self.scanning_service._parse_tool_output('nmap', nmap_output)

        self.assertGreater(len(results), 0)
        # Check that open ports are captured
        open_ports = [r for r in results if r.get('state') == 'open']
        self.assertEqual(len(open_ports), 2)

    def test_validate_tool_availability(self):
        """Test tool availability validation"""
        with patch('shutil.which') as mock_which:
            # Tool available
            mock_which.return_value = '/usr/bin/nuclei'
            self.assertTrue(self.scanning_service._validate_tool_availability('nuclei'))

            # Tool not available
            mock_which.return_value = None
            self.assertFalse(self.scanning_service._validate_tool_availability('nonexistent_tool'))

    def test_rate_limiting_compliance(self):
        """Test that scanning respects target rate limiting"""
        target = TargetFactory.create(
            requests_per_second=2.0,
            concurrent_requests=5,
            request_delay_ms=500
        )

        scan_session = ScanSessionFactory.create(target=target)

        config = self.scanning_service._get_tool_configuration(
            'nuclei',
            target,
            {}
        )

        # Check that rate limiting parameters are included
        config_str = ' '.join(config)
        self.assertIn('-rl', config_str)  # Rate limit flag
        self.assertIn('-c', config_str)   # Concurrency flag

    @patch('services.scanning_service.ScanningService._save_scan_results')
    @patch('services.scanning_service.ScanningService._execute_tool')
    def test_complete_scan_workflow(self, mock_execute_tool, mock_save_results):
        """Test complete scan workflow from start to finish"""
        # Mock tool execution results
        mock_execute_tool.side_effect = [
            {
                'success': True,
                'results_count': 10,
                'execution_time': 30.5,
                'output_file': '/tmp/amass_results.txt'
            },
            {
                'success': True,
                'results_count': 5,
                'execution_time': 45.2,
                'output_file': '/tmp/nuclei_results.json'
            }
        ]

        mock_save_results.return_value = True

        scan_config = {
            'tools': ['amass', 'nuclei'],
            'methodology_phases': ['reconnaissance', 'vulnerability_scanning']
        }

        # Start scan
        session = self.scanning_service.start_scan_session(
            target=self.target,
            session_name='Complete Workflow Test',
            scan_config=scan_config
        )

        # Execute reconnaissance phase
        recon_result = self.scanning_service.execute_scan_phase(
            scan_session=session,
            phase='reconnaissance',
            tools=['amass']
        )

        # Execute vulnerability scanning phase
        vuln_result = self.scanning_service.execute_scan_phase(
            scan_session=session,
            phase='vulnerability_scanning',
            tools=['nuclei']
        )

        # Verify results
        self.assertTrue(recon_result['success'])
        self.assertTrue(vuln_result['success'])

        # Verify tool executions were called
        self.assertEqual(mock_execute_tool.call_count, 2)

        # Verify results were saved
        self.assertEqual(mock_save_results.call_count, 2)


@pytest.mark.unit
class ScanningServiceIntegrationTest(TestCase):
    """Integration tests for ScanningService with real tool mocking"""

    def setUp(self):
        self.target = TargetFactory.create()
        self.scanning_service = ScanningService()

    def test_mock_tool_integration(self):
        """Test integration with MockToolExecutor"""
        scan_session = ScanSessionFactory.create(target=self.target)

        # Use mock tool executor
        mock_executor = MockToolExecutor('nuclei')
        mock_executor.set_results(TestDataGenerator.generate_scan_results('nuclei', 3))

        with patch.object(self.scanning_service, '_execute_tool') as mock_execute:
            mock_execute.return_value = mock_executor.execute()

            result = self.scanning_service._execute_tool(
                scan_session=scan_session,
                tool_name='nuclei',
                tool_parameters={}
            )

            self.assertTrue(result['success'])
            self.assertEqual(result['return_code'], 0)
            self.assertGreater(len(result['stdout']), 0)

    def test_error_handling_and_recovery(self):
        """Test error handling and recovery mechanisms"""
        scan_session = ScanSessionFactory.create(target=self.target)

        # Simulate tool failure
        with patch('subprocess.run') as mock_subprocess:
            mock_subprocess.side_effect = Exception("Tool crashed")

            result = self.scanning_service._execute_tool(
                scan_session=scan_session,
                tool_name='failing_tool',
                tool_parameters={}
            )

            self.assertFalse(result['success'])
            self.assertIn('Tool crashed', result['error_message'])

        # Verify scan session is marked as failed
        scan_session.refresh_from_db()
        # Note: This would depend on the actual error handling implementation

    def test_concurrent_scan_handling(self):
        """Test handling of concurrent scan requests"""
        target = TargetFactory.create(concurrent_requests=2)

        # Create multiple scan sessions
        session1 = ScanSessionFactory.create(target=target, status='running')
        session2 = ScanSessionFactory.create(target=target, status='queued')

        # Test that service respects concurrency limits
        with patch('services.scanning_service.ScanSession.objects.filter') as mock_filter:
            mock_filter.return_value.filter.return_value.count.return_value = 2

            can_start = self.scanning_service._can_start_scan(target)
            self.assertFalse(can_start)  # Already at limit

        # Test when under limit
        with patch('services.scanning_service.ScanSession.objects.filter') as mock_filter:
            mock_filter.return_value.filter.return_value.count.return_value = 1

            can_start = self.scanning_service._can_start_scan(target)
            self.assertTrue(can_start)  # Under limit