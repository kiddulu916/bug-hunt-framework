"""
End-to-end tests for complete bug bounty automation workflows
"""

import pytest
import time
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
from django.test import TransactionTestCase
from django.db import transaction
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.targets.models import Target, BugBountyPlatform
from apps.scanning.models import ScanSession, ScanStatus, ToolExecution
from apps.vulnerabilities.models import Vulnerability, VulnSeverity
from apps.exploitation.models import ExploitationSession, ExploitResult
from apps.reconnaissance.models import ReconResult
from apps.reporting.models import Report

from tests.factories import UserFactory, TargetFactory


@pytest.mark.django_db(transaction=True)
@pytest.mark.e2e
class TestCompleteReconToReportWorkflow(TransactionTestCase):
    """Test complete workflow from reconnaissance to final report"""

    def setUp(self):
        self.user = UserFactory()
        self.client = APIClient()

        # Authenticate client
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Target data for E2E testing
        self.target_data = {
            'target_name': 'E2E Test Corporation',
            'platform': BugBountyPlatform.HACKERONE,
            'researcher_username': 'e2e_tester',
            'main_url': 'https://e2e-test.example.com',
            'in_scope_urls': [
                'https://e2e-test.example.com',
                'https://api.e2e-test.example.com',
                'https://admin.e2e-test.example.com'
            ],
            'out_of_scope_urls': ['https://blog.e2e-test.example.com'],
            'requests_per_second': 10.0,
            'concurrent_requests': 5,
            'required_headers': {'User-Agent': 'E2EBot/1.0'},
            'program_notes': 'End-to-end testing target'
        }

    @patch('services.recon_service.ReconnaienceService.execute_reconnaissance')
    @patch('services.scanning_service.ScanningService.execute_full_scan')
    @patch('services.exploitation_service.ExploitationService.execute_exploitation')
    @patch('services.reporting_service.ReportingService.generate_comprehensive_report')
    def test_complete_bug_bounty_workflow(self, mock_report, mock_exploit, mock_scan, mock_recon):
        """Test complete end-to-end bug bounty automation workflow"""

        # Mock reconnaissance results
        mock_recon.return_value = {
            'status': 'completed',
            'subdomains': [
                'api.e2e-test.example.com',
                'admin.e2e-test.example.com',
                'dev.e2e-test.example.com'
            ],
            'open_ports': [80, 443, 8080, 3306],
            'technologies': ['nginx', 'php', 'mysql', 'wordpress'],
            'endpoints': [
                '/api/v1/users',
                '/admin/login',
                '/upload.php'
            ],
            'certificates': {
                'ssl_issuer': 'Let\'s Encrypt',
                'expiry_date': '2024-12-31'
            }
        }

        # Mock scanning results with multiple vulnerabilities
        mock_scan.return_value = {
            'status': 'completed',
            'vulnerabilities': [
                {
                    'type': 'sql_injection',
                    'severity': 'high',
                    'url': 'https://api.e2e-test.example.com/login',
                    'parameter': 'username',
                    'payload': "' OR 1=1 --",
                    'confidence': 0.9
                },
                {
                    'type': 'xss_reflected',
                    'severity': 'medium',
                    'url': 'https://e2e-test.example.com/search',
                    'parameter': 'q',
                    'payload': '<script>alert(1)</script>',
                    'confidence': 0.8
                },
                {
                    'type': 'file_upload',
                    'severity': 'high',
                    'url': 'https://admin.e2e-test.example.com/upload.php',
                    'description': 'Unrestricted file upload vulnerability',
                    'confidence': 0.85
                }
            ],
            'scan_duration': 1800,  # 30 minutes
            'tools_executed': ['nuclei', 'custom_web', 'custom_infra']
        }

        # Mock exploitation results
        mock_exploit.return_value = {
            'status': 'completed',
            'successful_exploits': [
                {
                    'vulnerability_id': 1,
                    'exploit_type': 'sql_injection',
                    'payload_executed': "' UNION SELECT username,password FROM users --",
                    'evidence': 'Successfully extracted 50 user credentials',
                    'impact': 'Database access achieved'
                },
                {
                    'vulnerability_id': 3,
                    'exploit_type': 'file_upload',
                    'payload_executed': 'malicious.php webshell',
                    'evidence': 'Webshell uploaded and executed',
                    'impact': 'Remote code execution achieved'
                }
            ],
            'failed_exploits': [
                {
                    'vulnerability_id': 2,
                    'exploit_type': 'xss_reflected',
                    'reason': 'CSP header blocks script execution'
                }
            ]
        }

        # Mock report generation
        mock_report.return_value = {
            'report_id': 'e2e-report-123',
            'file_path': '/reports/e2e-report-123.pdf',
            'executive_summary': 'Critical vulnerabilities identified requiring immediate attention',
            'total_vulnerabilities': 3,
            'critical_count': 0,
            'high_count': 2,
            'medium_count': 1,
            'low_count': 0,
            'exploitation_success_rate': 67,  # 2 out of 3
            'report_generated_at': datetime.now().isoformat()
        }

        # Step 1: Create target via API
        response = self.client.post('/api/targets/', self.target_data, format='json')
        self.assertEqual(response.status_code, 201)
        target_id = response.data['id']

        # Step 2: Start reconnaissance via API
        recon_data = {
            'target_id': target_id,
            'reconnaissance_config': {
                'subdomain_enumeration': True,
                'port_scanning': True,
                'technology_detection': True,
                'ssl_analysis': True
            }
        }
        response = self.client.post('/api/reconnaissance/', recon_data, format='json')
        self.assertEqual(response.status_code, 201)
        recon_session_id = response.data['id']

        # Wait for reconnaissance to complete (simulated)
        time.sleep(1)

        # Step 3: Start comprehensive scan based on recon results
        scan_data = {
            'target_id': target_id,
            'session_name': 'E2E Comprehensive Scan',
            'scan_config': {
                'tools': ['nuclei', 'custom_web', 'custom_infra', 'custom_api'],
                'intensity': 'aggressive',
                'include_recon_results': True,
                'recon_session_id': recon_session_id
            },
            'methodology_phases': ['reconnaissance', 'scanning', 'exploitation']
        }
        response = self.client.post('/api/scanning/', scan_data, format='json')
        self.assertEqual(response.status_code, 201)
        scan_session_id = response.data['id']

        # Wait for scan to complete (simulated)
        time.sleep(2)

        # Step 4: Verify vulnerabilities were discovered
        response = self.client.get(f'/api/vulnerabilities/?scan_session={scan_session_id}')
        self.assertEqual(response.status_code, 200)
        vulnerabilities = response.data['results']
        self.assertGreaterEqual(len(vulnerabilities), 3)

        # Verify high-severity vulnerabilities
        high_severity_vulns = [v for v in vulnerabilities if v['severity'] == 'high']
        self.assertGreaterEqual(len(high_severity_vulns), 2)

        # Step 5: Start exploitation for high-severity vulnerabilities
        exploitation_sessions = []
        for vuln in high_severity_vulns:
            exploit_data = {
                'vulnerability_id': vuln['id'],
                'target_id': target_id,
                'exploitation_type': vuln['vulnerability_type'],
                'automated_exploitation': True
            }
            response = self.client.post('/api/exploitation/', exploit_data, format='json')
            self.assertEqual(response.status_code, 201)
            exploitation_sessions.append(response.data['id'])

        # Wait for exploitation to complete (simulated)
        time.sleep(3)

        # Step 6: Verify exploitation results
        successful_exploits = 0
        for session_id in exploitation_sessions:
            response = self.client.get(f'/api/exploitation/{session_id}/results/')
            self.assertEqual(response.status_code, 200)
            if response.data['success']:
                successful_exploits += 1

        self.assertGreaterEqual(successful_exploits, 1)

        # Step 7: Generate comprehensive report
        report_data = {
            'scan_session_id': scan_session_id,
            'include_exploitation': True,
            'include_evidence': True,
            'report_format': 'pdf',
            'executive_summary': True
        }
        response = self.client.post('/api/reports/', report_data, format='json')
        self.assertEqual(response.status_code, 201)
        report_id = response.data['id']

        # Step 8: Verify report generation
        response = self.client.get(f'/api/reports/{report_id}/')
        self.assertEqual(response.status_code, 200)
        report = response.data

        # Verify report contents
        self.assertEqual(report['total_vulnerabilities'], 3)
        self.assertEqual(report['high_count'], 2)
        self.assertEqual(report['medium_count'], 1)
        self.assertGreaterEqual(report['exploitation_success_rate'], 50)

        # Verify all mocks were called
        mock_recon.assert_called()
        mock_scan.assert_called()
        mock_exploit.assert_called()
        mock_report.assert_called()

    @patch('services.notification_service.NotificationService.send_real_time_alert')
    def test_real_time_vulnerability_alerting(self, mock_alert):
        """Test real-time alerting during vulnerability discovery"""

        # Create target
        response = self.client.post('/api/targets/', self.target_data, format='json')
        target_id = response.data['id']

        # Create scan session
        scan_data = {
            'target_id': target_id,
            'session_name': 'Real-time Alert Test',
            'scan_config': {
                'tools': ['nuclei'],
                'real_time_alerts': True,
                'alert_severity_threshold': 'medium'
            }
        }
        response = self.client.post('/api/scanning/', scan_data, format='json')
        scan_session_id = response.data['id']

        # Simulate critical vulnerability discovery
        critical_vuln_data = {
            'scan_session': scan_session_id,
            'vulnerability_name': 'Remote Code Execution',
            'vulnerability_type': 'rce',
            'severity': 'critical',
            'cvss_score': 9.8,
            'affected_url': 'https://e2e-test.example.com/upload',
            'confidence_level': 0.95
        }

        # This would trigger real-time alerting
        response = self.client.post('/api/vulnerabilities/', critical_vuln_data, format='json')
        self.assertEqual(response.status_code, 201)

        # Verify alert was triggered
        mock_alert.assert_called_with(
            alert_type='critical_vulnerability',
            vulnerability_id=response.data['id'],
            severity='critical',
            target_name=self.target_data['target_name']
        )


@pytest.mark.django_db(transaction=True)
@pytest.mark.e2e
class TestMultiTargetWorkflow(TransactionTestCase):
    """Test end-to-end workflows across multiple targets"""

    def setUp(self):
        self.user = UserFactory()
        self.client = APIClient()

        # Authenticate client
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        # Multiple targets for testing
        self.targets_data = [
            {
                'target_name': f'Multi Target {i}',
                'platform': BugBountyPlatform.HACKERONE,
                'researcher_username': 'multi_tester',
                'main_url': f'https://target{i}.example.com',
                'in_scope_urls': [f'https://target{i}.example.com']
            } for i in range(1, 4)
        ]

    @patch('services.scan_scheduler.ScanScheduler.schedule_parallel_scans')
    @patch('services.scanning_service.ScanningService.execute_full_scan')
    def test_parallel_multi_target_scanning(self, mock_scan, mock_scheduler):
        """Test parallel scanning across multiple targets"""

        # Mock scheduler
        mock_scheduler.return_value = {
            'scheduled_scans': 3,
            'estimated_completion': datetime.now() + timedelta(hours=1)
        }

        # Mock scan results for each target
        mock_scan.return_value = {
            'status': 'completed',
            'vulnerabilities': 2,
            'scan_duration': 900
        }

        # Create multiple targets
        target_ids = []
        for target_data in self.targets_data:
            response = self.client.post('/api/targets/', target_data, format='json')
            self.assertEqual(response.status_code, 201)
            target_ids.append(response.data['id'])

        # Schedule parallel scans
        parallel_scan_data = {
            'target_ids': target_ids,
            'scan_config': {
                'tools': ['nuclei', 'custom_web'],
                'intensity': 'medium',
                'parallel_execution': True
            },
            'session_name': 'Multi-Target Parallel Scan'
        }

        response = self.client.post('/api/scanning/parallel/', parallel_scan_data, format='json')
        self.assertEqual(response.status_code, 201)

        # Verify all scans were scheduled
        scheduled_scans = response.data['scheduled_scans']
        self.assertEqual(len(scheduled_scans), len(target_ids))

        # Wait for scans to complete (simulated)
        time.sleep(2)

        # Verify scan sessions created for all targets
        for target_id in target_ids:
            response = self.client.get(f'/api/scanning/?target={target_id}')
            self.assertEqual(response.status_code, 200)
            self.assertGreater(len(response.data['results']), 0)

    def test_cross_target_vulnerability_correlation(self):
        """Test vulnerability correlation across multiple targets"""

        # Create targets and vulnerabilities
        target_ids = []
        for target_data in self.targets_data:
            response = self.client.post('/api/targets/', target_data, format='json')
            target_ids.append(response.data['id'])

            # Create scan session for each target
            scan_data = {
                'target_id': response.data['id'],
                'session_name': f'Correlation Test - {target_data["target_name"]}'
            }
            scan_response = self.client.post('/api/scanning/', scan_data, format='json')

            # Create similar vulnerability for each target
            vuln_data = {
                'scan_session': scan_response.data['id'],
                'vulnerability_name': 'Cross-Site Scripting',
                'vulnerability_type': 'xss_reflected',
                'severity': 'medium',
                'affected_parameter': 'search',
                'payload_used': '<script>alert(1)</script>'
            }
            self.client.post('/api/vulnerabilities/', vuln_data, format='json')

        # Test vulnerability correlation
        response = self.client.get('/api/vulnerabilities/correlate/?type=xss_reflected')
        self.assertEqual(response.status_code, 200)

        # Verify correlation results
        correlation_data = response.data
        self.assertIn('correlated_vulnerabilities', correlation_data)
        self.assertGreaterEqual(len(correlation_data['correlated_vulnerabilities']), 3)


@pytest.mark.django_db(transaction=True)
@pytest.mark.e2e
class TestWorkflowErrorRecovery(TransactionTestCase):
    """Test error handling and recovery in end-to-end workflows"""

    def setUp(self):
        self.user = UserFactory()
        self.client = APIClient()

        # Authenticate client
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

        self.target_data = {
            'target_name': 'Error Recovery Test',
            'platform': BugBountyPlatform.BUGCROWD,
            'researcher_username': 'error_tester',
            'main_url': 'https://error-test.example.com'
        }

    @patch('services.scanner_engines.nuclei_engine.NucleiEngine.execute_scan')
    @patch('services.scanner_engines.custom_web_engine.CustomWebEngine.execute_scan')
    def test_scan_tool_failure_recovery(self, mock_web_scan, mock_nuclei_scan):
        """Test workflow recovery when scan tools fail"""

        # Mock Nuclei failure but Web scanner success
        mock_nuclei_scan.side_effect = Exception("Nuclei tool crashed")
        mock_web_scan.return_value = {
            'status': 'completed',
            'vulnerabilities': [
                {
                    'type': 'xss_reflected',
                    'severity': 'medium',
                    'url': 'https://error-test.example.com/search'
                }
            ]
        }

        # Create target and scan
        response = self.client.post('/api/targets/', self.target_data, format='json')
        target_id = response.data['id']

        scan_data = {
            'target_id': target_id,
            'session_name': 'Tool Failure Recovery Test',
            'scan_config': {
                'tools': ['nuclei', 'custom_web'],
                'continue_on_tool_failure': True
            }
        }
        response = self.client.post('/api/scanning/', scan_data, format='json')
        scan_session_id = response.data['id']

        # Wait for scan completion
        time.sleep(1)

        # Verify scan completed with partial results
        response = self.client.get(f'/api/scanning/{scan_session_id}/')
        scan_session = response.data

        # Should have completed despite tool failure
        self.assertEqual(scan_session['status'], 'completed_with_errors')
        self.assertIn('tool_failures', scan_session['metadata'])

        # Should still have vulnerabilities from successful tool
        response = self.client.get(f'/api/vulnerabilities/?scan_session={scan_session_id}')
        vulnerabilities = response.data['results']
        self.assertGreater(len(vulnerabilities), 0)

    @patch('services.exploitation_service.ExploitationService.execute_exploitation')
    def test_exploitation_timeout_recovery(self, mock_exploitation):
        """Test exploitation timeout handling and workflow continuation"""

        # Mock exploitation timeout
        mock_exploitation.side_effect = asyncio.TimeoutError("Exploitation timed out")

        # Create target, scan, and vulnerability
        response = self.client.post('/api/targets/', self.target_data, format='json')
        target_id = response.data['id']

        scan_data = {'target_id': target_id, 'session_name': 'Timeout Test'}
        scan_response = self.client.post('/api/scanning/', scan_data, format='json')
        scan_session_id = scan_response.data['id']

        vuln_data = {
            'scan_session': scan_session_id,
            'vulnerability_name': 'SQL Injection',
            'vulnerability_type': 'sql_injection',
            'severity': 'high'
        }
        vuln_response = self.client.post('/api/vulnerabilities/', vuln_data, format='json')
        vulnerability_id = vuln_response.data['id']

        # Attempt exploitation with timeout
        exploit_data = {
            'vulnerability_id': vulnerability_id,
            'target_id': target_id,
            'exploitation_type': 'sql_injection',
            'timeout_seconds': 10
        }
        response = self.client.post('/api/exploitation/', exploit_data, format='json')
        exploitation_session_id = response.data['id']

        # Wait for timeout
        time.sleep(1)

        # Verify timeout was handled gracefully
        response = self.client.get(f'/api/exploitation/{exploitation_session_id}/')
        exploitation_session = response.data

        self.assertEqual(exploitation_session['status'], 'timeout')
        self.assertIn('timeout', exploitation_session['error_details'])

        # Verify workflow can continue to reporting despite exploitation timeout
        report_data = {
            'scan_session_id': scan_session_id,
            'include_exploitation': True,
            'include_failed_exploits': True
        }
        response = self.client.post('/api/reports/', report_data, format='json')
        self.assertEqual(response.status_code, 201)


@pytest.mark.django_db(transaction=True)
@pytest.mark.e2e
@pytest.mark.slow
class TestLongRunningWorkflow(TransactionTestCase):
    """Test long-running workflow scenarios"""

    def setUp(self):
        self.user = UserFactory()
        self.client = APIClient()

        # Authenticate client
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    @patch('services.scanning_service.ScanningService.execute_extended_scan')
    def test_24_hour_continuous_scanning(self, mock_extended_scan):
        """Test 24-hour continuous scanning workflow"""

        # Mock extended scan results over time
        mock_extended_scan.return_value = {
            'status': 'completed',
            'total_duration_hours': 24,
            'vulnerabilities_discovered': 15,
            'phases_completed': [
                'reconnaissance',
                'subdomain_enumeration',
                'port_scanning',
                'web_application_testing',
                'api_testing',
                'infrastructure_testing'
            ],
            'continuous_monitoring': True
        }

        # Create target for extended scanning
        target_data = {
            'target_name': 'Extended Scan Target',
            'platform': BugBountyPlatform.HACKERONE,
            'researcher_username': 'extended_tester',
            'main_url': 'https://extended-test.example.com'
        }
        response = self.client.post('/api/targets/', target_data, format='json')
        target_id = response.data['id']

        # Start extended scan
        extended_scan_data = {
            'target_id': target_id,
            'session_name': '24-Hour Continuous Scan',
            'scan_config': {
                'duration_hours': 24,
                'continuous_monitoring': True,
                'phases': [
                    'reconnaissance',
                    'vulnerability_scanning',
                    'exploitation',
                    'post_exploitation'
                ]
            }
        }
        response = self.client.post('/api/scanning/extended/', extended_scan_data, format='json')
        self.assertEqual(response.status_code, 201)
        scan_session_id = response.data['id']

        # Simulate extended execution (shortened for testing)
        time.sleep(3)

        # Verify extended scan completion
        response = self.client.get(f'/api/scanning/{scan_session_id}/')
        scan_session = response.data

        self.assertEqual(scan_session['status'], 'completed')
        self.assertIn('total_duration_hours', scan_session['metadata'])

    def test_workflow_progress_tracking(self):
        """Test real-time progress tracking during long workflows"""

        # Create target
        target_data = {
            'target_name': 'Progress Tracking Test',
            'platform': BugBountyPlatform.BUGCROWD,
            'researcher_username': 'progress_tester',
            'main_url': 'https://progress-test.example.com'
        }
        response = self.client.post('/api/targets/', target_data, format='json')
        target_id = response.data['id']

        # Start scan with progress tracking
        scan_data = {
            'target_id': target_id,
            'session_name': 'Progress Tracking Test',
            'scan_config': {
                'tools': ['nuclei', 'custom_web', 'custom_infra'],
                'progress_reporting': True,
                'progress_interval_seconds': 30
            }
        }
        response = self.client.post('/api/scanning/', scan_data, format='json')
        scan_session_id = response.data['id']

        # Monitor progress over time
        progress_checks = []
        for i in range(3):
            time.sleep(1)
            response = self.client.get(f'/api/scanning/{scan_session_id}/progress/')
            self.assertEqual(response.status_code, 200)
            progress_checks.append(response.data)

        # Verify progress tracking
        for progress in progress_checks:
            self.assertIn('completion_percentage', progress)
            self.assertIn('current_phase', progress)
            self.assertIn('estimated_time_remaining', progress)