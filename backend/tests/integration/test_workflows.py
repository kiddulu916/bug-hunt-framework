"""
Integration tests for complete scanning and exploitation workflows
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
from django.test import TransactionTestCase
from django.db import transaction

from apps.targets.models import Target, BugBountyPlatform
from apps.scanning.models import ScanSession, ScanStatus, ToolExecution
from apps.vulnerabilities.models import Vulnerability, VulnSeverity
from apps.exploitation.models import ExploitationSession, ExploitResult
from apps.reconnaissance.models import ReconResult
from apps.reporting.models import Report

from services.scanning_service import ScanningService
from services.exploitation_service import ExploitationService
from services.recon_service import ReconService
from services.reporting_service import ReportingService
from services.notification_service import NotificationService

from tests.factories import (
    TargetFactory, ScanSessionFactory, VulnerabilityFactory,
    ExploitationSessionFactory, UserFactory
)


@pytest.mark.django_db(transaction=True)
class TestFullScanWorkflow(TransactionTestCase):
    """Test complete scan workflow from target to report"""

    def setUp(self):
        self.user = UserFactory()
        self.target = TargetFactory(
            target_name="Complete Test Corp",
            main_url="https://testcorp.example.com",
            in_scope_urls=[
                "https://testcorp.example.com",
                "https://api.testcorp.example.com",
                "https://admin.testcorp.example.com"
            ]
        )

    @patch('services.scanner_engines.nuclei_engine.NucleiEngine.execute_scan')
    @patch('services.scanner_engines.custom_web_engine.CustomWebEngine.execute_scan')
    @patch('services.notification_service.NotificationService.send_notification')
    def test_complete_scan_workflow(self, mock_notification, mock_web_scan, mock_nuclei_scan):
        """Test complete scanning workflow with multiple tools"""

        # Mock scan results
        mock_nuclei_scan.return_value = {
            'status': 'completed',
            'vulnerabilities': [
                {
                    'template': 'xss-reflected',
                    'url': 'https://testcorp.example.com/search',
                    'severity': 'medium',
                    'description': 'Reflected XSS vulnerability'
                },
                {
                    'template': 'sql-injection',
                    'url': 'https://api.testcorp.example.com/login',
                    'severity': 'high',
                    'description': 'SQL injection in login endpoint'
                }
            ]
        }

        mock_web_scan.return_value = {
            'status': 'completed',
            'findings': [
                {
                    'type': 'directory_traversal',
                    'url': 'https://admin.testcorp.example.com/files',
                    'severity': 'high',
                    'payload': '../../../etc/passwd'
                }
            ]
        }

        # Create scan session
        scan_session = ScanSessionFactory(
            target=self.target,
            session_name="Complete Workflow Test",
            scan_config={
                'tools': ['nuclei', 'custom_web'],
                'intensity': 'aggressive',
                'max_duration': 3600
            }
        )

        # Execute scanning workflow
        scanning_service = ScanningService()

        with transaction.atomic():
            result = scanning_service.execute_full_scan(scan_session.id)

        # Verify scan completion
        scan_session.refresh_from_db()
        self.assertEqual(scan_session.status, ScanStatus.COMPLETED)

        # Verify vulnerabilities were created
        vulnerabilities = Vulnerability.objects.filter(scan_session=scan_session)
        self.assertEqual(vulnerabilities.count(), 3)

        # Verify high severity vulnerabilities
        high_severity_vulns = vulnerabilities.filter(severity=VulnSeverity.HIGH)
        self.assertEqual(high_severity_vulns.count(), 2)

        # Verify tool executions
        tool_executions = ToolExecution.objects.filter(scan_session=scan_session)
        self.assertGreaterEqual(tool_executions.count(), 2)

        # Verify notification was sent
        mock_notification.assert_called()

    @patch('services.exploitation_service.ExploitationService.execute_exploitation')
    def test_scan_to_exploitation_workflow(self, mock_exploitation):
        """Test workflow from scan results to exploitation"""

        # Create scan with vulnerabilities
        scan_session = ScanSessionFactory(
            target=self.target,
            status=ScanStatus.COMPLETED
        )

        vulnerability = VulnerabilityFactory(
            scan_session=scan_session,
            vulnerability_type='sql_injection',
            severity=VulnSeverity.HIGH,
            affected_url='https://testcorp.example.com/api/login',
            payload_used="' OR 1=1 --"
        )

        # Mock exploitation results
        mock_exploitation.return_value = {
            'success': True,
            'payload_executed': "' UNION SELECT username,password FROM users --",
            'evidence': 'Successfully extracted user credentials',
            'impact_level': 'critical'
        }

        # Execute exploitation workflow
        exploitation_service = ExploitationService()
        exploitation_session = exploitation_service.create_exploitation_session(
            vulnerability.id,
            exploitation_type='sql_injection'
        )

        result = exploitation_service.execute_exploitation(exploitation_session.id)

        # Verify exploitation results
        exploitation_session.refresh_from_db()
        self.assertEqual(exploitation_session.status, 'completed')

        exploit_results = ExploitResult.objects.filter(
            exploitation_session=exploitation_session
        )
        self.assertGreater(exploit_results.count(), 0)

        successful_exploits = exploit_results.filter(success=True)
        self.assertGreater(successful_exploits.count(), 0)

    @patch('services.reporting_service.ReportingService.generate_comprehensive_report')
    def test_complete_workflow_to_report(self, mock_report_generation):
        """Test complete workflow from scan to final report"""

        # Create completed scan with vulnerabilities and exploits
        scan_session = ScanSessionFactory(
            target=self.target,
            status=ScanStatus.COMPLETED
        )

        vulnerabilities = [
            VulnerabilityFactory(
                scan_session=scan_session,
                vulnerability_type='sql_injection',
                severity=VulnSeverity.HIGH
            ),
            VulnerabilityFactory(
                scan_session=scan_session,
                vulnerability_type='xss_reflected',
                severity=VulnSeverity.MEDIUM
            )
        ]

        exploitation_sessions = []
        for vuln in vulnerabilities:
            exp_session = ExploitationSessionFactory(
                vulnerability=vuln,
                target=self.target,
                status='completed'
            )
            exploitation_sessions.append(exp_session)

        # Mock report generation
        mock_report_generation.return_value = {
            'report_id': 'test-report-123',
            'file_path': '/reports/test-report-123.pdf',
            'executive_summary': 'Critical vulnerabilities found',
            'total_vulnerabilities': 2,
            'high_severity_count': 1,
            'exploitation_success_rate': 100
        }

        # Generate comprehensive report
        reporting_service = ReportingService()
        report_data = reporting_service.generate_comprehensive_report(
            scan_session.id,
            include_exploitation=True
        )

        # Verify report generation
        self.assertIn('report_id', report_data)
        self.assertIn('total_vulnerabilities', report_data)
        self.assertEqual(report_data['total_vulnerabilities'], 2)

        # Verify report record created
        reports = Report.objects.filter(scan_session=scan_session)
        self.assertGreater(reports.count(), 0)


@pytest.mark.django_db(transaction=True)
class TestReconnaissanceToScanWorkflow(TransactionTestCase):
    """Test reconnaissance to scanning workflow integration"""

    def setUp(self):
        self.target = TargetFactory(
            main_url="https://recon-test.example.com"
        )

    @patch('services.recon_service.ReconnaienceService.execute_reconnaissance')
    @patch('services.scanning_service.ScanningService.execute_targeted_scan')
    def test_recon_discovery_to_scan_workflow(self, mock_scan, mock_recon):
        """Test reconnaissance asset discovery feeding into targeted scans"""

        # Mock reconnaissance results
        mock_recon.return_value = {
            'subdomains': [
                'api.recon-test.example.com',
                'admin.recon-test.example.com',
                'dev.recon-test.example.com'
            ],
            'open_ports': [80, 443, 8080, 3306],
            'technologies': ['nginx', 'php', 'mysql'],
            'endpoints': [
                '/api/v1/users',
                '/admin/login',
                '/dev/debug'
            ]
        }

        mock_scan.return_value = {
            'status': 'completed',
            'vulnerabilities_found': 5,
            'high_severity_count': 2
        }

        # Execute reconnaissance
        recon_service = ReconnaienceService()
        recon_session = recon_service.create_recon_session(self.target.id)
        recon_results = recon_service.execute_reconnaissance(recon_session.id)

        # Verify reconnaissance completed
        recon_session.refresh_from_db()
        self.assertEqual(recon_session.status, 'completed')

        # Execute targeted scans based on recon results
        scanning_service = ScanningService()

        for subdomain in recon_results['subdomains']:
            scan_session = scanning_service.create_targeted_scan(
                target_id=self.target.id,
                target_url=f"https://{subdomain}",
                scan_focus='web_application'
            )
            scan_result = scanning_service.execute_targeted_scan(scan_session.id)

            # Verify scan execution
            self.assertIn('status', scan_result)
            self.assertEqual(scan_result['status'], 'completed')

    @patch('services.notification_service.NotificationService.send_real_time_alert')
    def test_critical_vulnerability_alert_workflow(self, mock_alert):
        """Test real-time alerting for critical vulnerabilities"""

        scan_session = ScanSessionFactory(
            target=self.target,
            status=ScanStatus.RUNNING
        )

        # Simulate discovering critical vulnerability during scan
        critical_vuln = VulnerabilityFactory(
            scan_session=scan_session,
            vulnerability_type='rce',
            severity=VulnSeverity.CRITICAL,
            cvss_score=9.8,
            affected_url='https://recon-test.example.com/upload'
        )

        # Trigger notification workflow
        notification_service = NotificationService()
        notification_service.process_vulnerability_discovery(critical_vuln.id)

        # Verify critical alert was sent
        mock_alert.assert_called_with(
            alert_type='critical_vulnerability',
            vulnerability_id=critical_vuln.id,
            severity='critical',
            target_name=self.target.target_name
        )


@pytest.mark.django_db(transaction=True)
class TestMultiTargetWorkflow(TransactionTestCase):
    """Test workflows across multiple targets"""

    def setUp(self):
        self.targets = [
            TargetFactory(
                target_name=f"Target {i}",
                main_url=f"https://target{i}.example.com"
            ) for i in range(1, 4)
        ]

    @patch('services.scan_scheduler.ScanScheduler.schedule_parallel_scans')
    def test_parallel_multi_target_scanning(self, mock_scheduler):
        """Test parallel scanning across multiple targets"""

        mock_scheduler.return_value = {
            'scheduled_scans': len(self.targets),
            'estimated_completion': datetime.now() + timedelta(hours=2)
        }

        from services.scan_scheduler import ScanScheduler
        scheduler = ScanScheduler()

        # Schedule parallel scans for all targets
        target_ids = [target.id for target in self.targets]
        schedule_result = scheduler.schedule_parallel_scans(
            target_ids=target_ids,
            scan_config={
                'tools': ['nuclei', 'nmap'],
                'intensity': 'medium'
            }
        )

        # Verify all scans were scheduled
        self.assertEqual(schedule_result['scheduled_scans'], len(self.targets))

        # Verify scan sessions created
        scan_sessions = ScanSession.objects.filter(target__in=self.targets)
        self.assertEqual(scan_sessions.count(), len(self.targets))

    def test_cross_target_vulnerability_correlation(self):
        """Test vulnerability correlation across multiple targets"""

        # Create similar vulnerabilities across targets
        common_vuln_type = 'xss_reflected'
        common_parameter = 'search'

        vulnerabilities = []
        for target in self.targets:
            scan_session = ScanSessionFactory(target=target)
            vuln = VulnerabilityFactory(
                scan_session=scan_session,
                vulnerability_type=common_vuln_type,
                affected_parameter=common_parameter,
                payload_used='<script>alert(1)</script>'
            )
            vulnerabilities.append(vuln)

        # Test vulnerability correlation logic
        from services.vulnerability_analyzer import VulnerabilityAnalyzer
        analyzer = VulnerabilityAnalyzer()

        correlation_results = analyzer.correlate_vulnerabilities_across_targets(
            vulnerability_type=common_vuln_type
        )

        # Verify correlation results
        self.assertIn('correlated_vulnerabilities', correlation_results)
        self.assertGreaterEqual(
            len(correlation_results['correlated_vulnerabilities']),
            len(self.targets)
        )


@pytest.mark.django_db(transaction=True)
class TestWorkflowErrorHandling(TransactionTestCase):
    """Test error handling and recovery in workflows"""

    def setUp(self):
        self.target = TargetFactory()

    @patch('services.scanner_engines.nuclei_engine.NucleiEngine.execute_scan')
    def test_scan_tool_failure_recovery(self, mock_scan):
        """Test workflow continues when individual tools fail"""

        # Mock tool failure
        mock_scan.side_effect = Exception("Nuclei execution failed")

        scan_session = ScanSessionFactory(
            target=self.target,
            scan_config={'tools': ['nuclei', 'custom_web']}
        )

        scanning_service = ScanningService()

        # Execute scan despite tool failure
        with self.assertLogs(level='ERROR') as log:
            result = scanning_service.execute_scan_with_fallback(scan_session.id)

        # Verify error was logged but workflow continued
        self.assertIn('Nuclei execution failed', str(log.output))

        # Verify scan session marked with partial results
        scan_session.refresh_from_db()
        self.assertIn('tool_failures', scan_session.metadata)

    def test_exploitation_timeout_handling(self):
        """Test exploitation timeout and cleanup"""

        scan_session = ScanSessionFactory(target=self.target)
        vulnerability = VulnerabilityFactory(scan_session=scan_session)

        exploitation_session = ExploitationSessionFactory(
            vulnerability=vulnerability,
            target=self.target
        )

        # Mock long-running exploitation
        with patch('asyncio.wait_for') as mock_wait:
            mock_wait.side_effect = asyncio.TimeoutError("Exploitation timed out")

            exploitation_service = ExploitationService()
            result = exploitation_service.execute_with_timeout(
                exploitation_session.id,
                timeout_seconds=30
            )

        # Verify timeout handling
        exploitation_session.refresh_from_db()
        self.assertEqual(exploitation_session.status, 'timeout')
        self.assertIn('timeout', exploitation_session.error_details)