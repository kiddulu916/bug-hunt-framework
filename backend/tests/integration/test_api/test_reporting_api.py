"""
Integration tests for Reporting API endpoints
"""

import pytest
import json
from unittest.mock import Mock, patch
from django.test import TransactionTestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken

from apps.reporting.models import Report, ReportFormat
from apps.scanning.models import ScanSession
from tests.factories import (
    UserFactory, TargetFactory, ScanSessionFactory, VulnerabilityFactory,
    ReportFactory
)


@pytest.mark.integration
@pytest.mark.django_db(transaction=True)
class TestReportingAPIEndpoints(TransactionTestCase):
    """Test reporting API endpoints"""

    def setUp(self):
        self.client = APIClient()
        self.user = UserFactory()
        self.target = TargetFactory()
        self.scan_session = ScanSessionFactory(target=self.target)

        # Create some vulnerabilities for the scan session
        self.vulnerabilities = VulnerabilityFactory.create_batch(
            5, scan_session=self.scan_session
        )

        # Authenticate client
        refresh = RefreshToken.for_user(self.user)
        self.client.credentials(HTTP_AUTHORIZATION=f'Bearer {refresh.access_token}')

    @patch('services.reporting_service.ReportingService.generate_report')
    def test_create_report(self, mock_generate):
        """Test creating a new report"""
        mock_generate.return_value = {
            'report_id': 'test-report-123',
            'file_path': '/reports/test-report-123.pdf',
            'status': 'completed'
        }

        report_data = {
            'scan_session_id': self.scan_session.id,
            'report_name': 'Security Assessment Report',
            'report_format': ReportFormat.PDF,
            'template_used': 'executive_summary',
            'report_config': {
                'include_screenshots': True,
                'include_recommendations': True,
                'include_executive_summary': True,
                'risk_matrix': True
            },
            'executive_summary': 'Critical vulnerabilities found requiring immediate attention'
        }

        response = self.client.post('/api/reports/', report_data, format='json')
        self.assertEqual(response.status_code, 201)

        # Verify report was created
        report = Report.objects.get(id=response.data['id'])
        self.assertEqual(report.scan_session, self.scan_session)
        self.assertEqual(report.report_format, ReportFormat.PDF)
        self.assertEqual(report.template_used, 'executive_summary')

        mock_generate.assert_called_once()

    def test_list_reports(self):
        """Test listing reports"""
        reports = ReportFactory.create_batch(3, scan_session=self.scan_session)

        response = self.client.get('/api/reports/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 3)

    def test_retrieve_report(self):
        """Test retrieving a specific report"""
        report = ReportFactory(scan_session=self.scan_session)

        response = self.client.get(f'/api/reports/{report.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['id'], report.id)
        self.assertEqual(response.data['report_name'], report.report_name)

    def test_update_report(self):
        """Test updating a report"""
        report = ReportFactory(
            scan_session=self.scan_session,
            executive_summary='Initial summary'
        )

        update_data = {
            'executive_summary': 'Updated executive summary with new findings',
            'report_config': {
                'include_screenshots': True,
                'include_recommendations': True,
                'include_technical_details': True
            }
        }

        response = self.client.patch(
            f'/api/reports/{report.id}/',
            update_data,
            format='json'
        )
        self.assertEqual(response.status_code, 200)

        # Verify update
        report.refresh_from_db()
        self.assertEqual(report.executive_summary, 'Updated executive summary with new findings')

    def test_delete_report(self):
        """Test deleting a report"""
        report = ReportFactory(scan_session=self.scan_session)

        response = self.client.delete(f'/api/reports/{report.id}/')
        self.assertEqual(response.status_code, 204)

        # Verify deletion
        self.assertFalse(Report.objects.filter(id=report.id).exists())

    @patch('services.reporting_service.ReportingService.download_report')
    def test_download_report(self, mock_download):
        """Test downloading a report file"""
        mock_download.return_value = {
            'file_content': b'PDF content',
            'content_type': 'application/pdf',
            'filename': 'security_report.pdf'
        }

        report = ReportFactory(
            scan_session=self.scan_session,
            file_path='/reports/test-report.pdf'
        )

        response = self.client.get(f'/api/reports/{report.id}/download/')
        self.assertEqual(response.status_code, 200)

        mock_download.assert_called_once_with(report.id)

    @patch('services.reporting_service.ReportingService.regenerate_report')
    def test_regenerate_report(self, mock_regenerate):
        """Test regenerating an existing report"""
        mock_regenerate.return_value = {
            'status': 'completed',
            'file_path': '/reports/regenerated-report.pdf',
            'generation_time': 45.2
        }

        report = ReportFactory(scan_session=self.scan_session)

        regenerate_data = {
            'include_new_vulnerabilities': True,
            'update_executive_summary': True
        }

        response = self.client.post(
            f'/api/reports/{report.id}/regenerate/',
            regenerate_data,
            format='json'
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['status'], 'completed')

        mock_regenerate.assert_called_once_with(report.id, regenerate_data)

    def test_report_templates(self):
        """Test getting available report templates"""
        response = self.client.get('/api/reports/templates/')
        self.assertEqual(response.status_code, 200)

        templates = response.data
        self.assertIn('templates', templates)
        self.assertIsInstance(templates['templates'], list)

        # Verify template structure
        if templates['templates']:
            template = templates['templates'][0]
            self.assertIn('name', template)
            self.assertIn('description', template)
            self.assertIn('sections', template)

    def test_report_preview(self):
        """Test generating a report preview"""
        preview_data = {
            'scan_session_id': self.scan_session.id,
            'template': 'executive_summary',
            'sections': ['executive_summary', 'vulnerability_overview']
        }

        response = self.client.post('/api/reports/preview/', preview_data, format='json')
        self.assertEqual(response.status_code, 200)

        preview = response.data
        self.assertIn('preview_html', preview)
        self.assertIn('estimated_pages', preview)
        self.assertIn('vulnerability_count', preview)

    def test_filter_reports_by_format(self):
        """Test filtering reports by format"""
        ReportFactory.create_batch(2, scan_session=self.scan_session, report_format=ReportFormat.PDF)
        ReportFactory.create_batch(3, scan_session=self.scan_session, report_format=ReportFormat.HTML)

        # Filter by PDF format
        response = self.client.get('/api/reports/?format=pdf')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 2)

        # Filter by HTML format
        response = self.client.get('/api/reports/?format=html')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 3)

    def test_filter_reports_by_scan_session(self):
        """Test filtering reports by scan session"""
        other_scan = ScanSessionFactory(target=self.target)

        ReportFactory.create_batch(2, scan_session=self.scan_session)
        ReportFactory.create_batch(3, scan_session=other_scan)

        response = self.client.get(f'/api/reports/?scan_session={self.scan_session.id}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 2)

    def test_search_reports(self):
        """Test searching reports"""
        ReportFactory(
            scan_session=self.scan_session,
            report_name='SQL Injection Assessment Report'
        )
        ReportFactory(
            scan_session=self.scan_session,
            report_name='XSS Vulnerability Report'
        )

        response = self.client.get('/api/reports/?search=SQL')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 1)
        self.assertIn('SQL', response.data['results'][0]['report_name'])

    @patch('services.reporting_service.ReportingService.generate_custom_report')
    def test_custom_report_generation(self, mock_generate_custom):
        """Test generating a custom report with specific sections"""
        mock_generate_custom.return_value = {
            'report_id': 'custom-report-123',
            'file_path': '/reports/custom-report-123.pdf',
            'status': 'completed'
        }

        custom_data = {
            'scan_session_id': self.scan_session.id,
            'report_name': 'Custom Security Report',
            'sections': [
                'executive_summary',
                'methodology',
                'findings_overview',
                'detailed_vulnerabilities',
                'recommendations'
            ],
            'custom_config': {
                'include_charts': True,
                'vulnerability_severity_filter': ['high', 'critical'],
                'custom_branding': True,
                'company_logo': '/assets/company_logo.png'
            }
        }

        response = self.client.post('/api/reports/custom/', custom_data, format='json')
        self.assertEqual(response.status_code, 201)

        mock_generate_custom.assert_called_once()

    def test_report_statistics(self):
        """Test report generation statistics"""
        # Create reports with different formats and statuses
        ReportFactory.create_batch(3, scan_session=self.scan_session, report_format=ReportFormat.PDF)
        ReportFactory.create_batch(2, scan_session=self.scan_session, report_format=ReportFormat.HTML)

        response = self.client.get('/api/reports/statistics/')
        self.assertEqual(response.status_code, 200)

        stats = response.data
        self.assertEqual(stats['total'], 5)
        self.assertIn('format_breakdown', stats)
        self.assertIn('average_generation_time', stats)

    @patch('services.reporting_service.ReportingService.bulk_generate_reports')
    def test_bulk_report_generation(self, mock_bulk_generate):
        """Test generating reports for multiple scan sessions"""
        other_scans = ScanSessionFactory.create_batch(2, target=self.target)
        scan_session_ids = [self.scan_session.id] + [s.id for s in other_scans]

        mock_bulk_generate.return_value = {
            'generated_reports': len(scan_session_ids),
            'report_ids': [1, 2, 3],
            'failed_generations': []
        }

        bulk_data = {
            'scan_session_ids': scan_session_ids,
            'report_format': ReportFormat.PDF,
            'template': 'standard_assessment',
            'report_config': {
                'include_executive_summary': True,
                'include_recommendations': True
            }
        }

        response = self.client.post('/api/reports/bulk/', bulk_data, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['generated_reports'], 3)

        mock_bulk_generate.assert_called_once()

    @patch('services.reporting_service.ReportingService.schedule_report_generation')
    def test_schedule_report_generation(self, mock_schedule):
        """Test scheduling automatic report generation"""
        mock_schedule.return_value = {
            'schedule_id': 'schedule-123',
            'next_execution': '2024-01-15T10:00:00Z',
            'status': 'scheduled'
        }

        schedule_data = {
            'scan_session_id': self.scan_session.id,
            'schedule_type': 'weekly',
            'report_format': ReportFormat.PDF,
            'email_recipients': ['admin@company.com', 'security@company.com'],
            'auto_send': True
        }

        response = self.client.post('/api/reports/schedule/', schedule_data, format='json')
        self.assertEqual(response.status_code, 201)
        self.assertIn('schedule_id', response.data)

        mock_schedule.assert_called_once()

    def test_report_sharing(self):
        """Test sharing reports with external users"""
        report = ReportFactory(scan_session=self.scan_session)

        sharing_data = {
            'share_type': 'public_link',
            'expiration_hours': 168,  # 1 week
            'password_protected': True,
            'allowed_downloads': 10
        }

        response = self.client.post(
            f'/api/reports/{report.id}/share/',
            sharing_data,
            format='json'
        )
        self.assertEqual(response.status_code, 200)

        share_data = response.data
        self.assertIn('share_url', share_data)
        self.assertIn('share_token', share_data)
        self.assertIn('expires_at', share_data)

    def test_report_comparison(self):
        """Test comparing multiple reports"""
        # Create multiple reports
        report1 = ReportFactory(scan_session=self.scan_session)
        report2 = ReportFactory(scan_session=self.scan_session)

        comparison_data = {
            'report_ids': [report1.id, report2.id],
            'comparison_type': 'vulnerability_changes'
        }

        response = self.client.post('/api/reports/compare/', comparison_data, format='json')
        self.assertEqual(response.status_code, 200)

        comparison = response.data
        self.assertIn('new_vulnerabilities', comparison)
        self.assertIn('resolved_vulnerabilities', comparison)
        self.assertIn('vulnerability_changes', comparison)

    def test_export_report_data(self):
        """Test exporting report data in various formats"""
        report = ReportFactory(scan_session=self.scan_session)

        # Test CSV export
        response = self.client.get(f'/api/reports/{report.id}/export/?format=csv')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'text/csv')

        # Test JSON export
        response = self.client.get(f'/api/reports/{report.id}/export/?format=json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/json')

        # Test XML export
        response = self.client.get(f'/api/reports/{report.id}/export/?format=xml')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response['Content-Type'], 'application/xml')

    def test_unauthorized_access(self):
        """Test unauthorized access to reporting endpoints"""
        self.client.credentials()

        response = self.client.get('/api/reports/')
        self.assertEqual(response.status_code, 401)

    def test_invalid_report_data(self):
        """Test creating report with invalid data"""
        invalid_data = {
            'scan_session_id': 999999,  # Non-existent scan session
            'report_name': '',          # Empty name
            'report_format': 'invalid_format',  # Invalid format
            'report_config': 'should_be_dict'   # Should be dict
        }

        response = self.client.post('/api/reports/', invalid_data, format='json')
        self.assertEqual(response.status_code, 400)

    def test_report_pagination(self):
        """Test report list pagination"""
        ReportFactory.create_batch(15, scan_session=self.scan_session)

        response = self.client.get('/api/reports/?page=1&page_size=10')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data['results']), 10)
        self.assertIsNotNone(response.data['next'])

    def test_report_ordering(self):
        """Test report list ordering"""
        from django.utils import timezone
        import datetime

        # Create reports at different times
        old_time = timezone.now() - datetime.timedelta(days=2)
        recent_time = timezone.now() - datetime.timedelta(days=1)

        with patch('django.utils.timezone.now', return_value=old_time):
            report1 = ReportFactory(scan_session=self.scan_session)

        with patch('django.utils.timezone.now', return_value=recent_time):
            report2 = ReportFactory(scan_session=self.scan_session)

        # Test ordering by creation date (descending - most recent first)
        response = self.client.get('/api/reports/?ordering=-created_at')
        self.assertEqual(response.status_code, 200)

        results = response.data['results']
        self.assertEqual(results[0]['id'], report2.id)  # Most recent first
        self.assertEqual(results[1]['id'], report1.id)  # Older second

    @patch('services.reporting_service.ReportingService.get_report_metrics')
    def test_report_metrics(self, mock_get_metrics):
        """Test getting detailed report metrics"""
        mock_get_metrics.return_value = {
            'generation_time': 45.2,
            'file_size_bytes': 2048576,
            'page_count': 25,
            'vulnerability_count': 15,
            'charts_count': 8,
            'screenshots_count': 12
        }

        report = ReportFactory(scan_session=self.scan_session)

        response = self.client.get(f'/api/reports/{report.id}/metrics/')
        self.assertEqual(response.status_code, 200)

        metrics = response.data
        self.assertIn('generation_time', metrics)
        self.assertIn('file_size_bytes', metrics)
        self.assertIn('vulnerability_count', metrics)

        mock_get_metrics.assert_called_once_with(report.id)