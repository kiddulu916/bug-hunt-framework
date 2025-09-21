"""
Unit tests for Report Generation Tools
"""

import pytest
import tempfile
import json
from pathlib import Path
from unittest.mock import Mock, patch
from django.test import TestCase

from tools.reporting.report_generator import ReportGenerator, ReportFormat
from tools.reporting.template_manager import TemplateManager
from tools.reporting.evidence_collector import EvidenceCollector
from tools.reporting.markdown_generator import MarkdownGenerator
from tools.reporting.pdf_generator import PDFGenerator
from tests.factories import (
    ScanSessionFactory, VulnerabilityFactory, TargetFactory,
    ExploitationSessionFactory
)
from tests.test_utils import TestDataGenerator, EvidenceFileHelper


@pytest.mark.unit
class ReportGeneratorTest(TestCase):
    """Test ReportGenerator functionality"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.target = TargetFactory.create()
        self.scan_session = ScanSessionFactory.create(target=self.target)

        # Create vulnerabilities
        self.critical_vuln = VulnerabilityFactory.create(
            scan_session=self.scan_session,
            severity='critical',
            vulnerability_name='Remote Code Execution'
        )
        self.high_vuln = VulnerabilityFactory.create(
            scan_session=self.scan_session,
            severity='high',
            vulnerability_name='SQL Injection'
        )

        self.report_generator = ReportGenerator(
            output_dir=self.temp_dir,
            template_dir=Path(__file__).parent / 'templates'
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_html_report_generation(self):
        """Test HTML report generation"""
        report_path = self.report_generator.generate_report(
            scan_session=self.scan_session,
            format=ReportFormat.HTML,
            template='executive_summary'
        )

        self.assertTrue(Path(report_path).exists())
        self.assertTrue(report_path.endswith('.html'))

        # Check report content
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()

        self.assertIn(self.target.target_name, content)
        self.assertIn('Remote Code Execution', content)
        self.assertIn('SQL Injection', content)
        self.assertIn('Critical', content)

    def test_pdf_report_generation(self):
        """Test PDF report generation"""
        with patch('tools.reporting.pdf_generator.PDFGenerator.generate_pdf') as mock_pdf:
            mock_pdf.return_value = f"{self.temp_dir}/test_report.pdf"

            report_path = self.report_generator.generate_report(
                scan_session=self.scan_session,
                format=ReportFormat.PDF,
                template='technical_detail'
            )

            self.assertTrue(report_path.endswith('.pdf'))
            mock_pdf.assert_called_once()

    def test_markdown_report_generation(self):
        """Test Markdown report generation"""
        report_path = self.report_generator.generate_report(
            scan_session=self.scan_session,
            format=ReportFormat.MARKDOWN,
            template='penetration_test'
        )

        self.assertTrue(Path(report_path).exists())
        self.assertTrue(report_path.endswith('.md'))

        # Check markdown content
        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()

        self.assertIn('# Penetration Test Report', content)
        self.assertIn('## Executive Summary', content)
        self.assertIn('| Vulnerability |', content)  # Table format
        self.assertIn('🔴', content)  # Critical severity emoji

    def test_json_report_generation(self):
        """Test JSON report generation"""
        report_path = self.report_generator.generate_report(
            scan_session=self.scan_session,
            format=ReportFormat.JSON,
            include_raw_data=True
        )

        self.assertTrue(Path(report_path).exists())
        self.assertTrue(report_path.endswith('.json'))

        # Validate JSON structure
        with open(report_path, 'r', encoding='utf-8') as f:
            data = json.load(f)

        self.assertIn('scan_session', data)
        self.assertIn('target_info', data)
        self.assertIn('vulnerabilities', data)
        self.assertIn('statistics', data)

        self.assertEqual(data['target_info']['name'], self.target.target_name)
        self.assertEqual(len(data['vulnerabilities']), 2)

    def test_report_configuration(self):
        """Test report configuration options"""
        config = {
            'include_screenshots': True,
            'include_payloads': True,
            'include_remediation': True,
            'risk_matrix': True,
            'executive_summary': True,
            'technical_details': False,
            'appendices': True
        }

        report_path = self.report_generator.generate_report(
            scan_session=self.scan_session,
            format=ReportFormat.HTML,
            config=config
        )

        with open(report_path, 'r', encoding='utf-8') as f:
            content = f.read()

        # Should include configured sections
        self.assertIn('Risk Matrix', content)
        self.assertIn('Executive Summary', content)

        # Should not include technical details (disabled)
        self.assertNotIn('Technical Implementation Details', content)

    def test_multi_format_generation(self):
        """Test generating multiple formats simultaneously"""
        formats = [ReportFormat.HTML, ReportFormat.PDF, ReportFormat.MARKDOWN]

        with patch('tools.reporting.pdf_generator.PDFGenerator.generate_pdf') as mock_pdf:
            mock_pdf.return_value = f"{self.temp_dir}/test_report.pdf"

            report_paths = self.report_generator.generate_multi_format_report(
                scan_session=self.scan_session,
                formats=formats,
                template='executive_summary'
            )

        self.assertEqual(len(report_paths), 3)
        self.assertTrue(any(p.endswith('.html') for p in report_paths))
        self.assertTrue(any(p.endswith('.pdf') for p in report_paths))
        self.assertTrue(any(p.endswith('.md') for p in report_paths))

    def test_report_metadata(self):
        """Test report metadata generation"""
        metadata = self.report_generator._generate_metadata(self.scan_session)

        self.assertIn('generated_at', metadata)
        self.assertIn('generator_version', metadata)
        self.assertIn('scan_session_id', metadata)
        self.assertIn('target_name', metadata)
        self.assertIn('vulnerability_count', metadata)

        self.assertEqual(metadata['target_name'], self.target.target_name)
        self.assertEqual(metadata['vulnerability_count'], 2)

    def test_vulnerability_filtering(self):
        """Test filtering vulnerabilities for reports"""
        # Filter only critical vulnerabilities
        filtered_vulns = self.report_generator._filter_vulnerabilities(
            self.scan_session.vulnerabilities.all(),
            min_severity='critical'
        )

        self.assertEqual(len(filtered_vulns), 1)
        self.assertEqual(filtered_vulns[0].severity, 'critical')

        # Filter by vulnerability type
        sql_vulns = self.report_generator._filter_vulnerabilities(
            self.scan_session.vulnerabilities.all(),
            vulnerability_types=['sql_injection']
        )

        self.assertEqual(len(sql_vulns), 1)
        self.assertIn('SQL', sql_vulns[0].vulnerability_name)


@pytest.mark.unit
class TemplateManagerTest(TestCase):
    """Test TemplateManager functionality"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.template_manager = TemplateManager(template_dir=self.temp_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_template_loading(self):
        """Test template loading and caching"""
        # Create a test template
        template_content = """
# {{ target_name }} Penetration Test Report

## Executive Summary
Found {{ vulnerability_count }} vulnerabilities.

{% for vuln in vulnerabilities %}
- **{{ vuln.vulnerability_name }}** ({{ vuln.severity }})
{% endfor %}
"""
        template_path = Path(self.temp_dir) / 'test_template.md'
        template_path.write_text(template_content)

        # Load template
        template = self.template_manager.get_template('test_template.md')
        self.assertIsNotNone(template)

        # Test template rendering
        context = {
            'target_name': 'Example Corp',
            'vulnerability_count': 2,
            'vulnerabilities': [
                {'vulnerability_name': 'XSS', 'severity': 'high'},
                {'vulnerability_name': 'SQLi', 'severity': 'critical'}
            ]
        }

        rendered = template.render(context)

        self.assertIn('Example Corp', rendered)
        self.assertIn('Found 2 vulnerabilities', rendered)
        self.assertIn('**XSS** (high)', rendered)
        self.assertIn('**SQLi** (critical)', rendered)

    def test_template_inheritance(self):
        """Test template inheritance and blocks"""
        # Create base template
        base_template = """
<!DOCTYPE html>
<html>
<head>
    <title>{% block title %}Default Title{% endblock %}</title>
</head>
<body>
    <h1>{% block header %}Default Header{% endblock %}</h1>
    <div class="content">
        {% block content %}{% endblock %}
    </div>
</body>
</html>
"""
        base_path = Path(self.temp_dir) / 'base.html'
        base_path.write_text(base_template)

        # Create child template
        child_template = """
{% extends "base.html" %}

{% block title %}{{ target_name }} Security Report{% endblock %}

{% block header %}Security Assessment Report{% endblock %}

{% block content %}
<h2>Vulnerabilities Found</h2>
<ul>
{% for vuln in vulnerabilities %}
    <li>{{ vuln.vulnerability_name }} - {{ vuln.severity }}</li>
{% endfor %}
</ul>
{% endblock %}
"""
        child_path = Path(self.temp_dir) / 'report.html'
        child_path.write_text(child_template)

        # Test inheritance
        template = self.template_manager.get_template('report.html')
        context = {
            'target_name': 'Test Corp',
            'vulnerabilities': [
                {'vulnerability_name': 'XSS', 'severity': 'medium'}
            ]
        }

        rendered = template.render(context)

        self.assertIn('<title>Test Corp Security Report</title>', rendered)
        self.assertIn('<h1>Security Assessment Report</h1>', rendered)
        self.assertIn('<li>XSS - medium</li>', rendered)

    def test_custom_filters(self):
        """Test custom Jinja2 filters"""
        template_content = """
Severity: {{ severity | severity_color }}
CVSS: {{ cvss_score | format_cvss }}
Date: {{ timestamp | format_date }}
"""
        template_path = Path(self.temp_dir) / 'filters_test.html'
        template_path.write_text(template_content)

        template = self.template_manager.get_template('filters_test.html')
        context = {
            'severity': 'critical',
            'cvss_score': 9.8,
            'timestamp': '2023-10-01T12:00:00Z'
        }

        rendered = template.render(context)

        # Custom filters should process the values
        self.assertIn('critical', rendered)

    def test_template_validation(self):
        """Test template syntax validation"""
        # Invalid template syntax
        invalid_template = """
# Report for {{ target_name }
{% for vuln in vulnerabilities %  # Missing closing %}
- {{ vuln.name }}
"""
        invalid_path = Path(self.temp_dir) / 'invalid.md'
        invalid_path.write_text(invalid_template)

        # Should handle invalid template gracefully
        with self.assertRaises(Exception):
            template = self.template_manager.get_template('invalid.md')
            template.render({'target_name': 'Test'})


@pytest.mark.unit
class EvidenceCollectorTest(TestCase):
    """Test EvidenceCollector functionality"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.evidence_collector = EvidenceCollector(
            evidence_dir=self.temp_dir,
            max_file_size=10 * 1024 * 1024  # 10MB
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_screenshot_collection(self):
        """Test screenshot evidence collection"""
        # Create mock screenshot data
        screenshot_data = EvidenceFileHelper.create_screenshot_file()

        evidence_path = self.evidence_collector.collect_screenshot(
            vulnerability_id='vuln_001',
            screenshot_data=screenshot_data.read(),
            filename='exploit_proof.png'
        )

        self.assertTrue(Path(evidence_path).exists())
        self.assertIn('vuln_001', evidence_path)
        self.assertTrue(evidence_path.endswith('.png'))

    def test_log_collection(self):
        """Test log file evidence collection"""
        log_content = """
[2023-10-01 12:00:00] Starting exploitation attempt
[2023-10-01 12:00:05] Payload sent: admin' OR '1'='1' --
[2023-10-01 12:00:06] Response received: Welcome administrator
[2023-10-01 12:00:07] Exploitation successful
"""

        evidence_path = self.evidence_collector.collect_log(
            vulnerability_id='vuln_002',
            log_content=log_content,
            log_type='exploitation'
        )

        self.assertTrue(Path(evidence_path).exists())

        with open(evidence_path, 'r') as f:
            stored_content = f.read()

        self.assertIn('Exploitation successful', stored_content)

    def test_network_trace_collection(self):
        """Test network trace evidence collection"""
        # Mock PCAP data
        pcap_data = b'\xd4\xc3\xb2\xa1\x02\x00\x04\x00'  # PCAP header

        evidence_path = self.evidence_collector.collect_network_trace(
            vulnerability_id='vuln_003',
            pcap_data=pcap_data,
            filename='exploit_traffic.pcap'
        )

        self.assertTrue(Path(evidence_path).exists())
        self.assertTrue(evidence_path.endswith('.pcap'))

    def test_evidence_organization(self):
        """Test evidence organization by vulnerability"""
        vuln_id = 'vuln_004'

        # Collect multiple types of evidence
        screenshot = self.evidence_collector.collect_screenshot(
            vuln_id, b'fake_image_data', 'screenshot1.png'
        )
        log = self.evidence_collector.collect_log(
            vuln_id, 'log content', 'request'
        )

        # Get evidence summary
        evidence_summary = self.evidence_collector.get_evidence_summary(vuln_id)

        self.assertEqual(len(evidence_summary['files']), 2)
        self.assertIn('screenshot1.png', str(evidence_summary['files'][0]))

        # Check evidence directory structure
        vuln_dir = Path(self.temp_dir) / vuln_id
        self.assertTrue(vuln_dir.exists())

    def test_evidence_validation(self):
        """Test evidence file validation"""
        # Test file size limits
        large_data = b'x' * (15 * 1024 * 1024)  # 15MB (exceeds limit)

        with self.assertRaises(ValueError):
            self.evidence_collector.collect_screenshot(
                'vuln_005', large_data, 'large_screenshot.png'
            )

    def test_evidence_integrity(self):
        """Test evidence integrity verification"""
        original_data = b'important evidence data'

        evidence_path = self.evidence_collector.collect_log(
            'vuln_006', original_data.decode(), 'important'
        )

        # Verify integrity
        is_valid = self.evidence_collector.verify_evidence_integrity(evidence_path)
        self.assertTrue(is_valid)

        # Tamper with evidence
        with open(evidence_path, 'w') as f:
            f.write('tampered data')

        # Should detect tampering
        is_valid = self.evidence_collector.verify_evidence_integrity(evidence_path)
        self.assertFalse(is_valid)

    def test_evidence_cleanup(self):
        """Test cleanup of old evidence files"""
        # Create old evidence files
        old_evidence = self.evidence_collector.collect_screenshot(
            'vuln_007', b'old_data', 'old_screenshot.png'
        )

        # Manually set old timestamp
        import os
        import time
        old_time = time.time() - (90 * 24 * 60 * 60)  # 90 days ago
        os.utime(old_evidence, (old_time, old_time))

        # Run cleanup
        cleaned_count = self.evidence_collector.cleanup_old_evidence(days=30)

        self.assertGreater(cleaned_count, 0)
        self.assertFalse(Path(old_evidence).exists())


@pytest.mark.unit
class MarkdownGeneratorTest(TestCase):
    """Test MarkdownGenerator functionality"""

    def setUp(self):
        self.scan_session = ScanSessionFactory.create()
        self.vulnerabilities = VulnerabilityFactory.create_batch(
            3, scan_session=self.scan_session
        )
        self.markdown_generator = MarkdownGenerator()

    def test_vulnerability_table_generation(self):
        """Test vulnerability table generation"""
        table = self.markdown_generator.generate_vulnerability_table(
            self.vulnerabilities
        )

        self.assertIn('| Vulnerability |', table)
        self.assertIn('| Severity |', table)
        self.assertIn('|---|', table)  # Table separator

        for vuln in self.vulnerabilities:
            self.assertIn(vuln.vulnerability_name, table)

    def test_severity_emoji_mapping(self):
        """Test severity to emoji mapping"""
        critical_emoji = self.markdown_generator._get_severity_emoji('critical')
        high_emoji = self.markdown_generator._get_severity_emoji('high')
        medium_emoji = self.markdown_generator._get_severity_emoji('medium')
        low_emoji = self.markdown_generator._get_severity_emoji('low')

        self.assertEqual(critical_emoji, '🔴')
        self.assertEqual(high_emoji, '🟠')
        self.assertEqual(medium_emoji, '🟡')
        self.assertEqual(low_emoji, '🟢')

    def test_code_block_generation(self):
        """Test code block generation"""
        payload = "admin' OR '1'='1' --"
        code_block = self.markdown_generator.generate_code_block(
            payload, language='sql'
        )

        self.assertIn('```sql', code_block)
        self.assertIn(payload, code_block)
        self.assertIn('```', code_block)

    def test_risk_matrix_generation(self):
        """Test risk matrix generation"""
        vulnerabilities = [
            VulnerabilityFactory.create(severity='critical', cvss_score=9.8),
            VulnerabilityFactory.create(severity='high', cvss_score=8.1),
            VulnerabilityFactory.create(severity='medium', cvss_score=5.4),
        ]

        risk_matrix = self.markdown_generator.generate_risk_matrix(vulnerabilities)

        self.assertIn('Risk Matrix', risk_matrix)
        self.assertIn('Critical', risk_matrix)
        self.assertIn('9.8', risk_matrix)

    def test_executive_summary_generation(self):
        """Test executive summary generation"""
        summary = self.markdown_generator.generate_executive_summary(
            self.scan_session, self.vulnerabilities
        )

        self.assertIn('Executive Summary', summary)
        self.assertIn(self.scan_session.target.target_name, summary)
        self.assertIn(str(len(self.vulnerabilities)), summary)


@pytest.mark.unit
class PDFGeneratorTest(TestCase):
    """Test PDFGenerator functionality"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.pdf_generator = PDFGenerator(output_dir=self.temp_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    @patch('weasyprint.HTML')
    def test_html_to_pdf_conversion(self, mock_html):
        """Test HTML to PDF conversion"""
        html_content = """
        <html>
            <head><title>Test Report</title></head>
            <body>
                <h1>Security Report</h1>
                <p>This is a test report.</p>
            </body>
        </html>
        """

        mock_document = Mock()
        mock_html.return_value = mock_document

        pdf_path = self.pdf_generator.generate_from_html(
            html_content, 'test_report.pdf'
        )

        self.assertTrue(pdf_path.endswith('.pdf'))
        mock_html.assert_called_once()
        mock_document.write_pdf.assert_called_once()

    def test_pdf_styling(self):
        """Test PDF styling and formatting"""
        css_styles = self.pdf_generator.get_default_styles()

        self.assertIn('@page', css_styles)
        self.assertIn('font-family', css_styles)
        self.assertIn('margin', css_styles)

    @patch('reportlab.pdfgen.canvas.Canvas')
    def test_direct_pdf_generation(self, mock_canvas):
        """Test direct PDF generation with reportlab"""
        mock_canvas_instance = Mock()
        mock_canvas.return_value = mock_canvas_instance

        content = {
            'title': 'Security Assessment Report',
            'sections': [
                {'title': 'Executive Summary', 'content': 'Summary content'},
                {'title': 'Vulnerabilities', 'content': 'Vulnerability details'}
            ]
        }

        pdf_path = self.pdf_generator.generate_direct(content, 'direct_report.pdf')

        self.assertTrue(pdf_path.endswith('.pdf'))
        mock_canvas.assert_called_once()


@pytest.mark.integration
class ReportGenerationIntegrationTest(TestCase):
    """Integration tests for complete report generation workflow"""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.target = TargetFactory.create(target_name='Integration Test Corp')
        self.scan_session = ScanSessionFactory.create(target=self.target)

        # Create complex test data
        self.vulnerabilities = [
            VulnerabilityFactory.create(
                scan_session=self.scan_session,
                severity='critical',
                vulnerability_name='Remote Code Execution',
                cvss_score=9.8
            ),
            VulnerabilityFactory.create(
                scan_session=self.scan_session,
                severity='high',
                vulnerability_name='SQL Injection',
                cvss_score=8.1
            ),
        ]

        self.exploitation_session = ExploitationSessionFactory.create(
            vulnerability=self.vulnerabilities[0],
            target=self.target,
            status='successful'
        )

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_complete_report_workflow(self):
        """Test complete report generation workflow"""
        report_generator = ReportGenerator(output_dir=self.temp_dir)

        # Generate HTML report
        html_report = report_generator.generate_report(
            scan_session=self.scan_session,
            format=ReportFormat.HTML,
            template='executive_summary'
        )

        # Generate Markdown report
        md_report = report_generator.generate_report(
            scan_session=self.scan_session,
            format=ReportFormat.MARKDOWN,
            template='technical_detail'
        )

        # Generate JSON report
        json_report = report_generator.generate_report(
            scan_session=self.scan_session,
            format=ReportFormat.JSON
        )

        # Verify all reports were created
        self.assertTrue(Path(html_report).exists())
        self.assertTrue(Path(md_report).exists())
        self.assertTrue(Path(json_report).exists())

        # Verify report content
        with open(html_report, 'r') as f:
            html_content = f.read()
            self.assertIn('Integration Test Corp', html_content)
            self.assertIn('Remote Code Execution', html_content)

        with open(json_report, 'r') as f:
            json_data = json.load(f)
            self.assertEqual(json_data['target_info']['name'], 'Integration Test Corp')
            self.assertEqual(len(json_data['vulnerabilities']), 2)

    def test_evidence_integration(self):
        """Test evidence collection and integration in reports"""
        evidence_collector = EvidenceCollector(evidence_dir=self.temp_dir)

        # Collect evidence for vulnerabilities
        screenshot_path = evidence_collector.collect_screenshot(
            str(self.vulnerabilities[0].id),
            b'fake_screenshot_data',
            'rce_proof.png'
        )

        log_path = evidence_collector.collect_log(
            str(self.vulnerabilities[1].id),
            'Exploitation log content',
            'sql_injection'
        )

        # Generate report with evidence
        report_generator = ReportGenerator(
            output_dir=self.temp_dir,
            evidence_collector=evidence_collector
        )

        report_path = report_generator.generate_report(
            scan_session=self.scan_session,
            format=ReportFormat.HTML,
            config={'include_evidence': True}
        )

        # Verify evidence is referenced in report
        with open(report_path, 'r') as f:
            content = f.read()
            self.assertIn('Evidence', content)

    def test_multi_target_report(self):
        """Test report generation for multiple targets"""
        # Create second target and scan
        target2 = TargetFactory.create(target_name='Second Target')
        scan_session2 = ScanSessionFactory.create(target=target2)
        VulnerabilityFactory.create(scan_session=scan_session2, severity='medium')

        report_generator = ReportGenerator(output_dir=self.temp_dir)

        # Generate consolidated report
        consolidated_report = report_generator.generate_consolidated_report(
            scan_sessions=[self.scan_session, scan_session2],
            format=ReportFormat.HTML
        )

        self.assertTrue(Path(consolidated_report).exists())

        with open(consolidated_report, 'r') as f:
            content = f.read()
            self.assertIn('Integration Test Corp', content)
            self.assertIn('Second Target', content)