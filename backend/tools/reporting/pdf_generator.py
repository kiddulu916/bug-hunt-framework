"""
PDF Generator
backend/tools/reporting/pdf_generator.py

Generates PDF format reports using ReportLab or WeasyPrint.
"""

import os
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
import tempfile

logger = logging.getLogger(__name__)

class PDFGenerator:
    """
    Generates PDF format security reports
    """

    def __init__(self):
        self.temp_dir = tempfile.mkdtemp()

    def generate_report(self, report_data: Dict[str, Any], metadata: Any, output_directory: Path) -> str:
        """
        Generate PDF report

        Args:
            report_data: Report data dictionary
            metadata: Report metadata
            output_directory: Output directory path

        Returns:
            Path to generated PDF file
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"security_report_{metadata.target_domain}_{timestamp}.pdf"
        filepath = output_directory / "pdf" / filename

        try:
            # Try different PDF generation methods
            if self._try_weasyprint(report_data, metadata, filepath):
                return str(filepath)
            elif self._try_reportlab(report_data, metadata, filepath):
                return str(filepath)
            else:
                # Fallback to HTML-to-PDF conversion
                return self._generate_html_to_pdf(report_data, metadata, filepath)

        except Exception as e:
            logger.error(f"Error generating PDF report: {str(e)}")
            raise

    def _try_weasyprint(self, report_data: Dict[str, Any], metadata: Any, output_path: Path) -> bool:
        """Try generating PDF using WeasyPrint"""
        try:
            from weasyprint import HTML, CSS
            from weasyprint.text.fonts import FontConfiguration

            # Generate HTML content
            html_content = self._generate_html_content(report_data, metadata)

            # Create CSS for styling
            css_content = self._generate_pdf_css()

            # Generate PDF
            font_config = FontConfiguration()
            html_doc = HTML(string=html_content)
            css_doc = CSS(string=css_content, font_config=font_config)

            html_doc.write_pdf(output_path, stylesheets=[css_doc], font_config=font_config)

            logger.info(f"Generated PDF using WeasyPrint: {output_path}")
            return True

        except ImportError:
            logger.debug("WeasyPrint not available, trying alternative method")
            return False
        except Exception as e:
            logger.error(f"WeasyPrint PDF generation failed: {str(e)}")
            return False

    def _try_reportlab(self, report_data: Dict[str, Any], metadata: Any, output_path: Path) -> bool:
        """Try generating PDF using ReportLab"""
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib import colors

            # Create document
            doc = SimpleDocTemplate(str(output_path), pagesize=A4)
            styles = getSampleStyleSheet()

            # Build story (content)
            story = []

            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.darkblue
            )
            story.append(Paragraph("Security Assessment Report", title_style))
            story.append(Spacer(1, 20))

            # Metadata
            story.append(Paragraph("Report Information", styles['Heading2']))
            metadata_data = [
                ['Target Domain', metadata.target_domain],
                ['Report ID', metadata.report_id],
                ['Assessment Type', metadata.assessment_type.replace('_', ' ').title()],
                ['Start Date', str(metadata.start_date)],
                ['End Date', str(metadata.end_date)],
                ['Tester', f"{metadata.tester_name} ({metadata.tester_email})"]
            ]

            metadata_table = Table(metadata_data, colWidths=[2*inch, 4*inch])
            metadata_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(metadata_table)
            story.append(Spacer(1, 20))

            # Executive Summary
            story.append(Paragraph("Executive Summary", styles['Heading2']))
            summary = report_data['executive_summary']
            story.append(Paragraph(f"Target: {summary['target']}", styles['Normal']))
            story.append(Paragraph(f"Assessment Period: {summary['assessment_period']}", styles['Normal']))
            story.append(Paragraph(f"Total Findings: {summary['total_findings']}", styles['Normal']))
            story.append(Paragraph(f"Overall Risk Score: {summary['overall_risk_score']}%", styles['Normal']))
            story.append(Spacer(1, 20))

            # Severity breakdown
            severity_data = [['Severity', 'Count']]
            for severity, count in summary['severity_breakdown'].items():
                severity_data.append([severity.title(), str(count)])

            severity_table = Table(severity_data, colWidths=[2*inch, 1*inch])
            severity_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 14),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))

            story.append(severity_table)
            story.append(Spacer(1, 20))

            # Detailed Findings
            story.append(Paragraph("Detailed Findings", styles['Heading2']))

            for severity in ['critical', 'high', 'medium', 'low', 'info']:
                findings = report_data['findings'].get(severity, [])
                if not findings:
                    continue

                story.append(Paragraph(f"{severity.title()} Severity ({len(findings)})", styles['Heading3']))

                for finding in findings:
                    story.append(Paragraph(finding['title'], styles['Heading4']))
                    story.append(Paragraph(f"Type: {finding['vulnerability_type'].replace('_', ' ').title()}", styles['Normal']))
                    story.append(Paragraph(f"Description: {finding['description']}", styles['Normal']))
                    story.append(Paragraph(f"Impact: {finding['impact']}", styles['Normal']))

                    if finding.get('affected_urls'):
                        urls_text = "Affected URLs: " + ", ".join(finding['affected_urls'])
                        story.append(Paragraph(urls_text, styles['Normal']))

                    if finding.get('proof_of_concept'):
                        story.append(Paragraph(f"Proof of Concept: {finding['proof_of_concept']}", styles['Code']))

                    story.append(Paragraph(f"Remediation: {finding['remediation']}", styles['Normal']))
                    story.append(Spacer(1, 12))

            # Build PDF
            doc.build(story)

            logger.info(f"Generated PDF using ReportLab: {output_path}")
            return True

        except ImportError:
            logger.debug("ReportLab not available, trying alternative method")
            return False
        except Exception as e:
            logger.error(f"ReportLab PDF generation failed: {str(e)}")
            return False

    def _generate_html_to_pdf(self, report_data: Dict[str, Any], metadata: Any, output_path: Path) -> str:
        """Fallback: Generate HTML and convert to PDF using system tools"""
        try:
            # Generate HTML content
            html_content = self._generate_html_content(report_data, metadata)

            # Save HTML to temp file
            html_temp_path = Path(self.temp_dir) / "report.html"
            with open(html_temp_path, 'w', encoding='utf-8') as f:
                f.write(html_content)

            # Try different conversion methods
            success = (
                self._try_wkhtmltopdf(html_temp_path, output_path) or
                self._try_chromium_pdf(html_temp_path, output_path) or
                self._create_placeholder_pdf(output_path)
            )

            if success:
                logger.info(f"Generated PDF using HTML conversion: {output_path}")
                return str(output_path)
            else:
                raise Exception("All PDF generation methods failed")

        except Exception as e:
            logger.error(f"HTML-to-PDF conversion failed: {str(e)}")
            raise

    def _try_wkhtmltopdf(self, html_path: Path, output_path: Path) -> bool:
        """Try converting HTML to PDF using wkhtmltopdf"""
        try:
            import subprocess

            cmd = [
                'wkhtmltopdf',
                '--page-size', 'A4',
                '--margin-top', '0.75in',
                '--margin-right', '0.75in',
                '--margin-bottom', '0.75in',
                '--margin-left', '0.75in',
                '--encoding', 'UTF-8',
                str(html_path),
                str(output_path)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            return result.returncode == 0

        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.debug(f"wkhtmltopdf conversion failed: {str(e)}")
            return False

    def _try_chromium_pdf(self, html_path: Path, output_path: Path) -> bool:
        """Try converting HTML to PDF using Chromium/Chrome headless"""
        try:
            import subprocess

            # Try different Chrome/Chromium executables
            chrome_paths = [
                'google-chrome',
                'chromium-browser',
                'chromium',
                'google-chrome-stable'
            ]

            for chrome_path in chrome_paths:
                try:
                    cmd = [
                        chrome_path,
                        '--headless',
                        '--disable-gpu',
                        '--print-to-pdf=' + str(output_path),
                        '--print-to-pdf-no-header',
                        'file://' + str(html_path.absolute())
                    ]

                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if result.returncode == 0 and output_path.exists():
                        return True

                except FileNotFoundError:
                    continue

            return False

        except Exception as e:
            logger.debug(f"Chromium PDF conversion failed: {str(e)}")
            return False

    def _create_placeholder_pdf(self, output_path: Path) -> bool:
        """Create a placeholder PDF when other methods fail"""
        try:
            from reportlab.pagesizes import letter
            from reportlab.platypus import SimpleDocTemplate, Paragraph
            from reportlab.lib.styles import getSampleStyleSheet

            doc = SimpleDocTemplate(str(output_path), pagesize=letter)
            styles = getSampleStyleSheet()

            story = [
                Paragraph("Security Assessment Report", styles['Title']),
                Paragraph("PDF generation libraries not available.", styles['Normal']),
                Paragraph("Please install WeasyPrint, ReportLab, or wkhtmltopdf for full PDF support.", styles['Normal']),
                Paragraph("Alternative: Generate HTML or Markdown report instead.", styles['Normal'])
            ]

            doc.build(story)
            return True

        except Exception as e:
            logger.error(f"Failed to create placeholder PDF: {str(e)}")
            return False

    def _generate_html_content(self, report_data: Dict[str, Any], metadata: Any) -> str:
        """Generate HTML content for PDF conversion"""
        from .template_manager import TemplateManager

        template_manager = TemplateManager()
        template = template_manager.get_html_template('comprehensive_report')

        return template.render(
            metadata=report_data.get('metadata', {}),
            executive_summary=report_data['executive_summary'],
            findings=report_data['findings'],
            statistics=report_data['statistics'],
            appendices=report_data.get('appendices', {}),
            generated_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )

    def _generate_pdf_css(self) -> str:
        """Generate CSS optimized for PDF rendering"""
        return """
        @page {
            margin: 2cm;
            @top-center {
                content: "Security Assessment Report";
                font-size: 10pt;
                color: #666;
            }
            @bottom-center {
                content: counter(page);
                font-size: 10pt;
                color: #666;
            }
        }

        body {
            font-family: 'DejaVu Sans', Arial, sans-serif;
            font-size: 11pt;
            line-height: 1.4;
            color: #333;
        }

        h1, h2, h3, h4, h5, h6 {
            color: #2c3e50;
            break-after: avoid;
        }

        h1 { font-size: 24pt; margin-bottom: 20pt; }
        h2 { font-size: 18pt; margin-top: 20pt; margin-bottom: 12pt; }
        h3 { font-size: 14pt; margin-top: 16pt; margin-bottom: 8pt; }
        h4 { font-size: 12pt; margin-top: 12pt; margin-bottom: 6pt; }

        .finding {
            break-inside: avoid;
            margin-bottom: 20pt;
            padding: 10pt;
            border-left: 3pt solid #3498db;
            background-color: #f8f9fa;
        }

        .poc-code {
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 8pt;
            font-family: 'DejaVu Sans Mono', monospace;
            font-size: 9pt;
            white-space: pre-wrap;
            break-inside: avoid;
        }

        table {
            border-collapse: collapse;
            width: 100%;
            margin: 10pt 0;
            break-inside: avoid;
        }

        th, td {
            border: 1pt solid #ddd;
            padding: 6pt;
            text-align: left;
        }

        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }

        .severity-critical { color: #e74c3c; font-weight: bold; }
        .severity-high { color: #e67e22; font-weight: bold; }
        .severity-medium { color: #f39c12; font-weight: bold; }
        .severity-low { color: #27ae60; font-weight: bold; }
        .severity-info { color: #3498db; font-weight: bold; }

        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150pt, 1fr));
            gap: 10pt;
            margin: 10pt 0;
        }

        .stat-card {
            background-color: #f8f9fa;
            padding: 10pt;
            border: 1pt solid #dee2e6;
            text-align: center;
        }

        .stat-number {
            font-size: 18pt;
            font-weight: bold;
            color: #2c3e50;
        }

        .executive-summary {
            background-color: #f8f9fa;
            padding: 15pt;
            border-left: 4pt solid #3498db;
            break-inside: avoid;
        }

        .footer {
            text-align: center;
            margin-top: 30pt;
            padding-top: 15pt;
            border-top: 1pt solid #dee2e6;
            color: #7f8c8d;
            font-size: 9pt;
        }
        """

# Example usage
def main():
    """Example usage of the PDFGenerator"""
    generator = PDFGenerator()

    # Sample data
    sample_data = {
        'executive_summary': {
            'target': 'example.com',
            'assessment_period': '2024-01-01 to 2024-01-07',
            'total_findings': 1,
            'overall_risk_score': 85.0,
            'severity_breakdown': {'critical': 1, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        },
        'findings': {
            'critical': [
                {
                    'title': 'SQL Injection in Login',
                    'vulnerability_type': 'sql_injection',
                    'severity': 'critical',
                    'description': 'SQL injection vulnerability found',
                    'impact': 'Data breach possible',
                    'affected_urls': ['https://example.com/login'],
                    'proof_of_concept': "' OR '1'='1' --",
                    'remediation': 'Use parameterized queries'
                }
            ],
            'high': [], 'medium': [], 'low': [], 'info': []
        },
        'statistics': {
            'total_findings': 1,
            'affected_urls_count': 1,
            'findings_with_poc': 1
        }
    }

    # Mock metadata
    metadata = type('Metadata', (), {
        'target_domain': 'example.com',
        'report_id': 'TEST-001',
        'assessment_type': 'web_app',
        'start_date': '2024-01-01',
        'end_date': '2024-01-07',
        'tester_name': 'Test User',
        'tester_email': 'test@example.com'
    })()

    # Generate PDF
    output_dir = Path('./reports')
    output_dir.mkdir(exist_ok=True)
    (output_dir / 'pdf').mkdir(exist_ok=True)

    try:
        pdf_path = generator.generate_report(sample_data, metadata, output_dir)
        print(f"Generated PDF: {pdf_path}")
    except Exception as e:
        print(f"PDF generation failed: {str(e)}")

if __name__ == "__main__":
    main()