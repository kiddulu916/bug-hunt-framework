"""
Reporting service for generating comprehensive security reports.
Handles report generation, templates, formatting, and export functionality.
"""

import os
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
import tempfile
import asyncio

from jinja2 import Environment, FileSystemLoader, Template
from weasyprint import HTML, CSS
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors

from apps.reports.models import Report
from apps.scans.models import ScanSession
from core.constants import REPORT_TYPES, REPORT_FORMATS, REPORT_TEMPLATES
from core.exceptions import (
    ReportGenerationException,
    TemplateNotFoundException,
    FileProcessingException
)
from api.schemas.report import ReportExport
from api.schemas.vulnerability import VulnerabilityExport

logger = logging.getLogger(__name__)

class ReportingService:
    """
    Service for generating and managing security reports.
    """
    
    def __init__(self):
        self.reports_dir = Path(os.getenv('REPORTS_DIR', '/app/reports'))
        self.templates_dir = Path(os.getenv('TEMPLATES_DIR', '/app/templates/reports'))
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        
        # Initialize Jinja2 environment
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=True
        )
        
        # Report generation statistics
        self.generation_stats = {
            'total_generated': 0,
            'generation_times': [],
            'error_count': 0
        }

    async def generate_report(self, report_id: str, template_options: Dict[str, Any], 
                            user_id: int) -> Dict[str, Any]:
        """
        Generate a comprehensive security report.
        
        Args:
            report_id: Report ID to generate
            template_options: Template-specific options
            user_id: User ID generating the report
            
        Returns:
            dict: Generation results and file paths
        """
        try:
            start_time = datetime.utcnow()
            
            # Get report and scan data (mock for now - would be database queries)
            report = await self._get_report(report_id)
            scan_session = await self._get_scan_session(report.scan_session_id)
            vulnerabilities = await self._get_vulnerabilities(report.scan_session_id)
            
            # Prepare report data
            report_data = await self._prepare_report_data(
                report, scan_session, vulnerabilities, template_options
            )
            
            # Generate report in multiple formats
            generation_results = {
                'report_id': report_id,
                'generated_at': start_time,
                'formats_generated': [],
                'file_paths': {},
                'generation_time': 0,
                'total_size': 0
            }
            
            # Generate PDF report
            pdf_path = await self._generate_pdf_report(report_data, report.report_type)
            if pdf_path:
                generation_results['formats_generated'].append('pdf')
                generation_results['file_paths']['pdf'] = str(pdf_path)
                generation_results['total_size'] += pdf_path.stat().st_size
            
            # Generate HTML report
            html_path = await self._generate_html_report(report_data, report.report_type)
            if html_path:
                generation_results['formats_generated'].append('html')
                generation_results['file_paths']['html'] = str(html_path)
                generation_results['total_size'] += html_path.stat().st_size
            
            # Generate JSON report
            json_path = await self._generate_json_report(report_data)
            if json_path:
                generation_results['formats_generated'].append('json')
                generation_results['file_paths']['json'] = str(json_path)
                generation_results['total_size'] += json_path.stat().st_size
            
            # Calculate generation time
            end_time = datetime.utcnow()
            generation_time = (end_time - start_time).total_seconds()
            generation_results['generation_time'] = generation_time
            
            # Update statistics
            self.generation_stats['total_generated'] += 1
            self.generation_stats['generation_times'].append(generation_time)
            
            logger.info(f"Generated report {report_id} in {generation_time:.2f}s")
            
            return generation_results
            
        except Exception as e:
            self.generation_stats['error_count'] += 1
            logger.error(f"Error generating report {report_id}: {e}")
            raise ReportGenerationException(report.report_type if 'report' in locals() else 'unknown', str(e))

    async def generate_custom_report(self, report_id: str, generation_request: Dict[str, Any], 
                                   user_id: int) -> Dict[str, Any]:
        """
        Generate a custom report with specific parameters.
        
        Args:
            report_id: Report ID
            generation_request: Custom generation parameters
            user_id: User ID
            
        Returns:
            dict: Generation results
        """
        try:
            # Get data from multiple scan sessions if specified
            scan_sessions = []
            vulnerabilities = []
            
            for session_id in generation_request['scan_session_ids']:
                session = await self._get_scan_session(session_id)
                session_vulns = await self._get_vulnerabilities(session_id)
                
                scan_sessions.append(session)
                vulnerabilities.extend(session_vulns)
            
            # Apply filters
            filtered_vulnerabilities = self._apply_vulnerability_filters(
                vulnerabilities, generation_request
            )
            
            # Prepare custom report data
            report_data = {
                'report_metadata': {
                    'title': generation_request['report_name'],
                    'type': generation_request['report_type'],
                    'generated_at': datetime.utcnow(),
                    'generated_by': user_id,
                    'scan_sessions': len(scan_sessions),
                    'total_vulnerabilities': len(filtered_vulnerabilities)
                },
                'scan_sessions': scan_sessions,
                'vulnerabilities': filtered_vulnerabilities,
                'statistics': self._calculate_report_statistics(filtered_vulnerabilities),
                'options': generation_request
            }
            
            # Generate in requested formats
            results = {'generated_files': {}}
            
            for format_type in generation_request.get('output_formats', ['pdf']):
                if format_type == 'pdf':
                    file_path = await self._generate_pdf_report(
                        report_data, generation_request['report_type']
                    )
                elif format_type == 'html':
                    file_path = await self._generate_html_report(
                        report_data, generation_request['report_type']
                    )
                elif format_type == 'json':
                    file_path = await self._generate_json_report(report_data)
                
                if file_path:
                    results['generated_files'][format_type] = str(file_path)
            
            return results
            
        except Exception as e:
            logger.error(f"Error generating custom report: {e}")
            raise ReportGenerationException('custom', str(e))

    async def get_available_templates(self, report_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Get list of available report templates.
        
        Args:
            report_type: Filter by report type (optional)
            
        Returns:
            list: Available templates
        """
        try:
            templates = []
            
            # Scan templates directory
            if self.templates_dir.exists():
                for template_file in self.templates_dir.glob('*.html'):
                    template_info = await self._get_template_info(template_file)
                    
                    if report_type is None or template_info.get('report_type') == report_type:
                        templates.append(template_info)
            
            # Add built-in templates
            for template_name, template_file in REPORT_TEMPLATES.items():
                if report_type is None or template_name.startswith(report_type):
                    templates.append({
                        'template_name': template_name,
                        'display_name': template_name.replace('_', ' ').title(),
                        'description': f'Built-in {template_name} template',
                        'report_type': template_name.split('_')[0],
                        'supported_formats': ['pdf', 'html', 'json'],
                        'is_built_in': True
                    })
            
            return templates
            
        except Exception as e:
            logger.error(f"Error getting available templates: {e}")
            return []

    async def get_template_details(self, template_name: str) -> Optional[Dict[str, Any]]:
        """
        Get detailed information about a specific template.
        
        Args:
            template_name: Template name
            
        Returns:
            dict: Template details or None if not found
        """
        try:
            template_path = self.templates_dir / f"{template_name}.html"
            
            if template_path.exists():
                return await self._get_template_info(template_path)
            
            # Check built-in templates
            if template_name in REPORT_TEMPLATES:
                return {
                    'template_name': template_name,
                    'display_name': template_name.replace('_', ' ').title(),
                    'description': f'Built-in {template_name} template',
                    'report_type': template_name.split('_')[0],
                    'supported_formats': ['pdf', 'html', 'json'],
                    'is_built_in': True,
                    'customizable_sections': ['executive_summary', 'recommendations'],
                    'template_options': {
                        'include_raw_data': {'type': 'boolean', 'default': False},
                        'severity_threshold': {'type': 'select', 'options': ['low', 'medium', 'high'], 'default': 'medium'}
                    }
                }
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting template details for {template_name}: {e}")
            return None

    async def export_report_data(self, report: Report, export_format: str, 
                                include_raw_data: bool = False) -> Dict[str, Any]:
        """
        Export report data in various formats for integration.
        
        Args:
            report: Report instance
            export_format: Export format (json, xml, csv)
            include_raw_data: Include raw scan data
            
        Returns:
            dict: Exported data
        """
        try:
            # Get report data
            scan_session = await self._get_scan_session(report.scan_session_id)
            vulnerabilities = await self._get_vulnerabilities(report.scan_session_id)
            
            export_data = {
                'report_metadata': {
                    'id': str(report.id),
                    'name': report.report_name,
                    'type': report.report_type,
                    'generated_at': report.generated_at.isoformat() if report.generated_at else None,
                    'scan_session_id': str(report.scan_session_id)
                },
                'scan_summary': {
                    'target_name': getattr(scan_session, 'target_name', 'Unknown'),
                    'scan_duration': getattr(scan_session, 'duration_seconds', 0),
                    'total_vulnerabilities': len(vulnerabilities),
                    'vulnerability_breakdown': self._get_vulnerability_breakdown(vulnerabilities)
                },
                'vulnerabilities': self._format_vulnerabilities_for_export(vulnerabilities, include_raw_data),
                'statistics': self._calculate_report_statistics(vulnerabilities)
            }
            
            if export_format == 'json':
                return export_data
            elif export_format == 'xml':
                return self._convert_to_xml(export_data)
            elif export_format == 'csv':
                return self._convert_to_csv(export_data)
            else:
                raise ValueError(f"Unsupported export format: {export_format}")
                
        except Exception as e:
            logger.error(f"Error exporting report data: {e}")
            raise FileProcessingException(str(report.id), "export", str(e))

    async def export_vulnerabilities(self, export_data: VulnerabilityExport) -> str:
        """
        Export vulnerabilities in specified format.
        
        Args:
            export_data: Vulnerability export configuration
            
        Returns:
            str: Path to exported file
        """
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"vulnerabilities_export_{timestamp}.{export_data.export_format}"
            file_path = self.reports_dir / filename
            
            if export_data.export_format == 'csv':
                await self._export_vulnerabilities_csv(export_data.vulnerabilities, file_path)
            elif export_data.export_format == 'json':
                await self._export_vulnerabilities_json(export_data.vulnerabilities, file_path)
            elif export_data.export_format == 'xml':
                await self._export_vulnerabilities_xml(export_data.vulnerabilities, file_path)
            elif export_data.export_format == 'pdf':
                await self._export_vulnerabilities_pdf(export_data.vulnerabilities, file_path)
            
            return str(file_path)
            
        except Exception as e:
            logger.error(f"Error exporting vulnerabilities: {e}")
            raise FileProcessingException("vulnerabilities", "export", str(e))

    async def cleanup_report_files(self, report: Report) -> None:
        """
        Clean up associated files for a report.
        
        Args:
            report: Report instance
        """
        try:
            file_paths = [
                report.pdf_file_path,
                report.html_file_path,
                report.json_file_path
            ]
            
            for file_path in file_paths:
                if file_path and Path(file_path).exists():
                    Path(file_path).unlink()
                    logger.info(f"Deleted report file: {file_path}")
                    
        except Exception as e:
            logger.error(f"Error cleaning up report files: {e}")

    # Private helper methods

    async def _prepare_report_data(self, report: Report, scan_session: Any, 
                                 vulnerabilities: List[Any], template_options: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare comprehensive data for report generation."""
        return {
            'report_metadata': {
                'title': report.report_name,
                'type': report.report_type,
                'generated_at': datetime.utcnow(),
                'scan_session_id': str(report.scan_session_id),
                'total_vulnerabilities': len(vulnerabilities)
            },
            'executive_summary': self._generate_executive_summary(vulnerabilities),
            'scan_details': {
                'target_name': getattr(scan_session, 'target_name', 'Unknown'),
                'scan_duration': getattr(scan_session, 'duration_seconds', 0),
                'methodology_phases': getattr(scan_session, 'methodology_phases', []),
                'tools_used': []
            },
            'vulnerabilities': vulnerabilities,
            'statistics': self._calculate_report_statistics(vulnerabilities),
            'recommendations': self._generate_recommendations(vulnerabilities),
            'template_options': template_options
        }

    async def _generate_pdf_report(self, report_data: Dict[str, Any], report_type: str) -> Optional[Path]:
        """Generate PDF report using ReportLab."""
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"{report_type}_report_{timestamp}.pdf"
            file_path = self.reports_dir / filename
            
            # Create PDF document
            doc = SimpleDocTemplate(
                str(file_path),
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build story (content)
            story = []
            styles = getSampleStyleSheet()
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Title'],
                fontSize=24,
                spaceAfter=30,
                textColor=colors.darkblue
            )
            
            story.append(Paragraph(report_data['report_metadata']['title'], title_style))
            story.append(Spacer(1, 12))
            
            # Executive Summary
            if report_data.get('executive_summary'):
                story.append(Paragraph("Executive Summary", styles['Heading1']))
                story.append(Paragraph(report_data['executive_summary'], styles['Normal']))
                story.append(Spacer(1, 12))
            
            # Vulnerability Summary Table
            if report_data.get('statistics'):
                story.append(Paragraph("Vulnerability Summary", styles['Heading1']))
                
                vuln_data = [
                    ['Severity', 'Count'],
                    ['Critical', str(report_data['statistics'].get('critical', 0))],
                    ['High', str(report_data['statistics'].get('high', 0))],
                    ['Medium', str(report_data['statistics'].get('medium', 0))],
                    ['Low', str(report_data['statistics'].get('low', 0))],
                ]
                
                vuln_table = Table(vuln_data)
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 14),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(vuln_table)
                story.append(Spacer(1, 12))
            
            # Detailed Vulnerabilities
            if report_data.get('vulnerabilities'):
                story.append(Paragraph("Detailed Findings", styles['Heading1']))
                
                for vuln in report_data['vulnerabilities'][:10]:  # Limit for example
                    story.append(Paragraph(f"Vulnerability: {vuln.get('name', 'Unknown')}", styles['Heading2']))
                    story.append(Paragraph(f"Severity: {vuln.get('severity', 'Unknown')}", styles['Normal']))
                    story.append(Paragraph(f"Description: {vuln.get('description', 'No description')}", styles['Normal']))
                    story.append(Spacer(1, 6))
            
            # Build PDF
            doc.build(story)
            
            return file_path
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {e}")
            return None

    async def _generate_html_report(self, report_data: Dict[str, Any], report_type: str) -> Optional[Path]:
        """Generate HTML report using Jinja2 templates."""
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"{report_type}_report_{timestamp}.html"
            file_path = self.reports_dir / filename
            
            # Get template
            template_name = f"{report_type}_report.html"
            
            try:
                template = self.jinja_env.get_template(template_name)
            except:
                # Use default template if specific one doesn't exist
                template = Template(self._get_default_html_template())
            
            # Render template
            html_content = template.render(**report_data)
            
            # Save to file
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            return file_path
            
        except Exception as e:
            logger.error(f"Error generating HTML report: {e}")
            return None

    async def _generate_json_report(self, report_data: Dict[str, Any]) -> Optional[Path]:
        """Generate JSON report."""
        try:
            timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
            filename = f"report_{timestamp}.json"
            file_path = self.reports_dir / filename
            
            # Convert datetime objects to strings for JSON serialization
            json_data = self._serialize_for_json(report_data)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, ensure_ascii=False)
            
            return file_path
            
        except Exception as e:
            logger.error(f"Error generating JSON report: {e}")
            return None

    def _generate_executive_summary(self, vulnerabilities: List[Any]) -> str:
        """Generate executive summary based on vulnerabilities."""
        total_vulns = len(vulnerabilities)
        
        if total_vulns == 0:
            return "No vulnerabilities were identified during this security assessment."
        
        # Count by severity
        critical = len([v for v in vulnerabilities if v.get('severity') == 'critical'])
        high = len([v for v in vulnerabilities if v.get('severity') == 'high'])
        medium = len([v for v in vulnerabilities if v.get('severity') == 'medium'])
        low = len([v for v in vulnerabilities if v.get('severity') == 'low'])
        
        summary = f"This security assessment identified {total_vulns} vulnerabilities. "
        
        if critical > 0:
            summary += f"Of critical concern are {critical} critical severity vulnerabilities that require immediate attention. "
        
        if high > 0:
            summary += f"Additionally, {high} high severity vulnerabilities should be prioritized for remediation. "
        
        if medium > 0:
            summary += f"{medium} medium severity vulnerabilities were also identified. "
        
        if low > 0:
            summary += f"{low} low severity vulnerabilities complete the findings. "
        
        summary += "Detailed technical information and remediation guidance are provided in the following sections."
        
        return summary

    def _calculate_report_statistics(self, vulnerabilities: List[Any]) -> Dict[str, Any]:
        """Calculate comprehensive statistics for vulnerabilities."""
        stats = {
            'total': len(vulnerabilities),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'by_type': {},
            'by_owasp_category': {},
            'verified_count': 0,
            'exploitable_count': 0
        }
        
        for vuln in vulnerabilities:
            # Count by severity
            severity = vuln.get('severity', 'unknown').lower()
            if severity in stats:
                stats[severity] += 1
            
            # Count by type
            vuln_type = vuln.get('vulnerability_type', 'unknown')
            stats['by_type'][vuln_type] = stats['by_type'].get(vuln_type, 0) + 1
            
            # Count by OWASP category
            owasp_cat = vuln.get('owasp_category', 'unknown')
            stats['by_owasp_category'][owasp_cat] = stats['by_owasp_category'].get(owasp_cat, 0) + 1
            
            # Count verified and exploitable
            if vuln.get('manually_verified'):
                stats['verified_count'] += 1
            
            if vuln.get('is_exploitable'):
                stats['exploitable_count'] += 1
        
        return stats

    def _generate_recommendations(self, vulnerabilities: List[Any]) -> List[str]:
        """Generate remediation recommendations."""
        recommendations = []
        
        # Critical vulnerabilities
        critical_vulns = [v for v in vulnerabilities if v.get('severity') == 'critical']
        if critical_vulns:
            recommendations.append(
                f"Immediately address {len(critical_vulns)} critical severity vulnerabilities "
                "as they pose significant security risks."
            )
        
        # High vulnerabilities
        high_vulns = [v for v in vulnerabilities if v.get('severity') == 'high']
        if high_vulns:
            recommendations.append(
                f"Prioritize remediation of {len(high_vulns)} high severity vulnerabilities "
                "within the next sprint cycle."
            )
        
        # Common vulnerability types
        vuln_types = {}
        for vuln in vulnerabilities:
            vtype = vuln.get('vulnerability_type', 'unknown')
            vuln_types[vtype] = vuln_types.get(vtype, 0) + 1
        
        # Type-specific recommendations
        if vuln_types.get('sql_injection', 0) > 0:
            recommendations.append(
                "Implement parameterized queries and input validation to prevent SQL injection attacks."
            )
        
        if vuln_types.get('xss_reflected', 0) > 0 or vuln_types.get('xss_stored', 0) > 0:
            recommendations.append(
                "Apply output encoding and implement Content Security Policy (CSP) to mitigate XSS vulnerabilities."
            )
        
        # General recommendations
        recommendations.extend([
            "Implement a regular vulnerability scanning schedule.",
            "Provide security training for development teams.",
            "Establish a security code review process.",
            "Consider implementing a Web Application Firewall (WAF)."
        ])
        
        return recommendations

    def _apply_vulnerability_filters(self, vulnerabilities: List[Any], 
                                   generation_request: Dict[str, Any]) -> List[Any]:
        """Apply filters to vulnerability list."""
        filtered = vulnerabilities
        
        # Severity filter
        if generation_request.get('severity_filter'):
            severity_list = generation_request['severity_filter']
            filtered = [v for v in filtered if v.get('severity') in severity_list]
        
        # Vulnerability types filter
        if generation_request.get('vulnerability_types_filter'):
            types_list = generation_request['vulnerability_types_filter']
            filtered = [v for v in filtered if v.get('vulnerability_type') in types_list]
        
        # Verified only filter
        if generation_request.get('verified_only'):
            filtered = [v for v in filtered if v.get('manually_verified')]
        
        # Exclude false positives
        if generation_request.get('exclude_false_positives'):
            filtered = [v for v in filtered if not v.get('likely_false_positive')]
        
        return filtered

    def _get_vulnerability_breakdown(self, vulnerabilities: List[Any]) -> Dict[str, int]:
        """Get vulnerability count breakdown by severity."""
        breakdown = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown').lower()
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown

    def _format_vulnerabilities_for_export(self, vulnerabilities: List[Any], 
                                         include_raw_data: bool) -> List[Dict[str, Any]]:
        """Format vulnerabilities for export."""
        formatted = []
        
        for vuln in vulnerabilities:
            formatted_vuln = {
                'id': vuln.get('id'),
                'name': vuln.get('vulnerability_name'),
                'type': vuln.get('vulnerability_type'),
                'severity': vuln.get('severity'),
                'cvss_score': vuln.get('cvss_score'),
                'affected_url': vuln.get('affected_url'),
                'description': vuln.get('impact_description'),
                'verified': vuln.get('manually_verified'),
                'exploitable': vuln.get('is_exploitable'),
                'discovered_at': vuln.get('discovered_at')
            }
            
            if include_raw_data:
                formatted_vuln.update({
                    'payload': vuln.get('payload_used'),
                    'request_data': vuln.get('request_data'),
                    'response_data': vuln.get('response_data'),
                    'tool_output': vuln.get('raw_output')
                })
            
            formatted.append(formatted_vuln)
        
        return formatted

    def _serialize_for_json(self, data: Any) -> Any:
        """Recursively serialize data for JSON output."""
        if isinstance(data, datetime):
            return data.isoformat()
        elif isinstance(data, dict):
            return {k: self._serialize_for_json(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._serialize_for_json(item) for item in data]
        else:
            return data

    def _get_default_html_template(self) -> str:
        """Get default HTML template if specific template not found."""
        return """
<!DOCTYPE html>
<html>
<head>
    <title>{{ report_metadata.title }}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .header { border-bottom: 2px solid #333; padding-bottom: 20px; }
        .section { margin: 30px 0; }
        .vulnerability { margin: 20px 0; padding: 15px; border-left: 4px solid #ccc; }
        .critical { border-left-color: #d32f2f; }
        .high { border-left-color: #f57c00; }
        .medium { border-left-color: #fbc02d; }
        .low { border-left-color: #388e3c; }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ report_metadata.title }}</h1>
        <p>Generated: {{ report_metadata.generated_at }}</p>
    </div>
    
    <div class="section">
        <h2>Executive Summary</h2>
        <p>{{ executive_summary }}</p>
    </div>
    
    <div class="section">
        <h2>Vulnerability Summary</h2>
        <ul>
            <li>Critical: {{ statistics.critical }}</li>
            <li>High: {{ statistics.high }}</li>
            <li>Medium: {{ statistics.medium }}</li>
            <li>Low: {{ statistics.low }}</li>
        </ul>
    </div>
    
    <div class="section">
        <h2>Detailed Findings</h2>
        {% for vuln in vulnerabilities %}
        <div class="vulnerability {{ vuln.severity }}">
            <h3>{{ vuln.vulnerability_name }}</h3>
            <p><strong>Severity:</strong> {{ vuln.severity }}</p>
            <p><strong>URL:</strong> {{ vuln.affected_url }}</p>
            <p>{{ vuln.impact_description }}</p>
        </div>
        {% endfor %}
    </div>
</body>
</html>
        """

    async def _get_template_info(self, template_path: Path) -> Dict[str, Any]:
        """Extract information from template file."""
        return {
            'template_name': template_path.stem,
            'display_name': template_path.stem.replace('_', ' ').title(),
            'description': f'Custom template: {template_path.stem}',
            'file_path': str(template_path),
            'supported_formats': ['html', 'pdf'],
            'is_built_in': False
        }

    # Placeholder methods for database operations
    async def _get_report(self, report_id: str) -> Any:
        """Mock report retrieval."""
        class MockReport:
            def __init__(self):
                self.id = report_id
                self.scan_session_id = "mock-session-id"
                self.report_name = "Security Assessment Report"
                self.report_type = "technical"
                self.generated_at = None
                self.pdf_file_path = None
                self.html_file_path = None
                self.json_file_path = None
        
        return MockReport()

    async def _get_scan_session(self, session_id: str) -> Any:
        """Mock scan session retrieval."""
        class MockScanSession:
            def __init__(self):
                self.id = session_id
                self.target_name = "example.com"
                self.duration_seconds = 3600
                self.methodology_phases = ["passive_recon", "active_recon"]
        
        return MockScanSession()

    async def _get_vulnerabilities(self, session_id: str) -> List[Any]:
        """Mock vulnerabilities retrieval."""
        return [
            {
                'id': 'vuln-1',
                'vulnerability_name': 'SQL Injection',
                'vulnerability_type': 'sql_injection',
                'severity': 'high',
                'cvss_score': 8.1,
                'affected_url': 'https://example.com/login',
                'impact_description': 'Allows unauthorized database access',
                'manually_verified': True,
                'is_exploitable': True,
                'discovered_at': datetime.utcnow()
            }
        ]

    # Export helper methods
    async def _export_vulnerabilities_csv(self, vulnerabilities: List[Any], file_path: Path) -> None:
        """Export vulnerabilities to CSV format."""
        import csv
        
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = ['name', 'type', 'severity', 'cvss_score', 'url', 'verified', 'exploitable']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            for vuln in vulnerabilities:
                writer.writerow({
                    'name': vuln.vulnerability_name,
                    'type': vuln.vulnerability_type,
                    'severity': vuln.severity,
                    'cvss_score': vuln.cvss_score,
                    'url': vuln.affected_url,
                    'verified': vuln.manually_verified,
                    'exploitable': vuln.is_exploitable
                })

    async def _export_vulnerabilities_json(self, vulnerabilities: List[Any], file_path: Path) -> None:
        """Export vulnerabilities to JSON format."""
        data = [
            {
                'name': vuln.vulnerability_name,
                'type': vuln.vulnerability_type,
                'severity': vuln.severity.value,
                'cvss_score': vuln.cvss_score,
                'url': vuln.affected_url,
                'description': vuln.impact_description,
                'verified': vuln.manually_verified,
                'exploitable': vuln.is_exploitable,
                'discovered_at': vuln.discovered_at.isoformat() if vuln.discovered_at else None
            }
            for vuln in vulnerabilities
        ]
        
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    async def _export_vulnerabilities_xml(self, vulnerabilities: List[Any], file_path: Path) -> None:
        """Export vulnerabilities to XML format."""
        import xml.etree.ElementTree as ET
        
        root = ET.Element('vulnerabilities')
        
        for vuln in vulnerabilities:
            vuln_elem = ET.SubElement(root, 'vulnerability')
            ET.SubElement(vuln_elem, 'name').text = vuln.vulnerability_name
            ET.SubElement(vuln_elem, 'type').text = vuln.vulnerability_type
            ET.SubElement(vuln_elem, 'severity').text = vuln.severity.value
            ET.SubElement(vuln_elem, 'cvss_score').text = str(vuln.cvss_score)
            ET.SubElement(vuln_elem, 'url').text = vuln.affected_url
            ET.SubElement(vuln_elem, 'verified').text = str(vuln.manually_verified)
            ET.SubElement(vuln_elem, 'exploitable').text = str(vuln.is_exploitable)
        
        tree = ET.ElementTree(root)
        tree.write(file_path, encoding='utf-8', xml_declaration=True)

    async def _export_vulnerabilities_pdf(self, vulnerabilities: List[Any], file_path: Path) -> None:
        """Export vulnerabilities to PDF format."""
        # Create simple PDF with vulnerability list
        doc = SimpleDocTemplate(str(file_path), pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        story.append(Paragraph("Vulnerability Export", styles['Title']))
        story.append(Spacer(1, 12))
        
        for vuln in vulnerabilities:
            story.append(Paragraph(f"<b>{vuln.vulnerability_name}</b>", styles['Heading2']))
            story.append(Paragraph(f"Severity: {vuln.severity.value}", styles['Normal']))
            story.append(Paragraph(f"URL: {vuln.affected_url}", styles['Normal']))
            story.append(Spacer(1, 6))
        
        doc.build(story)