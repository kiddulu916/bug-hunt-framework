"""
Report Generator
backend/tools/reporting/report_generator.py

Main report generation engine for bug bounty findings.
"""

import json
import logging
import os
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from pathlib import Path
import uuid

from .template_manager import TemplateManager
from .evidence_collector import EvidenceCollector
from .markdown_generator import MarkdownGenerator
from .pdf_generator import PDFGenerator

logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityFinding:
    """Represents a vulnerability finding for reporting"""
    id: str
    title: str
    severity: str  # critical, high, medium, low, info
    vulnerability_type: str
    description: str
    impact: str
    affected_urls: List[str]
    proof_of_concept: str
    remediation: str
    references: List[str]
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    discovery_date: Optional[datetime] = None
    evidence_files: List[str] = None

@dataclass
class ReportMetadata:
    """Report metadata"""
    report_id: str
    target_domain: str
    assessment_type: str  # web_app, api, infrastructure
    start_date: datetime
    end_date: datetime
    tester_name: str
    tester_email: str
    report_version: str = "1.0"
    classification: str = "confidential"

class ReportGenerator:
    """
    Main report generation engine
    """

    def __init__(self, output_directory: str = "reports"):
        self.output_directory = Path(output_directory)
        self.output_directory.mkdir(exist_ok=True)

        # Initialize sub-components
        self.template_manager = TemplateManager()
        self.evidence_collector = EvidenceCollector()
        self.markdown_generator = MarkdownGenerator()
        self.pdf_generator = PDFGenerator()

        # Create subdirectories
        (self.output_directory / "html").mkdir(exist_ok=True)
        (self.output_directory / "pdf").mkdir(exist_ok=True)
        (self.output_directory / "markdown").mkdir(exist_ok=True)
        (self.output_directory / "json").mkdir(exist_ok=True)

    def generate_comprehensive_report(
        self,
        findings: List[VulnerabilityFinding],
        metadata: ReportMetadata,
        formats: List[str] = None
    ) -> Dict[str, str]:
        """
        Generate comprehensive security assessment report

        Args:
            findings: List of vulnerability findings
            metadata: Report metadata
            formats: Output formats ['html', 'pdf', 'markdown', 'json']

        Returns:
            Dictionary mapping format to file path
        """
        if formats is None:
            formats = ['html', 'markdown', 'json']

        logger.info(f"Generating report for {len(findings)} findings in formats: {formats}")

        # Organize findings by severity
        organized_findings = self.organize_findings_by_severity(findings)

        # Generate report content
        report_data = {
            'metadata': asdict(metadata),
            'executive_summary': self.generate_executive_summary(findings, metadata),
            'findings': organized_findings,
            'statistics': self.calculate_statistics(findings),
            'appendices': self.generate_appendices(findings)
        }

        # Collect evidence
        evidence_paths = self.evidence_collector.collect_all_evidence(findings)
        report_data['evidence'] = evidence_paths

        generated_files = {}

        # Generate reports in requested formats
        for format_type in formats:
            try:
                if format_type.lower() == 'json':
                    file_path = self.generate_json_report(report_data, metadata)
                elif format_type.lower() == 'markdown':
                    file_path = self.generate_markdown_report(report_data, metadata)
                elif format_type.lower() == 'html':
                    file_path = self.generate_html_report(report_data, metadata)
                elif format_type.lower() == 'pdf':
                    file_path = self.generate_pdf_report(report_data, metadata)
                else:
                    logger.warning(f"Unsupported format: {format_type}")
                    continue

                generated_files[format_type] = file_path
                logger.info(f"Generated {format_type} report: {file_path}")

            except Exception as e:
                logger.error(f"Error generating {format_type} report: {str(e)}")

        return generated_files

    def organize_findings_by_severity(self, findings: List[VulnerabilityFinding]) -> Dict[str, List[Dict]]:
        """Organize findings by severity level"""
        severity_order = ['critical', 'high', 'medium', 'low', 'info']
        organized = {severity: [] for severity in severity_order}

        for finding in findings:
            severity = finding.severity.lower()
            if severity in organized:
                organized[severity].append(asdict(finding))

        return organized

    def generate_executive_summary(
        self,
        findings: List[VulnerabilityFinding],
        metadata: ReportMetadata
    ) -> Dict[str, Any]:
        """Generate executive summary"""
        total_findings = len(findings)
        severity_counts = self.count_findings_by_severity(findings)

        # Calculate risk score
        risk_score = self.calculate_overall_risk_score(findings)

        # Key findings (top 3 by severity)
        key_findings = sorted(
            findings,
            key=lambda x: {'critical': 5, 'high': 4, 'medium': 3, 'low': 2, 'info': 1}.get(x.severity.lower(), 0),
            reverse=True
        )[:3]

        return {
            'target': metadata.target_domain,
            'assessment_period': f"{metadata.start_date.strftime('%Y-%m-%d')} to {metadata.end_date.strftime('%Y-%m-%d')}",
            'total_findings': total_findings,
            'severity_breakdown': severity_counts,
            'overall_risk_score': risk_score,
            'key_findings': [
                {
                    'title': f.title,
                    'severity': f.severity,
                    'type': f.vulnerability_type
                }
                for f in key_findings
            ],
            'recommendations': self.generate_high_level_recommendations(findings)
        }

    def count_findings_by_severity(self, findings: List[VulnerabilityFinding]) -> Dict[str, int]:
        """Count findings by severity"""
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}

        for finding in findings:
            severity = finding.severity.lower()
            if severity in counts:
                counts[severity] += 1

        return counts

    def calculate_overall_risk_score(self, findings: List[VulnerabilityFinding]) -> float:
        """Calculate overall risk score"""
        severity_weights = {'critical': 10, 'high': 7, 'medium': 4, 'low': 2, 'info': 1}
        total_score = 0
        max_possible_score = len(findings) * 10  # If all were critical

        for finding in findings:
            severity = finding.severity.lower()
            total_score += severity_weights.get(severity, 1)

        if max_possible_score == 0:
            return 0.0

        return round((total_score / max_possible_score) * 100, 1)

    def generate_high_level_recommendations(self, findings: List[VulnerabilityFinding]) -> List[str]:
        """Generate high-level recommendations"""
        recommendations = []

        # Count vulnerability types
        vuln_types = {}
        for finding in findings:
            vuln_type = finding.vulnerability_type
            vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1

        # Generate recommendations based on most common vulnerabilities
        common_vulns = sorted(vuln_types.items(), key=lambda x: x[1], reverse=True)[:3]

        for vuln_type, count in common_vulns:
            if vuln_type.lower() in ['sql_injection', 'sqli']:
                recommendations.append("Implement parameterized queries and input validation to prevent SQL injection attacks")
            elif vuln_type.lower() in ['xss', 'cross_site_scripting']:
                recommendations.append("Implement output encoding and Content Security Policy (CSP) to prevent XSS attacks")
            elif vuln_type.lower() in ['csrf', 'cross_site_request_forgery']:
                recommendations.append("Implement CSRF tokens and proper authentication checks")
            elif vuln_type.lower() in ['broken_authentication', 'auth']:
                recommendations.append("Strengthen authentication mechanisms and session management")

        # Generic recommendations
        recommendations.extend([
            "Conduct regular security assessments and penetration testing",
            "Implement a Web Application Firewall (WAF)",
            "Keep all software components updated and patched",
            "Provide security awareness training for development teams"
        ])

        return recommendations[:5]  # Limit to top 5

    def calculate_statistics(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Calculate report statistics"""
        stats = {
            'total_findings': len(findings),
            'severity_breakdown': self.count_findings_by_severity(findings),
            'vulnerability_types': {},
            'affected_urls_count': 0,
            'findings_with_poc': 0,
            'cvss_scores': []
        }

        # Count vulnerability types
        for finding in findings:
            vuln_type = finding.vulnerability_type
            stats['vulnerability_types'][vuln_type] = stats['vulnerability_types'].get(vuln_type, 0) + 1

            # Count affected URLs
            stats['affected_urls_count'] += len(finding.affected_urls)

            # Count findings with PoC
            if finding.proof_of_concept:
                stats['findings_with_poc'] += 1

            # Collect CVSS scores
            if finding.cvss_score:
                stats['cvss_scores'].append(finding.cvss_score)

        # Calculate average CVSS score
        if stats['cvss_scores']:
            stats['average_cvss_score'] = round(sum(stats['cvss_scores']) / len(stats['cvss_scores']), 1)
        else:
            stats['average_cvss_score'] = 0.0

        return stats

    def generate_appendices(self, findings: List[VulnerabilityFinding]) -> Dict[str, Any]:
        """Generate appendices for the report"""
        return {
            'methodology': self.get_testing_methodology(),
            'tools_used': self.get_tools_used(),
            'references': self.get_security_references(),
            'glossary': self.get_security_glossary()
        }

    def get_testing_methodology(self) -> List[str]:
        """Get testing methodology description"""
        return [
            "Automated vulnerability scanning using industry-standard tools",
            "Manual testing and verification of identified vulnerabilities",
            "Code review and configuration analysis",
            "Business logic testing and authentication bypass attempts",
            "Input validation testing across all application entry points"
        ]

    def get_tools_used(self) -> List[str]:
        """Get list of tools used in assessment"""
        return [
            "Nuclei - Vulnerability scanner",
            "Nmap - Network discovery and security auditing",
            "SQLMap - SQL injection testing",
            "Burp Suite - Web application security testing",
            "OWASP ZAP - Web application security scanner",
            "Custom Python scripts for specific vulnerability testing"
        ]

    def get_security_references(self) -> List[Dict[str, str]]:
        """Get security references"""
        return [
            {"title": "OWASP Top 10", "url": "https://owasp.org/www-project-top-ten/"},
            {"title": "NIST Cybersecurity Framework", "url": "https://www.nist.gov/cyberframework"},
            {"title": "CWE - Common Weakness Enumeration", "url": "https://cwe.mitre.org/"},
            {"title": "CVE - Common Vulnerabilities and Exposures", "url": "https://cve.mitre.org/"},
            {"title": "CVSS - Common Vulnerability Scoring System", "url": "https://www.first.org/cvss/"}
        ]

    def get_security_glossary(self) -> Dict[str, str]:
        """Get security glossary"""
        return {
            "SQL Injection": "A code injection technique used to attack data-driven applications",
            "XSS": "Cross-Site Scripting - A type of injection attack where malicious scripts are injected into websites",
            "CSRF": "Cross-Site Request Forgery - An attack that forces authenticated users to submit requests",
            "CVSS": "Common Vulnerability Scoring System - A method used to supply a qualitative measure of severity",
            "CWE": "Common Weakness Enumeration - A list of software and hardware weakness types",
            "PoC": "Proof of Concept - A demonstration that shows a vulnerability can be exploited",
            "WAF": "Web Application Firewall - A security solution that monitors HTTP traffic"
        }

    def generate_json_report(self, report_data: Dict[str, Any], metadata: ReportMetadata) -> str:
        """Generate JSON report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"security_report_{metadata.target_domain}_{timestamp}.json"
        filepath = self.output_directory / "json" / filename

        with open(filepath, 'w') as f:
            json.dump(report_data, f, indent=2, default=str)

        return str(filepath)

    def generate_markdown_report(self, report_data: Dict[str, Any], metadata: ReportMetadata) -> str:
        """Generate Markdown report"""
        return self.markdown_generator.generate_report(report_data, metadata, self.output_directory)

    def generate_html_report(self, report_data: Dict[str, Any], metadata: ReportMetadata) -> str:
        """Generate HTML report"""
        template = self.template_manager.get_html_template('comprehensive_report')

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"security_report_{metadata.target_domain}_{timestamp}.html"
        filepath = self.output_directory / "html" / filename

        # Render template with data
        html_content = template.render(
            metadata=report_data['metadata'],
            executive_summary=report_data['executive_summary'],
            findings=report_data['findings'],
            statistics=report_data['statistics'],
            appendices=report_data['appendices'],
            generated_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        )

        with open(filepath, 'w') as f:
            f.write(html_content)

        return str(filepath)

    def generate_pdf_report(self, report_data: Dict[str, Any], metadata: ReportMetadata) -> str:
        """Generate PDF report"""
        return self.pdf_generator.generate_report(report_data, metadata, self.output_directory)

# Example usage
def main():
    """Example usage of the ReportGenerator"""
    # Sample vulnerability findings
    findings = [
        VulnerabilityFinding(
            id="vuln_001",
            title="SQL Injection in Login Form",
            severity="high",
            vulnerability_type="sql_injection",
            description="The login form is vulnerable to SQL injection attacks",
            impact="An attacker could bypass authentication and access sensitive data",
            affected_urls=["https://example.com/login"],
            proof_of_concept="' OR '1'='1' --",
            remediation="Use parameterized queries",
            references=["https://owasp.org/www-community/attacks/SQL_Injection"],
            cvss_score=8.1,
            cwe_id="CWE-89",
            discovery_date=datetime.now()
        ),
        VulnerabilityFinding(
            id="vuln_002",
            title="Reflected XSS in Search Function",
            severity="medium",
            vulnerability_type="xss",
            description="The search function reflects user input without proper encoding",
            impact="An attacker could execute arbitrary JavaScript in victim's browser",
            affected_urls=["https://example.com/search"],
            proof_of_concept="<script>alert('XSS')</script>",
            remediation="Implement output encoding",
            references=["https://owasp.org/www-community/attacks/xss/"],
            cvss_score=6.1,
            cwe_id="CWE-79",
            discovery_date=datetime.now()
        )
    ]

    # Report metadata
    metadata = ReportMetadata(
        report_id=str(uuid.uuid4()),
        target_domain="example.com",
        assessment_type="web_app",
        start_date=datetime.now() - timedelta(days=7),
        end_date=datetime.now(),
        tester_name="Security Tester",
        tester_email="tester@example.com"
    )

    # Generate report
    generator = ReportGenerator("./reports")
    generated_files = generator.generate_comprehensive_report(
        findings=findings,
        metadata=metadata,
        formats=['json', 'markdown', 'html']
    )

    for format_type, file_path in generated_files.items():
        print(f"{format_type.upper()} report: {file_path}")

if __name__ == "__main__":
    main()