"""
Markdown Generator
backend/tools/reporting/markdown_generator.py

Generates Markdown format reports with GitHub-flavored markdown.
"""

import os
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path
from datetime import datetime
from .template_manager import TemplateManager

logger = logging.getLogger(__name__)

class MarkdownGenerator:
    """
    Generates Markdown format security reports
    """

    def __init__(self):
        self.template_manager = TemplateManager()

    def generate_report(self, report_data: Dict[str, Any], metadata: Any, output_directory: Path) -> str:
        """
        Generate comprehensive Markdown report

        Args:
            report_data: Report data dictionary
            metadata: Report metadata
            output_directory: Output directory path

        Returns:
            Path to generated Markdown file
        """
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"security_report_{metadata.target_domain}_{timestamp}.md"
        filepath = output_directory / "markdown" / filename

        try:
            # Generate report content
            content = self.build_markdown_content(report_data, metadata)

            # Write to file
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)

            logger.info(f"Generated Markdown report: {filepath}")
            return str(filepath)

        except Exception as e:
            logger.error(f"Error generating Markdown report: {str(e)}")
            raise

    def build_markdown_content(self, report_data: Dict[str, Any], metadata: Any) -> str:
        """Build the complete Markdown content"""
        content_parts = [
            self.generate_header(metadata),
            self.generate_table_of_contents(report_data),
            self.generate_executive_summary(report_data['executive_summary']),
            self.generate_report_metadata(metadata),
            self.generate_detailed_findings(report_data['findings']),
            self.generate_statistics(report_data['statistics']),
            self.generate_appendices(report_data.get('appendices', {})),
            self.generate_footer(metadata)
        ]

        return '\n\n'.join(content_parts)

    def generate_header(self, metadata: Any) -> str:
        """Generate report header"""
        return f"""# 🛡️ Security Assessment Report

**Target:** `{metadata.target_domain}`
**Generated:** {datetime.now().strftime('%B %d, %Y at %H:%M:%S UTC')}
**Report ID:** `{metadata.report_id}`
**Classification:** {metadata.classification.upper()}

---"""

    def generate_table_of_contents(self, report_data: Dict[str, Any]) -> str:
        """Generate table of contents"""
        toc = """## 📋 Table of Contents

- [Executive Summary](#-executive-summary)
- [Report Information](#-report-information)
- [Detailed Findings](#-detailed-findings)"""

        # Add severity sections if they have findings
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if report_data['findings'].get(severity):
                count = len(report_data['findings'][severity])
                emoji = self.get_severity_emoji(severity)
                toc += f"\n  - [{emoji} {severity.title()} ({count})](#-{severity}-severity)"

        toc += """
- [Assessment Statistics](#-assessment-statistics)
- [Appendices](#-appendices)
  - [Testing Methodology](#testing-methodology)
  - [Tools Used](#tools-used)
  - [References](#references)

---"""
        return toc

    def generate_executive_summary(self, summary: Dict[str, Any]) -> str:
        """Generate executive summary section"""
        content = f"""## 📊 Executive Summary

### Overview
This security assessment was conducted on **{summary['target']}** during the period {summary['assessment_period']}. The assessment identified **{summary['total_findings']}** security findings with an overall risk score of **{summary['overall_risk_score']}%**.

### Risk Assessment

| Severity | Count | Impact |
|----------|-------|--------|"""

        severity_descriptions = {
            'critical': 'Immediate action required - Critical business impact',
            'high': 'Urgent remediation needed - High business impact',
            'medium': 'Should be addressed - Moderate business impact',
            'low': 'Low priority - Minimal business impact',
            'info': 'Informational - No immediate impact'
        }

        for severity, count in summary['severity_breakdown'].items():
            emoji = self.get_severity_emoji(severity)
            description = severity_descriptions.get(severity, 'Unknown impact')
            content += f"\n| {emoji} {severity.title()} | **{count}** | {description} |"

        if summary.get('key_findings'):
            content += f"\n\n### 🎯 Key Findings\n"
            for i, finding in enumerate(summary['key_findings'], 1):
                emoji = self.get_severity_emoji(finding['severity'])
                content += f"{i}. **{finding['title']}** ({emoji} {finding['severity'].title()})\n"

        if summary.get('recommendations'):
            content += f"\n\n### 🚨 Immediate Actions Required\n"
            for i, rec in enumerate(summary['recommendations'][:5], 1):
                content += f"{i}. {rec}\n"

        return content

    def generate_report_metadata(self, metadata: Any) -> str:
        """Generate report metadata section"""
        return f"""## 📋 Report Information

| Field | Value |
|-------|-------|
| **Report ID** | `{metadata.report_id}` |
| **Target Domain** | `{metadata.target_domain}` |
| **Assessment Type** | {metadata.assessment_type.replace('_', ' ').title()} |
| **Start Date** | {metadata.start_date} |
| **End Date** | {metadata.end_date} |
| **Tester** | {metadata.tester_name} ({metadata.tester_email}) |
| **Report Version** | {metadata.report_version} |
| **Classification** | {metadata.classification.upper()} |"""

    def generate_detailed_findings(self, findings: Dict[str, List]) -> str:
        """Generate detailed findings section"""
        content = "## 🔍 Detailed Findings\n"

        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if not findings.get(severity):
                continue

            emoji = self.get_severity_emoji(severity)
            count = len(findings[severity])
            content += f"\n### {emoji} {severity.title()} Severity ({count})\n"

            for finding in findings[severity]:
                content += self.format_finding(finding, severity)

        return content

    def format_finding(self, finding: Dict[str, Any], severity: str) -> str:
        """Format individual finding"""
        content = f"\n#### {finding['title']}\n"

        # Metadata table
        content += f"""
| Property | Value |
|----------|-------|
| **Type** | {finding['vulnerability_type'].replace('_', ' ').title()} |
| **Severity** | {self.get_severity_emoji(severity)} {finding['severity'].title()} |"""

        if finding.get('cvss_score'):
            content += f"\n| **CVSS Score** | {finding['cvss_score']} |"

        if finding.get('cwe_id'):
            content += f"\n| **CWE** | [{finding['cwe_id']}](https://cwe.mitre.org/data/definitions/{finding['cwe_id'].replace('CWE-', '')}.html) |"

        # Description
        content += f"\n\n**📝 Description:**\n{finding['description']}\n"

        # Impact
        content += f"\n**💥 Impact:**\n{finding['impact']}\n"

        # Affected URLs
        if finding.get('affected_urls'):
            content += f"\n**🎯 Affected URLs:**\n"
            for url in finding['affected_urls']:
                content += f"- `{url}`\n"

        # Proof of Concept
        if finding.get('proof_of_concept'):
            content += f"\n**🔬 Proof of Concept:**\n"
            content += f"```\n{finding['proof_of_concept']}\n```\n"

        # Remediation
        content += f"\n**🔧 Remediation:**\n{finding['remediation']}\n"

        # References
        if finding.get('references'):
            content += f"\n**📚 References:**\n"
            for ref in finding['references']:
                content += f"- [{ref}]({ref})\n"

        content += "\n---\n"
        return content

    def generate_statistics(self, statistics: Dict[str, Any]) -> str:
        """Generate statistics section"""
        content = f"""## 📈 Assessment Statistics

### Overview
- **Total Findings:** {statistics['total_findings']}
- **Affected URLs:** {statistics['affected_urls_count']}
- **Findings with PoC:** {statistics['findings_with_poc']}"""

        if statistics.get('average_cvss_score'):
            content += f"\n- **Average CVSS Score:** {statistics['average_cvss_score']}"

        # Severity breakdown chart (using text)
        content += "\n\n### Severity Distribution\n"
        content += "```\n"
        max_count = max(statistics['severity_breakdown'].values()) if statistics['severity_breakdown'] else 1

        for severity, count in statistics['severity_breakdown'].items():
            bar_length = int((count / max_count) * 20) if max_count > 0 else 0
            bar = "█" * bar_length + "░" * (20 - bar_length)
            emoji = self.get_severity_emoji(severity)
            content += f"{emoji} {severity.title():8} │{bar}│ {count}\n"

        content += "```\n"

        # Vulnerability types
        if statistics.get('vulnerability_types'):
            content += "\n### Vulnerability Types\n\n"
            content += "| Vulnerability Type | Count |\n"
            content += "|-------------------|-------|\n"

            # Sort by count descending
            sorted_vulns = sorted(
                statistics['vulnerability_types'].items(),
                key=lambda x: x[1],
                reverse=True
            )

            for vuln_type, count in sorted_vulns:
                clean_name = vuln_type.replace('_', ' ').title()
                content += f"| {clean_name} | {count} |\n"

        return content

    def generate_appendices(self, appendices: Dict[str, Any]) -> str:
        """Generate appendices section"""
        content = "## 📚 Appendices\n"

        if appendices.get('methodology'):
            content += "\n### Testing Methodology\n"
            for i, method in enumerate(appendices['methodology'], 1):
                content += f"{i}. {method}\n"

        if appendices.get('tools_used'):
            content += "\n### Tools Used\n"
            for tool in appendices['tools_used']:
                content += f"- {tool}\n"

        if appendices.get('references'):
            content += "\n### References\n"
            for ref in appendices['references']:
                content += f"- [{ref['title']}]({ref['url']})\n"

        if appendices.get('glossary'):
            content += "\n### Security Glossary\n"
            for term, definition in appendices['glossary'].items():
                content += f"- **{term}:** {definition}\n"

        return content

    def generate_footer(self, metadata: Any) -> str:
        """Generate report footer"""
        return f"""---

## 📄 Report Information

*This report was generated automatically by the Bug Hunt Framework on {datetime.now().strftime('%B %d, %Y at %H:%M:%S UTC')}*

**Classification:** {metadata.classification.upper()}
**Report Version:** {metadata.report_version}
**Format:** Markdown (GitHub Flavored)

> ⚠️ **Important:** This report contains sensitive security information. Handle according to your organization's data classification policies.

---

*© 2024 Bug Hunt Framework - Automated Security Assessment Platform*"""

    def get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level"""
        emoji_map = {
            'critical': '🚨',
            'high': '🔴',
            'medium': '🟡',
            'low': '🟢',
            'info': '🔵'
        }
        return emoji_map.get(severity.lower(), '⚪')

    def generate_summary_report(self, report_data: Dict[str, Any], metadata: Any, output_directory: Path) -> str:
        """Generate a concise summary report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"security_summary_{metadata.target_domain}_{timestamp}.md"
        filepath = output_directory / "markdown" / filename

        try:
            summary = report_data['executive_summary']

            content = f"""# 📊 Security Assessment Summary

**Target:** {summary['target']}
**Period:** {summary['assessment_period']}
**Risk Score:** {summary['overall_risk_score']}%

## Quick Stats
- **Total Findings:** {summary['total_findings']}
- **Critical:** {summary['severity_breakdown'].get('critical', 0)}
- **High:** {summary['severity_breakdown'].get('high', 0)}
- **Medium:** {summary['severity_breakdown'].get('medium', 0)}

## Top Issues
"""

            for i, finding in enumerate(summary.get('key_findings', [])[:3], 1):
                emoji = self.get_severity_emoji(finding['severity'])
                content += f"{i}. {emoji} **{finding['title']}** ({finding['severity'].title()})\n"

            content += f"\n## Next Steps\n"
            for i, rec in enumerate(summary.get('recommendations', [])[:3], 1):
                content += f"{i}. {rec}\n"

            content += f"\n*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*"

            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)

            logger.info(f"Generated summary report: {filepath}")
            return str(filepath)

        except Exception as e:
            logger.error(f"Error generating summary report: {str(e)}")
            raise

# Example usage
def main():
    """Example usage of the MarkdownGenerator"""
    generator = MarkdownGenerator()

    # Sample data
    sample_data = {
        'executive_summary': {
            'target': 'example.com',
            'assessment_period': '2024-01-01 to 2024-01-07',
            'total_findings': 5,
            'overall_risk_score': 75.5,
            'severity_breakdown': {'critical': 1, 'high': 2, 'medium': 1, 'low': 1, 'info': 0},
            'key_findings': [
                {'title': 'SQL Injection', 'severity': 'critical', 'type': 'sql_injection'}
            ],
            'recommendations': ['Fix SQL injection', 'Implement WAF']
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
                    'remediation': 'Use parameterized queries',
                    'references': ['https://owasp.org/sql-injection']
                }
            ],
            'high': [], 'medium': [], 'low': [], 'info': []
        },
        'statistics': {
            'total_findings': 1,
            'affected_urls_count': 1,
            'findings_with_poc': 1,
            'severity_breakdown': {'critical': 1, 'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'vulnerability_types': {'sql_injection': 1}
        },
        'appendices': {
            'methodology': ['Automated scanning', 'Manual testing'],
            'tools_used': ['Nuclei', 'SQLMap'],
            'references': [{'title': 'OWASP', 'url': 'https://owasp.org'}]
        }
    }

    # Mock metadata
    metadata = type('Metadata', (), {
        'target_domain': 'example.com',
        'report_id': 'TEST-001',
        'classification': 'confidential',
        'assessment_type': 'web_app',
        'start_date': '2024-01-01',
        'end_date': '2024-01-07',
        'tester_name': 'Test User',
        'tester_email': 'test@example.com',
        'report_version': '1.0'
    })()

    # Generate report
    output_dir = Path('./reports')
    output_dir.mkdir(exist_ok=True)
    (output_dir / 'markdown').mkdir(exist_ok=True)

    report_path = generator.generate_report(sample_data, metadata, output_dir)
    print(f"Generated report: {report_path}")

if __name__ == "__main__":
    main()