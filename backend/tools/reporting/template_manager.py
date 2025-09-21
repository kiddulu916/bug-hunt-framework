"""
Template Manager
backend/tools/reporting/template_manager.py

Manages report templates for different output formats.
"""

import os
from typing import Dict, Any, Optional
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, Template

class TemplateManager:
    """
    Manages report templates using Jinja2
    """

    def __init__(self, templates_directory: str = None):
        if templates_directory is None:
            self.templates_directory = Path(__file__).parent / "templates"
        else:
            self.templates_directory = Path(templates_directory)

        self.templates_directory.mkdir(exist_ok=True)

        # Initialize Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(str(self.templates_directory)),
            autoescape=True
        )

        # Create default templates if they don't exist
        self.create_default_templates()

    def create_default_templates(self):
        """Create default report templates"""
        self.create_html_template()
        self.create_markdown_template()
        self.create_executive_summary_template()

    def create_html_template(self):
        """Create default HTML template"""
        html_template = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment Report - {{ metadata.target_domain }}</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .header {
            text-align: center;
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }
        .header h1 {
            color: #2c3e50;
            margin: 0 0 10px 0;
            font-size: 2.5em;
        }
        .header .subtitle {
            color: #7f8c8d;
            font-size: 1.2em;
        }
        .section {
            margin-bottom: 40px;
        }
        .section h2 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
            margin-bottom: 20px;
        }
        .section h3 {
            color: #34495e;
            margin-top: 25px;
            margin-bottom: 15px;
        }
        .severity-critical { color: #e74c3c; font-weight: bold; }
        .severity-high { color: #e67e22; font-weight: bold; }
        .severity-medium { color: #f39c12; font-weight: bold; }
        .severity-low { color: #27ae60; font-weight: bold; }
        .severity-info { color: #3498db; font-weight: bold; }
        .finding {
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin: 20px 0;
            border-radius: 0 5px 5px 0;
        }
        .finding h4 {
            margin-top: 0;
            color: #2c3e50;
        }
        .finding-meta {
            background-color: #ecf0f1;
            padding: 10px;
            border-radius: 5px;
            margin: 10px 0;
            font-size: 0.9em;
        }
        .poc-code {
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            font-family: 'Courier New', monospace;
            overflow-x: auto;
            margin: 10px 0;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }
        .stat-card {
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            border: 1px solid #dee2e6;
        }
        .stat-number {
            font-size: 2em;
            font-weight: bold;
            color: #2c3e50;
        }
        .stat-label {
            color: #7f8c8d;
            margin-top: 5px;
        }
        .executive-summary {
            background-color: #f8f9fa;
            padding: 25px;
            border-radius: 8px;
            border-left: 5px solid #3498db;
        }
        .recommendations {
            background-color: #d5f4e6;
            padding: 20px;
            border-radius: 8px;
            border-left: 5px solid #27ae60;
        }
        .recommendations ul {
            margin: 0;
            padding-left: 20px;
        }
        .metadata-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .metadata-table th,
        .metadata-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        .metadata-table th {
            background-color: #f8f9fa;
            font-weight: bold;
            color: #2c3e50;
        }
        .footer {
            text-align: center;
            margin-top: 50px;
            padding-top: 20px;
            border-top: 1px solid #dee2e6;
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>Security Assessment Report</h1>
            <div class="subtitle">{{ metadata.target_domain }} | {{ generated_date }}</div>
        </div>

        <!-- Executive Summary -->
        <div class="section">
            <h2>Executive Summary</h2>
            <div class="executive-summary">
                <p><strong>Target:</strong> {{ executive_summary.target }}</p>
                <p><strong>Assessment Period:</strong> {{ executive_summary.assessment_period }}</p>
                <p><strong>Total Findings:</strong> {{ executive_summary.total_findings }}</p>
                <p><strong>Overall Risk Score:</strong> {{ executive_summary.overall_risk_score }}%</p>

                <div class="stats-grid">
                    {% for severity, count in executive_summary.severity_breakdown.items() %}
                    <div class="stat-card">
                        <div class="stat-number severity-{{ severity }}">{{ count }}</div>
                        <div class="stat-label">{{ severity.title() }}</div>
                    </div>
                    {% endfor %}
                </div>

                {% if executive_summary.recommendations %}
                <div class="recommendations">
                    <h3>Key Recommendations</h3>
                    <ul>
                        {% for rec in executive_summary.recommendations[:5] %}
                        <li>{{ rec }}</li>
                        {% endfor %}
                    </ul>
                </div>
                {% endif %}
            </div>
        </div>

        <!-- Report Metadata -->
        <div class="section">
            <h2>Report Information</h2>
            <table class="metadata-table">
                <tr><th>Report ID</th><td>{{ metadata.report_id }}</td></tr>
                <tr><th>Target Domain</th><td>{{ metadata.target_domain }}</td></tr>
                <tr><th>Assessment Type</th><td>{{ metadata.assessment_type.replace('_', ' ').title() }}</td></tr>
                <tr><th>Start Date</th><td>{{ metadata.start_date }}</td></tr>
                <tr><th>End Date</th><td>{{ metadata.end_date }}</td></tr>
                <tr><th>Tester</th><td>{{ metadata.tester_name }} ({{ metadata.tester_email }})</td></tr>
                <tr><th>Report Version</th><td>{{ metadata.report_version }}</td></tr>
            </table>
        </div>

        <!-- Detailed Findings -->
        <div class="section">
            <h2>Detailed Findings</h2>

            {% for severity in ['critical', 'high', 'medium', 'low', 'info'] %}
                {% if findings[severity] %}
                <h3 class="severity-{{ severity }}">{{ severity.title() }} Severity ({{ findings[severity]|length }})</h3>

                {% for finding in findings[severity] %}
                <div class="finding">
                    <h4>{{ finding.title }}</h4>

                    <div class="finding-meta">
                        <strong>Type:</strong> {{ finding.vulnerability_type.replace('_', ' ').title() }} |
                        <strong>Severity:</strong> <span class="severity-{{ finding.severity }}">{{ finding.severity.title() }}</span>
                        {% if finding.cvss_score %}
                        | <strong>CVSS Score:</strong> {{ finding.cvss_score }}
                        {% endif %}
                        {% if finding.cwe_id %}
                        | <strong>CWE:</strong> {{ finding.cwe_id }}
                        {% endif %}
                    </div>

                    <h5>Description</h5>
                    <p>{{ finding.description }}</p>

                    <h5>Impact</h5>
                    <p>{{ finding.impact }}</p>

                    {% if finding.affected_urls %}
                    <h5>Affected URLs</h5>
                    <ul>
                        {% for url in finding.affected_urls %}
                        <li><code>{{ url }}</code></li>
                        {% endfor %}
                    </ul>
                    {% endif %}

                    {% if finding.proof_of_concept %}
                    <h5>Proof of Concept</h5>
                    <div class="poc-code">{{ finding.proof_of_concept }}</div>
                    {% endif %}

                    <h5>Remediation</h5>
                    <p>{{ finding.remediation }}</p>

                    {% if finding.references %}
                    <h5>References</h5>
                    <ul>
                        {% for ref in finding.references %}
                        <li><a href="{{ ref }}" target="_blank">{{ ref }}</a></li>
                        {% endfor %}
                    </ul>
                    {% endif %}
                </div>
                {% endfor %}
                {% endif %}
            {% endfor %}
        </div>

        <!-- Statistics -->
        <div class="section">
            <h2>Assessment Statistics</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-number">{{ statistics.total_findings }}</div>
                    <div class="stat-label">Total Findings</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ statistics.affected_urls_count }}</div>
                    <div class="stat-label">Affected URLs</div>
                </div>
                <div class="stat-card">
                    <div class="stat-number">{{ statistics.findings_with_poc }}</div>
                    <div class="stat-label">With PoC</div>
                </div>
                {% if statistics.average_cvss_score %}
                <div class="stat-card">
                    <div class="stat-number">{{ statistics.average_cvss_score }}</div>
                    <div class="stat-label">Avg CVSS Score</div>
                </div>
                {% endif %}
            </div>

            {% if statistics.vulnerability_types %}
            <h3>Vulnerability Types</h3>
            <table class="metadata-table">
                {% for vuln_type, count in statistics.vulnerability_types.items() %}
                <tr>
                    <td>{{ vuln_type.replace('_', ' ').title() }}</td>
                    <td>{{ count }}</td>
                </tr>
                {% endfor %}
            </table>
            {% endif %}
        </div>

        <!-- Appendices -->
        {% if appendices %}
        <div class="section">
            <h2>Appendices</h2>

            {% if appendices.methodology %}
            <h3>Testing Methodology</h3>
            <ul>
                {% for method in appendices.methodology %}
                <li>{{ method }}</li>
                {% endfor %}
            </ul>
            {% endif %}

            {% if appendices.tools_used %}
            <h3>Tools Used</h3>
            <ul>
                {% for tool in appendices.tools_used %}
                <li>{{ tool }}</li>
                {% endfor %}
            </ul>
            {% endif %}

            {% if appendices.references %}
            <h3>References</h3>
            <ul>
                {% for ref in appendices.references %}
                <li><a href="{{ ref.url }}" target="_blank">{{ ref.title }}</a></li>
                {% endfor %}
            </ul>
            {% endif %}
        </div>
        {% endif %}

        <!-- Footer -->
        <div class="footer">
            <p>This report was generated automatically by the Bug Hunt Framework on {{ generated_date }}</p>
            <p>Classification: {{ metadata.classification.title() }}</p>
        </div>
    </div>
</body>
</html>'''

        template_path = self.templates_directory / "comprehensive_report.html"
        with open(template_path, 'w') as f:
            f.write(html_template)

    def create_markdown_template(self):
        """Create default Markdown template"""
        markdown_template = '''# Security Assessment Report

**Target:** {{ metadata.target_domain }}
**Generated:** {{ generated_date }}
**Report ID:** {{ metadata.report_id }}

---

## Executive Summary

- **Target:** {{ executive_summary.target }}
- **Assessment Period:** {{ executive_summary.assessment_period }}
- **Total Findings:** {{ executive_summary.total_findings }}
- **Overall Risk Score:** {{ executive_summary.overall_risk_score }}%

### Severity Breakdown

{% for severity, count in executive_summary.severity_breakdown.items() %}
- **{{ severity.title() }}:** {{ count }}
{% endfor %}

### Key Recommendations

{% for rec in executive_summary.recommendations[:5] %}
- {{ rec }}
{% endfor %}

---

## Report Information

| Field | Value |
|-------|-------|
| Report ID | {{ metadata.report_id }} |
| Target Domain | {{ metadata.target_domain }} |
| Assessment Type | {{ metadata.assessment_type.replace('_', ' ').title() }} |
| Start Date | {{ metadata.start_date }} |
| End Date | {{ metadata.end_date }} |
| Tester | {{ metadata.tester_name }} ({{ metadata.tester_email }}) |
| Report Version | {{ metadata.report_version }} |

---

## Detailed Findings

{% for severity in ['critical', 'high', 'medium', 'low', 'info'] %}
{% if findings[severity] %}
### {{ severity.title() }} Severity ({{ findings[severity]|length }})

{% for finding in findings[severity] %}
#### {{ finding.title }}

**Type:** {{ finding.vulnerability_type.replace('_', ' ').title() }}
**Severity:** {{ finding.severity.title() }}
{% if finding.cvss_score %}**CVSS Score:** {{ finding.cvss_score }}  {% endif %}
{% if finding.cwe_id %}**CWE:** {{ finding.cwe_id }}  {% endif %}

**Description:**
{{ finding.description }}

**Impact:**
{{ finding.impact }}

{% if finding.affected_urls %}
**Affected URLs:**
{% for url in finding.affected_urls %}
- `{{ url }}`
{% endfor %}
{% endif %}

{% if finding.proof_of_concept %}
**Proof of Concept:**
```
{{ finding.proof_of_concept }}
```
{% endif %}

**Remediation:**
{{ finding.remediation }}

{% if finding.references %}
**References:**
{% for ref in finding.references %}
- [{{ ref }}]({{ ref }})
{% endfor %}
{% endif %}

---

{% endfor %}
{% endif %}
{% endfor %}

## Assessment Statistics

- **Total Findings:** {{ statistics.total_findings }}
- **Affected URLs:** {{ statistics.affected_urls_count }}
- **Findings with PoC:** {{ statistics.findings_with_poc }}
{% if statistics.average_cvss_score %}- **Average CVSS Score:** {{ statistics.average_cvss_score }}{% endif %}

### Vulnerability Types

{% for vuln_type, count in statistics.vulnerability_types.items() %}
- **{{ vuln_type.replace('_', ' ').title() }}:** {{ count }}
{% endfor %}

---

## Appendices

{% if appendices.methodology %}
### Testing Methodology

{% for method in appendices.methodology %}
- {{ method }}
{% endfor %}
{% endif %}

{% if appendices.tools_used %}
### Tools Used

{% for tool in appendices.tools_used %}
- {{ tool }}
{% endfor %}
{% endif %}

{% if appendices.references %}
### References

{% for ref in appendices.references %}
- [{{ ref.title }}]({{ ref.url }})
{% endfor %}
{% endif %}

---

*This report was generated automatically by the Bug Hunt Framework on {{ generated_date }}*
*Classification: {{ metadata.classification.title() }}*'''

        template_path = self.templates_directory / "comprehensive_report.md"
        with open(template_path, 'w') as f:
            f.write(markdown_template)

    def create_executive_summary_template(self):
        """Create executive summary template"""
        exec_summary_template = '''# Executive Summary - {{ metadata.target_domain }}

## Overview
This security assessment was conducted on **{{ metadata.target_domain }}** from {{ metadata.start_date }} to {{ metadata.end_date }}. The assessment identified **{{ executive_summary.total_findings }}** security findings with an overall risk score of **{{ executive_summary.overall_risk_score }}%**.

## Key Findings
{% for finding in executive_summary.key_findings %}
- **{{ finding.title }}** ({{ finding.severity.title() }})
{% endfor %}

## Risk Assessment
{% for severity, count in executive_summary.severity_breakdown.items() %}
- **{{ severity.title() }} Risk:** {{ count }} findings
{% endfor %}

## Immediate Actions Required
{% for rec in executive_summary.recommendations[:3] %}
1. {{ rec }}
{% endfor %}

---
*Generated on {{ generated_date }}*'''

        template_path = self.templates_directory / "executive_summary.md"
        with open(template_path, 'w') as f:
            f.write(exec_summary_template)

    def get_html_template(self, template_name: str) -> Template:
        """Get HTML template by name"""
        try:
            return self.env.get_template(f"{template_name}.html")
        except Exception as e:
            # Fallback to basic template
            return Template(f"<html><body><h1>Template Error</h1><p>{str(e)}</p></body></html>")

    def get_markdown_template(self, template_name: str) -> Template:
        """Get Markdown template by name"""
        try:
            return self.env.get_template(f"{template_name}.md")
        except Exception as e:
            return Template(f"# Template Error\n{str(e)}")

    def render_template(self, template_name: str, **kwargs) -> str:
        """Render template with given data"""
        try:
            if template_name.endswith('.html'):
                template = self.get_html_template(template_name.replace('.html', ''))
            elif template_name.endswith('.md'):
                template = self.get_markdown_template(template_name.replace('.md', ''))
            else:
                template = self.env.get_template(template_name)

            return template.render(**kwargs)
        except Exception as e:
            return f"Template rendering error: {str(e)}"

# Example usage
def main():
    """Example usage of the TemplateManager"""
    manager = TemplateManager()

    # Test data
    test_data = {
        'metadata': {
            'target_domain': 'example.com',
            'report_id': 'REPORT-001'
        },
        'generated_date': '2024-01-01 12:00:00'
    }

    # Render template
    html_content = manager.render_template('comprehensive_report.html', **test_data)
    print("HTML template rendered successfully")

if __name__ == "__main__":
    main()