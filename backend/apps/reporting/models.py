"""
Report Generation Models
backend/apps/reporting/models.py
"""

from django.db import models
from apps.scanning.models import ScanSession
import uuid

class ReportType(models.TextChoices):
    TECHNICAL = "technical", "Technical Report"
    EXECUTIVE = "executive", "Executive Summary"
    BUG_BOUNTY = "bug_bounty", "Bug Bounty Report"
    COMPLIANCE = "compliance", "Compliance Report"
    CUSTOM = "custom", "Custom Report"

class ReportFormat(models.TextChoices):
    PDF = "pdf", "PDF"
    HTML = "html", "HTML"
    JSON = "json", "JSON"
    MARKDOWN = "markdown", "Markdown"
    DOCX = "docx", "Word Document"

class Report(models.Model):
    """Generated penetration testing reports"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_session = models.ForeignKey(
        ScanSession,
        on_delete=models.CASCADE,
        related_name='reports'
    )

    report_name = models.CharField(
        max_length=255,
        help_text="Name of the generated report"
    )
    report_type = models.CharField(
        max_length=50,
        choices=ReportType.choices,
        help_text="Type of report generated"
    )
    report_format = models.CharField(
        max_length=20,
        choices=ReportFormat.choices,
        default=ReportFormat.PDF,
        help_text="Output format of the report"
    )

    # Report Content
    executive_summary = models.TextField(
        blank=True,
        help_text="Executive summary for management"
    )
    technical_details = models.TextField(
        blank=True,
        help_text="Technical details and methodology"
    )
    methodology_used = models.TextField(
        blank=True,
        help_text="Testing methodology description"
    )
    recommendations = models.TextField(
        blank=True,
        help_text="Security recommendations"
    )

    # File Information
    pdf_file_path = models.FileField(
        upload_to='reports/pdf/',
        blank=True,
        null=True,
        help_text="Path to PDF report file"
    )
    html_file_path = models.FileField(
        upload_to='reports/html/',
        blank=True,
        null=True,
        help_text="Path to HTML report file"
    )
    json_file_path = models.FileField(
        upload_to='reports/json/',
        blank=True,
        null=True,
        help_text="Path to JSON data export"
    )

    # Report Statistics
    total_vulnerabilities_reported = models.IntegerField(
        default=0,
        help_text="Total vulnerabilities included in report"
    )
    critical_count = models.IntegerField(default=0)
    high_count = models.IntegerField(default=0)
    medium_count = models.IntegerField(default=0)
    low_count = models.IntegerField(default=0)
    info_count = models.IntegerField(default=0)

    # PII Redaction Status
    pii_redacted = models.BooleanField(
        default=False,
        help_text="Whether PII has been redacted from this report"
    )
    redaction_rules_applied = models.JSONField(
        default=dict,
        blank=True,
        help_text="PII redaction rules that were applied"
    )

    # Report Configuration
    include_raw_data = models.BooleanField(
        default=False,
        help_text="Include raw tool outputs in report"
    )
    include_screenshots = models.BooleanField(
        default=True,
        help_text="Include vulnerability screenshots"
    )
    include_remediation = models.BooleanField(
        default=True,
        help_text="Include remediation recommendations"
    )
    include_exploitation_chains = models.BooleanField(
        default=True,
        help_text="Include exploitation chain details"
    )

    # Template and Styling
    template_used = models.CharField(
        max_length=100,
        blank=True,
        help_text="Report template that was used"
    )
    custom_styling = models.JSONField(
        default=dict,
        blank=True,
        help_text="Custom styling options applied"
    )

    # Metadata
    generated_at = models.DateTimeField(auto_now_add=True)
    generated_by = models.CharField(
        max_length=100,
        default="AutoReporter",
        help_text="System or user that generated the report"
    )
    file_size_bytes = models.BigIntegerField(
        blank=True,
        null=True,
        help_text="Size of generated report file in bytes"
    )

    class Meta:
        db_table = 'reports'
        ordering = ['-generated_at']
        indexes = [
            models.Index(fields=['scan_session', 'report_type']),
            models.Index(fields=['generated_at']),
            models.Index(fields=['report_type']),
            models.Index(fields=['pii_redacted']),
        ]

    def __str__(self):
        return f"{self.report_name} - {self.get_report_type_display()}"

    @property
    def vulnerability_summary(self):
        """Get vulnerability count summary"""
        return {
            'total': self.total_vulnerabilities_reported,
            'critical': self.critical_count,
            'high': self.high_count,
            'medium': self.medium_count,
            'low': self.low_count,
            'info': self.info_count,
        }

    @property
    def file_size_human(self):
        """Get human-readable file size"""
        if not self.file_size_bytes:
            return "Unknown"

        for unit in ['B', 'KB', 'MB', 'GB']:
            if self.file_size_bytes < 1024.0:
                return f"{self.file_size_bytes:.1f} {unit}"
            self.file_size_bytes /= 1024.0
        return f"{self.file_size_bytes:.1f} TB"

    def get_primary_file(self):
        """Get the primary report file based on format"""
        format_mapping = {
            'pdf': self.pdf_file_path,
            'html': self.html_file_path,
            'json': self.json_file_path,
        }
        return format_mapping.get(self.report_format)

    @classmethod
    def get_report_stats(cls, scan_session=None):
        """Get report generation statistics"""
        queryset = cls.objects.all()
        if scan_session:
            queryset = queryset.filter(scan_session=scan_session)

        return {
            'total_reports': queryset.count(),
            'by_type': {
                choice[0]: queryset.filter(report_type=choice[0]).count()
                for choice in cls.ReportType.choices
            },
            'by_format': {
                choice[0]: queryset.filter(report_format=choice[0]).count()
                for choice in cls.ReportFormat.choices
            },
            'pii_redacted_count': queryset.filter(pii_redacted=True).count(),
            'average_vulnerabilities': queryset.aggregate(
                models.Avg('total_vulnerabilities_reported')
            )['total_vulnerabilities_reported__avg'] or 0,
        }

class ReportTemplate(models.Model):
    """Customizable report templates"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)

    template_name = models.CharField(
        max_length=255,
        unique=True,
        help_text="Name of the report template"
    )
    template_type = models.CharField(
        max_length=50,
        choices=ReportType.choices,
        help_text="Type of reports this template is for"
    )

    # Template Content
    template_content = models.TextField(
        help_text="Jinja2 template content"
    )
    css_styling = models.TextField(
        blank=True,
        help_text="CSS styles for the template"
    )
    javascript_code = models.TextField(
        blank=True,
        help_text="JavaScript code for interactive elements"
    )

    # Template Configuration
    default_sections = models.JSONField(
        default=list,
        help_text="Default sections to include in reports"
    )
    required_data_fields = models.JSONField(
        default=list,
        help_text="Required data fields for this template"
    )
    optional_data_fields = models.JSONField(
        default=list,
        help_text="Optional data fields for this template"
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this template is available for use"
    )
    is_default = models.BooleanField(
        default=False,
        help_text="Whether this is the default template for its type"
    )

    # Usage Statistics
    usage_count = models.IntegerField(
        default=0,
        help_text="Number of times this template has been used"
    )

    class Meta:
        db_table = 'report_templates'
        ordering = ['template_name']
        indexes = [
            models.Index(fields=['template_type']),
            models.Index(fields=['is_active']),
            models.Index(fields=['is_default']),
        ]

    def __str__(self):
        return f"{self.template_name} ({self.get_template_type_display()})"

    def increment_usage(self):
        """Increment usage counter"""
        self.usage_count += 1
        self.save(update_fields=['usage_count'])

    @classmethod
    def get_default_template(cls, template_type):
        """Get default template for a specific type"""
        return cls.objects.filter(
            template_type=template_type,
            is_default=True,
            is_active=True
        ).first()

    @classmethod
    def get_available_templates(cls, template_type=None):
        """Get all available templates"""
        queryset = cls.objects.filter(is_active=True)
        if template_type:
            queryset = queryset.filter(template_type=template_type)
        return queryset.order_by('-usage_count', 'template_name')
