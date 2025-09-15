"""
Vulnerability Management Models
backend/apps/vulnerabilities/models.py
"""

from django.db import models
from django.contrib.postgres.fields import ArrayField
from apps.scanning.models import ScanSession
import uuid


class VulnSeverity(models.TextChoices):
    CRITICAL = "critical", "Critical"
    HIGH = "high", "High"
    MEDIUM = "medium", "Medium"
    LOW = "low", "Low"
    INFO = "info", "Info"


class ExploitationDifficulty(models.TextChoices):
    EASY = "easy", "Easy"
    MEDIUM = "medium", "Medium"
    HARD = "hard", "Hard"
    UNKNOWN = "unknown", "Unknown"


class RemediationPriority(models.TextChoices):
    IMMEDIATE = "immediate", "Immediate"
    HIGH = "high", "High"
    MEDIUM = "medium", "Medium"
    LOW = "low", "Low"
    INFO_ONLY = "info_only", "Info Only"


class Vulnerability(models.Model):
    """Discovered vulnerabilities and security issues"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_session = models.ForeignKey(
        ScanSession,
        on_delete=models.CASCADE,
        related_name='vulnerabilities'
    )

    # Vulnerability Classification
    vulnerability_name = models.CharField(
        max_length=255,
        help_text="Name/title of the vulnerability"
    )
    vulnerability_type = models.CharField(
        max_length=100,
        help_text="Type of vulnerability (sqli, xss, rce, etc.)"
    )
    owasp_category = models.CharField(
        max_length=50,
        blank=True,
        help_text="OWASP Top 10 category (A01, A02, etc.)"
    )
    cwe_id = models.CharField(
        max_length=20,
        blank=True,
        help_text="CWE identifier (CWE-79, CWE-89, etc.)"
    )

    # Severity and Impact
    severity = models.CharField(
        max_length=20,
        choices=VulnSeverity.choices,
        help_text="Vulnerability severity level"
    )
    cvss_score = models.FloatField(
        blank=True,
        null=True,
        help_text="CVSS score (0.0-10.0)"
    )
    impact_description = models.TextField(
        help_text="Description of potential impact"
    )

    # Location Information
    affected_url = models.URLField(
        max_length=1000,
        help_text="URL where vulnerability was found"
    )
    affected_parameter = models.CharField(
        max_length=255,
        blank=True,
        help_text="Specific parameter that's vulnerable"
    )
    http_method = models.CharField(
        max_length=10,
        blank=True,
        help_text="HTTP method (GET, POST, etc.)"
    )

    # Technical Details
    payload_used = models.TextField(
        blank=True,
        help_text="Payload that triggered the vulnerability"
    )
    request_data = models.TextField(
        blank=True,
        help_text="Full HTTP request demonstrating the vulnerability"
    )
    response_data = models.TextField(
        blank=True,
        help_text="HTTP response showing vulnerability evidence"
    )

    # Discovery Information
    discovered_by_tool = models.CharField(
        max_length=100,
        help_text="Tool that discovered this vulnerability"
    )
    discovery_method = models.CharField(
        max_length=200,
        help_text="Method used to discover vulnerability"
    )
    confidence_level = models.FloatField(
        default=0.0,
        help_text="Confidence in vulnerability validity (0-1)"
    )
    false_positive_likelihood = models.FloatField(
        default=0.0,
        help_text="Likelihood this is a false positive (0-1)"
    )

    # Evidence
    screenshot_paths = ArrayField(
        models.CharField(max_length=500),
        default=list,
        blank=True,
        help_text="Paths to screenshot evidence"
    )
    additional_evidence = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional evidence files and data"
    )

    # Exploitation Details
    is_exploitable = models.BooleanField(
        default=False,
        help_text="Whether vulnerability was successfully exploited"
    )
    exploitation_difficulty = models.CharField(
        max_length=20,
        choices=ExploitationDifficulty.choices,
        blank=True,
        help_text="Difficulty level for exploitation"
    )
    exploitation_notes = models.TextField(
        blank=True,
        help_text="Notes on exploitation attempts"
    )

    # Remediation
    remediation_suggestion = models.TextField(
        blank=True,
        help_text="Suggested remediation steps"
    )
    remediation_priority = models.CharField(
        max_length=20,
        choices=RemediationPriority.choices,
        blank=True,
        help_text="Priority for remediation"
    )

    # Validation Status
    manually_verified = models.BooleanField(
        default=False,
        help_text="Whether vulnerability has been manually verified"
    )
    verification_notes = models.TextField(
        blank=True,
        help_text="Manual verification notes"
    )

    # Metadata
    discovered_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'vulnerabilities'
        ordering = ['-discovered_at']
        indexes = [
            models.Index(fields=['scan_session', 'severity']),
            models.Index(fields=['vulnerability_type']),
            models.Index(fields=['owasp_category']),
            models.Index(fields=['manually_verified']),
            models.Index(fields=['severity', 'cvss_score']),
        ]

    def __str__(self):
        return f"{self.vulnerability_name} - {self.get_severity_display()}"

    @property
    def severity_score(self):
        """Get numeric severity score for sorting"""
        severity_scores = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
        return severity_scores.get(self.severity, 0)

    @property
    def has_evidence(self):
        """Check if vulnerability has visual evidence"""
        return len(self.screenshot_paths) > 0 or bool(self.additional_evidence)

    def get_owasp_description(self):
        """Get OWASP category description"""
        owasp_mapping = {
            'A01': 'Broken Access Control',
            'A02': 'Cryptographic Failures',
            'A03': 'Injection',
            'A04': 'Insecure Design',
            'A05': 'Security Misconfiguration',
            'A06': 'Vulnerable and Outdated Components',
            'A07': 'Identification and Authentication Failures',
            'A08': 'Software and Data Integrity Failures',
            'A09': 'Security Logging and Monitoring Failures',
            'A10': 'Server-Side Request Forgery'
        }
        return owasp_mapping.get(self.owasp_category, '')

    @classmethod
    def get_severity_stats(cls, scan_session=None):
        """Get vulnerability statistics by severity"""
        queryset = cls.objects.all()
        if scan_session:
            queryset = queryset.filter(scan_session=scan_session)

        return {
            'total': queryset.count(),
            'critical': queryset.filter(severity='critical').count(),
            'high': queryset.filter(severity='high').count(),
            'medium': queryset.filter(severity='medium').count(),
            'low': queryset.filter(severity='low').count(),
            'info': queryset.filter(severity='info').count(),
            'verified': queryset.filter(manually_verified=True).count(),
            'exploitable': queryset.filter(is_exploitable=True).count(),
        }


class ExploitationChain(models.Model):
    """Vulnerability chains for maximum impact exploitation"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.CASCADE,
        related_name='exploitation_chains'
    )

    chain_name = models.CharField(
        max_length=255,
        help_text="Name for this exploitation chain"
    )
    chain_description = models.TextField(
        help_text="Description of the exploitation chain"
    )

    # Chain Details
    step_number = models.IntegerField(
        help_text="Step number in the chain"
    )
    total_steps = models.IntegerField(
        help_text="Total steps in this chain"
    )

    # Exploitation Step
    step_description = models.TextField(
        help_text="Description of this exploitation step"
    )
    payload = models.TextField(
        blank=True,
        help_text="Payload used in this step"
    )
    expected_result = models.TextField(
        blank=True,
        help_text="Expected result from this step"
    )
    actual_result = models.TextField(
        blank=True,
        help_text="Actual result obtained from this step"
    )

    # Evidence
    screenshot_path = models.CharField(
        max_length=500,
        blank=True,
        help_text="Screenshot evidence for this step"
    )
    request_response_log = models.TextField(
        blank=True,
        help_text="HTTP request/response log for this step"
    )

    # Success Tracking
    step_successful = models.BooleanField(
        default=False,
        help_text="Whether this step was successful"
    )
    chain_successful = models.BooleanField(
        default=False,
        help_text="Whether the entire chain was successful"
    )

    # Impact Assessment
    impact_increase = models.CharField(
        max_length=50,
        blank=True,
        help_text="How much this step increases impact "
        "(none, low, medium, high)"
    )
    final_impact_description = models.TextField(
        blank=True,
        help_text="Description of final impact achieved"
    )

    # Metadata
    executed_at = models.DateTimeField(auto_now_add=True)

    """Meta class for ExploitationChain"""

    class Meta:
        db_table = 'exploitation_chains'
        ordering = ['vulnerability', 'step_number']
        indexes = [
            models.Index(fields=['vulnerability', 'step_number']),
            models.Index(fields=['chain_successful']),
        ]

    def __str__(self):
        return f"{self.chain_name} - Step {self.step_number}/{self.total_steps}"

    @property
    def is_final_step(self):
        """Check if this is the final step in the chain"""
        return self.step_number == self.total_steps

    @property
    def success_percentage(self):
        """Calculate success percentage for this chain"""
        total_steps = ExploitationChain.objects.filter(
            vulnerability=self.vulnerability,
            chain_name=self.chain_name
        ).count()

        successful_steps = ExploitationChain.objects.filter(
            vulnerability=self.vulnerability,
            chain_name=self.chain_name,
            step_successful=True
        ).count()

        if total_steps > 0:
            return (successful_steps / total_steps) * 100
        return 0
