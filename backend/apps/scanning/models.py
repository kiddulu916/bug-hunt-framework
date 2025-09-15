"""
Scan Session Management Models
backend/apps/scanning/models.py
"""

from django.db import models
from django.contrib.postgres.fields import ArrayField
from apps.targets.models import Target
import uuid

class ScanStatus(models.TextChoices):
    QUEUED = "queued", "Queued"
    RUNNING = "running", "Running"
    PAUSED = "paused", "Paused"
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"
    CANCELLED = "cancelled", "Cancelled"

class ToolStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    RUNNING = "running", "Running"
    COMPLETED = "completed", "Completed"
    FAILED = "failed", "Failed"
    SKIPPED = "skipped", "Skipped"

class ScanSession(models.Model):
    """Individual penetration testing sessions"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target = models.ForeignKey(
        Target,
        on_delete=models.CASCADE,
        related_name='scan_sessions'
    )

    session_name = models.CharField(max_length=255, help_text="Descriptive name for this scan")
    status = models.CharField(
        max_length=20,
        choices=ScanStatus.choices,
        default=ScanStatus.QUEUED
    )

    # Scan Configuration
    scan_config = models.JSONField(
        default=dict,
        help_text="Tools to run and their parameters"
    )
    methodology_phases = ArrayField(
        models.CharField(max_length=50),
        default=list,
        help_text="Testing methodology phases"
    )

    # Progress Tracking
    current_phase = models.CharField(
        max_length=50,
        blank=True,
        null=True,
        help_text="Current testing phase"
    )
    phase_progress = models.JSONField(
        default=dict,
        help_text="Progress tracking per phase"
    )
    total_progress = models.FloatField(
        default=0.0,
        help_text="Overall scan progress percentage (0-100)"
    )

    # Timing
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    estimated_completion = models.DateTimeField(blank=True, null=True)

    # Results Summary
    total_subdomains_found = models.IntegerField(default=0)
    total_endpoints_found = models.IntegerField(default=0)
    total_vulnerabilities = models.IntegerField(default=0)
    critical_vulnerabilities = models.IntegerField(default=0)
    high_vulnerabilities = models.IntegerField(default=0)

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'scan_sessions'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['target', 'status']),
            models.Index(fields=['status']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return f"{self.session_name} - {self.target.target_name}"

    @property
    def duration(self):
        """Calculate scan duration if completed"""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

    @property
    def is_running(self):
        return self.status == ScanStatus.RUNNING

    @property
    def vulnerability_summary(self):
        """Get vulnerability counts by severity"""
        return {
            'total': self.total_vulnerabilities,
            'critical': self.critical_vulnerabilities,
            'high': self.high_vulnerabilities,
            'medium': self.vulnerabilities.filter(severity='medium').count(),
            'low': self.vulnerabilities.filter(severity='low').count(),
            'info': self.vulnerabilities.filter(severity='info').count(),
        }

class ToolExecution(models.Model):
    """Track individual tool execution within scan sessions"""

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_session = models.ForeignKey(
        ScanSession,
        on_delete=models.CASCADE,
        related_name='tool_executions'
    )

    tool_name = models.CharField(
        max_length=100,
        help_text="Tool name (amass, subfinder, nuclei, etc.)"
    )
    tool_category = models.CharField(
        max_length=50,
        help_text="Tool category (passive_recon, active_recon, etc.)"
    )
    command_executed = models.TextField(help_text="Full command that was executed")

    status = models.CharField(
        max_length=20,
        choices=ToolStatus.choices,
        default=ToolStatus.PENDING
    )

    # Execution Details
    started_at = models.DateTimeField(blank=True, null=True)
    completed_at = models.DateTimeField(blank=True, null=True)
    execution_time_seconds = models.FloatField(blank=True, null=True)

    # Results
    output_file_path = models.FilePathField(
        max_length=500,
        blank=True,
        null=True,
        help_text="Path to tool output file"
    )
    raw_output = models.TextField(
        blank=True,
        help_text="Raw tool output"
    )
    parsed_results_count = models.IntegerField(
        default=0,
        help_text="Number of results parsed from output"
    )
    error_message = models.TextField(
        blank=True,
        help_text="Error message if tool execution failed"
    )

    # Configuration
    tool_parameters = models.JSONField(
        default=dict,
        help_text="Parameters passed to the tool"
    )

    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'tool_executions'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['scan_session', 'tool_category']),
            models.Index(fields=['tool_name']),
            models.Index(fields=['status']),
        ]

    def __str__(self):
        return f"{self.tool_name} - {self.scan_session.session_name}"

    @property
    def duration(self):
        """Calculate execution duration"""
        if self.started_at and self.completed_at:
            return self.completed_at - self.started_at
        return None

    @property
    def success_rate(self):
        """Calculate success rate for this tool across all sessions"""
        total_executions = ToolExecution.objects.filter(tool_name=self.tool_name).count()
        successful_executions = ToolExecution.objects.filter(
            tool_name=self.tool_name,
            status=ToolStatus.COMPLETED
        ).count()

        if total_executions > 0:
            return (successful_executions / total_executions) * 100
        return 0
