"""
Target Management Models
backend/apps/targets/models.py
"""

from django.db import models
from django.contrib.postgres.fields import ArrayField
import uuid
import enum

class BugBountyPlatform(models.TextChoices):
    HACKERONE = "hackerone", "HackerOne"
    BUGCROWD = "bugcrowd", "Bugcrowd"
    INTIGRITI = "intigriti", "Intigriti"
    SYNACK = "synack", "Synack"
    YESWEHACK = "yeswehack", "YesWeHack"
    PRIVATE = "private", "Private Program"

class Target(models.Model):
    """Target company and bug bounty program information"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    target_name = models.CharField(max_length=255, unique=True, help_text="Target company name")
    platform = models.CharField(
        max_length=20, 
        choices=BugBountyPlatform.choices,
        help_text="Bug bounty platform hosting this program"
    )
    researcher_username = models.CharField(
        max_length=100, 
        help_text="Your username on the bug bounty platform"
    )
    main_url = models.URLField(max_length=500, help_text="Primary target URL")
    wildcard_url = models.URLField(
        max_length=500, 
        blank=True, 
        null=True,
        help_text="Wildcard URL if applicable (e.g., *.example.com)"
    )
    
    # Scope Management
    in_scope_urls = ArrayField(
        models.URLField(max_length=500),
        default=list,
        blank=True,
        help_text="URLs that are in scope for testing"
    )
    out_of_scope_urls = ArrayField(
        models.URLField(max_length=500),
        default=list,
        blank=True,
        help_text="URLs that are explicitly out of scope"
    )
    in_scope_assets = ArrayField(
        models.CharField(max_length=500),
        default=list,
        blank=True,
        help_text="Other in-scope assets (IPs, domains, etc.)"
    )
    out_of_scope_assets = ArrayField(
        models.CharField(max_length=500),
        default=list,
        blank=True,
        help_text="Other out-of-scope assets"
    )
    
    # Rate Limiting & Request Configuration
    requests_per_second = models.FloatField(
        default=5.0,
        help_text="Maximum requests per second to target"
    )
    concurrent_requests = models.IntegerField(
        default=10,
        help_text="Maximum concurrent requests"
    )
    request_delay_ms = models.IntegerField(
        default=200,
        help_text="Delay between requests in milliseconds"
    )
    
    # HTTP Configuration
    required_headers = models.JSONField(
        default=dict,
        blank=True,
        help_text="Headers required for every request to target"
    )
    authentication_headers = models.JSONField(
        default=dict,
        blank=True,
        help_text="Authentication headers (cookies, API keys, etc.)"
    )
    user_agents = ArrayField(
        models.CharField(max_length=500),
        default=list,
        blank=True,
        help_text="Custom User-Agent strings to rotate"
    )
    
    # Program Specific Notes
    program_notes = models.TextField(
        blank=True,
        help_text="General notes about the bug bounty program"
    )
    special_requirements = models.TextField(
        blank=True,
        help_text="Special testing requirements or restrictions"
    )
    pii_redaction_rules = models.JSONField(
        default=dict,
        blank=True,
        help_text="Rules for redacting PII in reports"
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this target is active for testing"
    )
    
    class Meta:
        db_table = 'targets'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['platform']),
            models.Index(fields=['is_active']),
            models.Index(fields=['target_name']),
        ]
    
    def __str__(self):
        return f"{self.target_name} ({self.get_platform_display()})"
    
    @property
    def total_scan_sessions(self):
        return self.scan_sessions.count()
    
    @property
    def latest_scan_session(self):
        return self.scan_sessions.order_by('-created_at').first()
    
    def get_scope_summary(self):
        """Return a summary of in-scope and out-of-scope items"""
        return {
            'in_scope_urls_count': len(self.in_scope_urls),
            'out_of_scope_urls_count': len(self.out_of_scope_urls),
            'in_scope_assets_count': len(self.in_scope_assets),
            'out_of_scope_assets_count': len(self.out_of_scope_assets),
        }