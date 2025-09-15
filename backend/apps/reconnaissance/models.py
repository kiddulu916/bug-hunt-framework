"""
Reconnaissance Results Models
backend/apps/reconnaissance/models.py
"""

from django.db import models
from django.contrib.postgres.fields import ArrayField
from apps.scanning.models import ScanSession
import uuid

class ReconResultType(models.TextChoices):
    SUBDOMAIN = "subdomain", "Subdomain"
    ENDPOINT = "endpoint", "Endpoint"
    SERVICE = "service", "Service"
    TECHNOLOGY = "technology", "Technology"
    EMAIL = "email", "Email Address"
    IP_ADDRESS = "ip_address", "IP Address"
    PORT = "port", "Open Port"
    CERTIFICATE = "certificate", "SSL Certificate"
    DNS_RECORD = "dns_record", "DNS Record"

class DiscoveryMethod(models.TextChoices):
    DNS_ENUM = "dns_enum", "DNS Enumeration"
    PORT_SCAN = "port_scan", "Port Scanning"
    WEB_CRAWLING = "web_crawling", "Web Crawling"
    CERTIFICATE_TRANSPARENCY = "cert_transparency", "Certificate Transparency"
    SEARCH_ENGINE = "search_engine", "Search Engine"
    SOCIAL_MEDIA = "social_media", "Social Media"
    CODE_REPOSITORY = "code_repository", "Code Repository"
    ARCHIVE_SEARCH = "archive_search", "Archive Search"

class ReconResult(models.Model):
    """Reconnaissance results from passive and active discovery"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    scan_session = models.ForeignKey(
        ScanSession, 
        on_delete=models.CASCADE, 
        related_name='recon_results'
    )
    
    # Discovery Information
    result_type = models.CharField(
        max_length=50,
        choices=ReconResultType.choices,
        help_text="Type of asset discovered"
    )
    discovered_asset = models.CharField(
        max_length=1000, 
        help_text="The discovered asset (URL, domain, IP, etc.)"
    )
    
    # Asset Details
    ip_address = models.GenericIPAddressField(
        blank=True, 
        null=True,
        help_text="Resolved IP address"
    )
    port = models.IntegerField(
        blank=True, 
        null=True,
        help_text="Port number if applicable"
    )
    protocol = models.CharField(
        max_length=20, 
        blank=True,
        help_text="Protocol (http, https, tcp, udp)"
    )
    service_name = models.CharField(
        max_length=100, 
        blank=True,
        help_text="Service running on the port"
    )
    service_version = models.CharField(
        max_length=200, 
        blank=True,
        help_text="Version of the service"
    )
    
    # HTTP Specific Details
    status_code = models.IntegerField(
        blank=True, 
        null=True,
        help_text="HTTP status code"
    )
    response_size = models.IntegerField(
        blank=True, 
        null=True,
        help_text="HTTP response size in bytes"
    )
    title = models.CharField(
        max_length=500, 
        blank=True,
        help_text="Page title"
    )
    technologies = ArrayField(
        models.CharField(max_length=100),
        default=list,
        blank=True,
        help_text="Detected technologies"
    )
    
    # Discovery Source
    discovered_by_tool = models.CharField(
        max_length=100,
        help_text="Tool that discovered this asset"
    )
    discovery_method = models.CharField(
        max_length=100,
        choices=DiscoveryMethod.choices,
        help_text="Method used for discovery"
    )
    confidence_score = models.FloatField(
        default=0.0,
        help_text="Confidence in result accuracy (0-1)"
    )
    
    # Scope Validation
    is_in_scope = models.BooleanField(
        null=True,
        help_text="Whether this asset is in testing scope"
    )
    scope_validation_reason = models.CharField(
        max_length=500, 
        blank=True,
        help_text="Reason for scope decision"
    )
    
    # Additional Data
    headers = models.JSONField(
        default=dict,
        blank=True,
        help_text="HTTP headers if applicable"
    )
    additional_info = models.JSONField(
        default=dict,
        blank=True,
        help_text="Additional metadata about the asset"
    )
    
    # Metadata
    discovered_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'recon_results'
        ordering = ['-discovered_at']
        indexes = [
            models.Index(fields=['scan_session', 'result_type']),
            models.Index(fields=['discovered_asset']),
            models.Index(fields=['is_in_scope']),
            models.Index(fields=['discovered_by_tool']),
        ]
        # Prevent duplicate results within the same scan
        unique_together = ['scan_session', 'discovered_asset', 'result_type']
    
    def __str__(self):
        return f"{self.get_result_type_display()}: {self.discovered_asset}"
    
    @property
    def is_web_asset(self):
        """Check if this is a web-accessible asset"""
        return self.protocol in ['http', 'https'] and self.status_code is not None
    
    @property
    def is_live(self):
        """Check if asset is responding"""
        if self.status_code:
            return self.status_code < 400
        return False
    
    def get_full_url(self):
        """Construct full URL for web assets"""
        if self.result_type == ReconResultType.ENDPOINT:
            return self.discovered_asset
        elif self.result_type == ReconResultType.SUBDOMAIN and self.protocol:
            return f"{self.protocol}://{self.discovered_asset}"
        return None
    
    @classmethod
    def get_stats_by_scan(cls, scan_session):
        """Get statistics for a scan session"""
        results = cls.objects.filter(scan_session=scan_session)
        
        return {
            'total_results': results.count(),
            'by_type': {
                choice[0]: results.filter(result_type=choice[0]).count()
                for choice in cls.ReconResultType.choices
            },
            'in_scope': results.filter(is_in_scope=True).count(),
            'out_of_scope': results.filter(is_in_scope=False).count(),
            'pending_validation': results.filter(is_in_scope__isnull=True).count(),
            'live_assets': results.filter(status_code__lt=400).count(),
            'by_tool': {
                tool: results.filter(discovered_by_tool=tool).count()
                for tool in results.values_list('discovered_by_tool', flat=True).distinct()
            }
        }