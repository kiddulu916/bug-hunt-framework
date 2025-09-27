"""
Pydantic schemas for target management.
Defines data validation and serialization models for target-related API endpoints.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any, Union
from pydantic import (
    BaseModel,
    Field,
    model_validator,
    HttpUrl,
    field_validator
)
from apps.targets.models import BugBountyPlatform
from core.security import InputValidator
input_validator = InputValidator()


class TargetBase(BaseModel):
    """Base schema for target data."""

    target_name: str = Field(
        ...,
        min_length=3,
        max_length=255,
        description="Target name"
        )
    platform: BugBountyPlatform = Field(..., description="Bug bounty platform")
    researcher_username: str = Field(
        ...,
        min_length=3,
        max_length=100,
        description="Researcher username on platform"
        )
    main_url: HttpUrl = Field(..., description="Primary target URL")
    wildcard_url: Optional[HttpUrl] = Field(
        None,
        description="Wildcard URL pattern"
        )
    in_scope_urls: List[str] = Field(
        default_factory=list,
        description="In-scope URL patterns"
        )
    out_of_scope_urls: List[str] = Field(
        default_factory=list,
        description="Out-of-scope URL patterns"
        )
    in_scope_assets: List[str] = Field(
        default_factory=list,
        description="In-scope asset patterns"
        )
    out_of_scope_assets: List[str] = Field(
        default_factory=list,
        description="Out-of-scope asset patterns"
        )
    requests_per_second: float = Field(
        5.0,
        ge=0.1, le=100.0,
        description="Request rate limit"
        )
    concurrent_requests: int = Field(
        10,
        ge=1,
        le=100,
        description="Concurrent request limit"
        )
    request_delay_ms: int = Field(
        200,
        ge=0,
        le=10000,
        description="Delay between requests in milliseconds"
        )
    required_headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Required HTTP headers"
        )
    authentication_headers: Dict[str, str] = Field(
        default_factory=dict,
        description="Authentication headers"
        )
    user_agents: List[str] = Field(
        default_factory=lambda: ["BugBountyBot/1.0"],
        description="User agent strings"
        )
    program_notes: Optional[str] = Field(
        None,
        max_length=2000,
        description="Program-specific notes"
        )
    special_requirements: Optional[str] = Field(
        None,
        max_length=2000,
        description="Special testing requirements"
        )
    pii_redaction_rules: Dict[str, Any] = Field(
        default_factory=dict,
        description="PII redaction configuration"
        )

    @field_validator('target_name')
    @classmethod
    def validate_target_name(cls, v):
        """Validate target name format."""
        if not input_validator.validate_target_name(v):
            raise ValueError('Invalid target name format')
        return v

    @field_validator('in_scope_urls', 'out_of_scope_urls')
    @classmethod
    def validate_url_patterns(cls, v):
        """Validate URL patterns."""
        if not isinstance(v, list):
            raise ValueError('URL patterns must be a list')

        validated_urls = []
        for url_pattern in v:
            if isinstance(url_pattern, str):
                url_pattern = url_pattern.strip()
                if url_pattern:  # Only add non-empty patterns
                    validated_urls.append(url_pattern)

        return validated_urls

    @field_validator('user_agents')
    @classmethod
    def validate_user_agents(cls, v):
        """Ensure at least one user agent is provided."""
        if not v:
            return ["BugBountyBot/1.0"]
        return [ua.strip() for ua in v if ua.strip()]

    @model_validator(mode="after")
    @classmethod
    def validate_scope_consistency(cls, values):
        """Validate that scope configuration is consistent."""
        in_scope_urls = values.get('in_scope_urls', [])
        out_of_scope_urls = values.get('out_of_scope_urls', [])

        # Check for overlapping scope definitions
        for in_scope in in_scope_urls:
            for out_scope in out_of_scope_urls:
                if in_scope == out_scope:
                    raise ValueError(
                        f'URL pattern "{in_scope}" \
                        cannot be both in-scope and out-of-scope'
                        )

        return values


class TargetCreate(TargetBase):
    """Schema for creating a new target."""

    class Config:
        schema_extra = {
            "example": {
                "target_name": "Example Corp Bug Bounty",
                "platform": "hackerone",
                "researcher_username": "security_researcher",
                "main_url": "https://example.com",
                "wildcard_url": "https://*.example.com",
                "in_scope_urls": [
                    "https://example.com/*",
                    "https://api.example.com/*",
                    "https://app.example.com/*"
                ],
                "out_of_scope_urls": [
                    "https://blog.example.com/*",
                    "https://help.example.com/*"
                ],
                "in_scope_assets": [
                    "192.168.1.0/24",
                    "example.com",
                    "*.example.com"
                ],
                "out_of_scope_assets": [
                    "192.168.1.1",
                    "blog.example.com"
                ],
                "requests_per_second": 5.0,
                "concurrent_requests": 10,
                "request_delay_ms": 200,
                "required_headers": {
                    "User-Agent": "BugBountyBot/1.0"
                },
                "authentication_headers": {
                    "Authorization": "Bearer token123"
                },
                "program_notes": "Standard web application testing \
                                  program with comprehensive scope",
                "special_requirements": "Avoid testing during business hours \
                                        (9-5 EST). Test during business hours"
            }
        }


class TargetUpdate(BaseModel):
    """Schema for updating target data."""

    target_name: Optional[str] = Field(None, min_length=3, max_length=255)
    platform: Optional[BugBountyPlatform] = None
    researcher_username: Optional[str] = Field(
        None,
        min_length=3,
        max_length=100
        )
    main_url: Optional[HttpUrl] = None
    wildcard_url: Optional[HttpUrl] = None
    in_scope_urls: Optional[List[str]] = None
    out_of_scope_urls: Optional[List[str]] = None
    in_scope_assets: Optional[List[str]] = None
    out_of_scope_assets: Optional[List[str]] = None
    requests_per_second: Optional[float] = Field(None, ge=0.1, le=100.0)
    concurrent_requests: Optional[int] = Field(None, ge=1, le=100)
    request_delay_ms: Optional[int] = Field(None, ge=0, le=10000)
    required_headers: Optional[Dict[str, str]] = None
    authentication_headers: Optional[Dict[str, str]] = None
    user_agents: Optional[List[str]] = None
    program_notes: Optional[str] = Field(None, max_length=2000)
    special_requirements: Optional[str] = Field(None, max_length=2000)
    pii_redaction_rules: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None

    @field_validator('target_name')
    @classmethod
    def validate_target_name(cls, v):
        """Validate target name format."""
        if v is not None and not input_validator.validate_target_name(v):
            raise ValueError('Invalid target name format')
        return v


class TargetResponse(TargetBase):
    """Schema for target response data."""

    id: str = Field(..., description="Target ID")
    is_active: bool = Field(
        True,
        description="Whether target is active for scanning"
        )
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    @field_validator('id')
    @classmethod
    def validate_id(cls, v):
        """Validate target ID format."""
        if not input_validator.validate_uuid(v):
            raise ValueError('Invalid target ID format')
        return v

    class Config:
        """Config for target response."""
        orm_mode = True
        schema_extra = {
            "example": {
                "id": "12345678-1234-5678-9012-123456789012",
                "target_name": "Example Corp Bug Bounty",
                "platform": "hackerone",
                "researcher_username": "security_researcher",
                "main_url": "https://example.com",
                "wildcard_url": "https://*.example.com",
                "in_scope_urls": [
                    "https://example.com/*",
                    "https://api.example.com/*"
                ],
                "out_of_scope_urls": [
                    "https://blog.example.com/*"
                ],
                "requests_per_second": 5.0,
                "concurrent_requests": 10,
                "request_delay_ms": 200,
                "is_active": True,
                "created_at": "2024-01-15T10:30:00Z",
                "updated_at": "2024-01-15T14:20:00Z"
            }
        }


class TargetListResponse(BaseModel):
    """Schema for paginated target list response."""

    targets: List[TargetResponse] = Field(..., description="List of targets")
    pagination: Dict[str, Any] = Field(..., description="Pagination metadata")
    platform_counts: Dict[str, int] = Field(
        default_factory=dict,
        description="Count by platform"
        )
    total_active: int = Field(0, description="Total active targets")

    class Config:
        schema_extra = {
            "example": {
                "targets": [],
                "pagination": {
                    "count": 25,
                    "total_pages": 3,
                    "current_page": 1,
                    "page_size": 10,
                    "has_next": True,
                    "has_previous": False
                },
                "platform_counts": {
                    "hackerone": 10,
                    "bugcrowd": 8,
                    "intigriti": 5,
                    "private": 2
                },
                "total_active": 23
            }
        }


class ScopeValidation(BaseModel):
    """Schema for scope validation results."""

    asset_url: str = Field(..., description="Asset URL being validated")
    is_valid: bool = Field(..., description="Whether asset is in scope")
    is_in_scope: bool = Field(..., description="Whether asset matches in-scope patterns")
    is_out_of_scope: bool = Field(..., description="Whether asset matches out-of-scope patterns")
    matching_patterns: List[str] = Field(default_factory=list, description="Matching scope patterns")
    validation_reason: str = Field(..., description="Reason for validation result")
    recommendations: List[str] = Field(default_factory=list, description="Recommendations for scope compliance")

    class Config:
        schema_extra = {
            "example": {
                "asset_url": "https://api.example.com/v1/users",
                "is_valid": True,
                "is_in_scope": True,
                "is_out_of_scope": False,
                "matching_patterns": ["https://api.example.com/*"],
                "validation_reason": "URL matches in-scope pattern",
                "recommendations": []
            }
        }

class TargetConfiguration(BaseModel):
    """Schema for target scanning configuration."""

    target_id: str = Field(..., description="Target ID")
    scan_config: Dict[str, Any] = Field(..., description="Generated scan configuration")
    tool_configs: Dict[str, Dict[str, Any]] = Field(..., description="Tool-specific configurations")
    rate_limiting: Dict[str, Union[float, int]] = Field(..., description="Rate limiting configuration")
    authentication: Dict[str, Any] = Field(..., description="Authentication configuration")
    scope_rules: Dict[str, List[str]] = Field(..., description="Scope validation rules")
    special_instructions: List[str] = Field(default_factory=list, description="Special testing instructions")

    class Config:
        schema_extra = {
            "example": {
                "target_id": "12345678-1234-5678-9012-123456789012",
                "scan_config": {
                    "phases": ["passive_recon", "active_recon", "vulnerability_testing"],
                    "tools": ["amass", "subfinder", "httpx", "nuclei"],
                    "depth": "comprehensive"
                },
                "tool_configs": {
                    "amass": {
                        "passive_only": True,
                        "timeout": 3600
                    },
                    "nuclei": {
                        "severity": ["critical", "high", "medium"],
                        "exclude_tags": ["dos"]
                    }
                },
                "rate_limiting": {
                    "requests_per_second": 5.0,
                    "concurrent_requests": 10,
                    "delay_ms": 200
                },
                "authentication": {
                    "type": "bearer_token",
                    "headers": {}
                },
                "scope_rules": {
                    "in_scope": ["https://example.com/*"],
                    "out_of_scope": ["https://blog.example.com/*"]
                },
                "special_instructions": [
                    "Avoid testing during business hours",
                    "Use authenticated scanning where possible"
                ]
            }
        }

class ConnectivityTest(BaseModel):
    """Schema for target connectivity test results."""

    url: HttpUrl = Field(..., description="Tested URL")
    is_reachable: bool = Field(..., description="Whether URL is reachable")
    response_time_ms: Optional[float] = Field(None, description="Response time in milliseconds")
    status_code: Optional[int] = Field(None, description="HTTP status code")
    response_headers: Dict[str, str] = Field(default_factory=dict, description="Response headers")
    error_message: Optional[str] = Field(None, description="Error message if unreachable")
    ssl_info: Optional[Dict[str, Any]] = Field(None, description="SSL certificate information")
    dns_resolution: Optional[Dict[str, Any]] = Field(None, description="DNS resolution information")
    tested_at: datetime = Field(default_factory=datetime.utcnow, description="Test timestamp")

    class Config:
        schema_extra = {
            "example": {
                "url": "https://example.com",
                "is_reachable": True,
                "response_time_ms": 245.3,
                "status_code": 200,
                "response_headers": {
                    "Server": "nginx/1.18.0",
                    "Content-Type": "text/html"
                },
                "ssl_info": {
                    "valid": True,
                    "expires_at": "2024-12-31T23:59:59Z",
                    "issuer": "Let's Encrypt"
                },
                "dns_resolution": {
                    "a_records": ["192.0.2.1"],
                    "aaaa_records": ["2001:db8::1"],
                    "cname_records": []
                },
                "tested_at": "2024-01-15T10:30:00Z"
            }
        }

class TargetStatistics(BaseModel):
    """Schema for target statistics."""

    target_id: str = Field(..., description="Target ID")
    target_name: str = Field(..., description="Target name")
    scans: Dict[str, Union[int, float]] = Field(..., description="Scan statistics")
    vulnerabilities: Dict[str, int] = Field(..., description="Vulnerability statistics")
    assets_discovered: int = Field(..., description="Total assets discovered")
    scope: Dict[str, int] = Field(..., description="Scope configuration statistics")
    last_scan_date: Optional[datetime] = Field(None, description="Date of last scan")
    avg_scan_duration_hours: Optional[float] = Field(None, description="Average scan duration in hours")

    class Config:
        schema_extra = {
            "example": {
                "target_id": "12345678-1234-5678-9012-123456789012",
                "target_name": "Example Corp Bug Bounty",
                "scans": {
                    "total": 15,
                    "completed": 13,
                    "success_rate": 86.7
                },
                "vulnerabilities": {
                    "total": 47,
                    "critical": 2,
                    "high": 8,
                    "medium": 23,
                    "low": 14
                },
                "assets_discovered": 156,
                "scope": {
                    "in_scope_urls": 3,
                    "out_of_scope_urls": 2,
                    "in_scope_assets": 5,
                    "out_of_scope_assets": 2
                },
                "last_scan_date": "2024-01-14T16:45:00Z",
                "avg_scan_duration_hours": 2.3
            }
        }

class TargetFilter(BaseModel):
    """Schema for target filtering options."""

    platforms: Optional[List[BugBountyPlatform]] = Field(None, description="Filter by platforms")
    is_active: Optional[bool] = Field(None, description="Filter by active status")
    created_after: Optional[datetime] = Field(None, description="Created after date")
    created_before: Optional[datetime] = Field(None, description="Created before date")
    updated_after: Optional[datetime] = Field(None, description="Updated after date")
    updated_before: Optional[datetime] = Field(None, description="Updated before date")
    has_scans: Optional[bool] = Field(None, description="Filter targets with/without scans")
    min_request_rate: Optional[float] = Field(None, ge=0.1, description="Minimum request rate")
    max_request_rate: Optional[float] = Field(None, le=100.0, description="Maximum request rate")

    @model_validator(mode="after")
    @classmethod
    def validate_date_ranges(cls, values):
        """Validate date range consistency."""
        created_after = values.get('created_after')
        created_before = values.get('created_before')
        updated_after = values.get('updated_after')
        updated_before = values.get('updated_before')

        if created_after and created_before and created_after > created_before:
            raise ValueError('created_after must be before created_before')

        if updated_after and updated_before and updated_after > updated_before:
            raise ValueError('updated_after must be before updated_before')

        return values

    @model_validator(mode="after")
    @classmethod
    def validate_rate_range(cls, values):
        """Validate request rate range."""
        min_rate = values.get('min_request_rate')
        max_rate = values.get('max_request_rate')

        if min_rate and max_rate and min_rate > max_rate:
            raise ValueError('min_request_rate must be less than or equal to max_request_rate')

        return values

class ScopeRule(BaseModel):
    """Schema for individual scope rule."""

    pattern: str = Field(..., min_length=1, description="URL or asset pattern")
    rule_type: str = Field(..., pattern=r'^(url|ip|domain|wildcard)', description="Type of scope rule")
    is_inclusive: bool = Field(..., description="True for in-scope, False for out-of-scope")
    description: Optional[str] = Field(None, description="Rule description")
    priority: int = Field(0, description="Rule priority (higher = more important)")

class ScopeConfiguration(BaseModel):
    """Schema for comprehensive scope configuration."""

    target_id: str = Field(..., description="Target ID")
    rules: List[ScopeRule] = Field(..., description="List of scope rules")
    default_policy: str = Field("deny", pattern=r'^(allow|deny)', description="Default policy for unlisted assets")
    validation_notes: Optional[str] = Field(None, description="Notes about scope validation")
    last_updated: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")

class TargetHealth(BaseModel):
    """Schema for target health status."""

    target_id: str = Field(..., description="Target ID")
    is_healthy: bool = Field(..., description="Overall health status")
    connectivity_status: str = Field(..., pattern=r'^(online|offline|degraded|unknown)', description="Connectivity status")
    last_successful_scan: Optional[datetime] = Field(None, description="Last successful scan timestamp")
    last_connectivity_check: datetime = Field(..., description="Last connectivity check timestamp")
    health_issues: List[str] = Field(default_factory=list, description="List of detected health issues")
    recommendations: List[str] = Field(default_factory=list, description="Recommendations to improve health")

class BulkTargetOperation(BaseModel):
    """Schema for bulk operations on targets."""

    target_ids: List[str] = Field(..., min_items=1, description="List of target IDs")
    operation: str = Field(..., pattern=r'^(activate|deactivate|update_rate_limit|delete)', description="Operation to perform")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Operation-specific parameters")

    class Config:
        schema_extra = {
            "example": {
                "target_ids": [
                    "12345678-1234-5678-9012-123456789012",
                    "87654321-4321-8765-4321-876543218765"
                ],
                "operation": "update_rate_limit",
                "parameters": {
                    "requests_per_second": 3.0,
                    "concurrent_requests": 5
                }
            }
        }

class TargetExport(BaseModel):
    """Schema for target export data."""

    targets: List[TargetResponse] = Field(..., description="Targets to export")
    export_format: str = Field(..., pattern=r'^(csv|json|xml)', description="Export format")
    include_statistics: bool = Field(False, description="Include target statistics")
    include_scope_rules: bool = Field(True, description="Include detailed scope rules")
    filters: Dict[str, Any] = Field(default_factory=dict, description="Applied filters")
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Export generation timestamp")
    generated_by: str = Field(..., description="User who generated the export")

# Platform-specific schemas

class PlatformIntegration(BaseModel):
    """Schema for bug bounty platform integration settings."""

    platform: BugBountyPlatform = Field(..., description="Bug bounty platform")
    api_key: Optional[str] = Field(None, description="API key for platform")
    webhook_url: Optional[HttpUrl] = Field(None, description="Webhook URL for notifications")
    auto_submission: bool = Field(False, description="Automatically submit findings")
    submission_template: Optional[str] = Field(None, description="Template for submissions")
    platform_specific_config: Dict[str, Any] = Field(default_factory=dict, description="Platform-specific configuration")

class TargetValidation(BaseModel):
    """Schema for target validation results."""

    is_valid: bool = Field(..., description="Overall validation result")
    validation_errors: List[str] = Field(default_factory=list, description="Validation error messages")
    validation_warnings: List[str] = Field(default_factory=list, description="Validation warnings")
    scope_conflicts: List[str] = Field(default_factory=list, description="Scope configuration conflicts")
    recommendations: List[str] = Field(default_factory=list, description="Improvement recommendations")
    validated_at: datetime = Field(default_factory=datetime.utcnow, description="Validation timestamp")

# Export all schemas
__all__ = [
    "TargetBase",
    "TargetCreate",
    "TargetUpdate",
    "TargetResponse",
    "TargetListResponse",
    "ScopeValidation",
    "TargetConfiguration",
    "ConnectivityTest",
    "TargetStatistics",
    "TargetFilter",
    "ScopeRule",
    "ScopeConfiguration",
    "TargetHealth",
    "BulkTargetOperation",
    "TargetExport",
    "PlatformIntegration",
    "TargetValidation",
]
