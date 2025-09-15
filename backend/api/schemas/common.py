"""
Common Pydantic schemas shared across the application.
Defines reusable data validation and serialization models.
"""

from typing import List, Optional, Dict, Any, Union, Generic, TypeVar
from pydantic import BaseModel, Field, validator
from pydantic.generics import GenericModel
from datetime import datetime
from enum import Enum

# Generic type for paginated responses
T = TypeVar('T')

class PaginationMeta(BaseModel):
    """Schema for pagination metadata."""
    
    count: int = Field(..., ge=0, description="Total number of items")
    total_pages: int = Field(..., ge=1, description="Total number of pages")
    current_page: int = Field(..., ge=1, description="Current page number")
    page_size: int = Field(..., ge=1, le=100, description="Items per page")
    has_next: bool = Field(..., description="Whether there are more pages")
    has_previous: bool = Field(..., description="Whether there are previous pages")
    start_index: int = Field(..., ge=0, description="Starting item index")
    end_index: int = Field(..., ge=0, description="Ending item index")
    next_page: Optional[int] = Field(None, description="Next page number")
    previous_page: Optional[int] = Field(None, description="Previous page number")

    class Config:
        schema_extra = {
            "example": {
                "count": 150,
                "total_pages": 8,
                "current_page": 2,
                "page_size": 20,
                "has_next": True,
                "has_previous": True,
                "start_index": 21,
                "end_index": 40,
                "next_page": 3,
                "previous_page": 1
            }
        }

class PaginatedResponse(GenericModel, Generic[T]):
    """Generic schema for paginated API responses."""
    
    items: List[T] = Field(..., description="List of items")
    pagination: PaginationMeta = Field(..., description="Pagination metadata")

class StatusResponse(BaseModel):
    """Schema for simple status responses."""
    
    status: str = Field(..., description="Operation status")
    message: str = Field(..., description="Status message")
    details: Optional[Dict[str, Any]] = Field(None, description="Additional details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Response timestamp")

    class Config:
        schema_extra = {
            "example": {
                "status": "success",
                "message": "Operation completed successfully",
                "details": {"items_processed": 5},
                "timestamp": "2024-01-15T14:30:00Z"
            }
        }

class ErrorResponse(BaseModel):
    """Schema for API error responses."""
    
    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    error_code: Optional[str] = Field(None, description="Specific error code")
    details: Optional[Dict[str, Any]] = Field(None, description="Error details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")
    request_id: Optional[str] = Field(None, description="Request identifier")

    class Config:
        schema_extra = {
            "example": {
                "error": "ValidationError",
                "message": "Invalid input data provided",
                "error_code": "INVALID_DATA",
                "details": {
                    "field": "email",
                    "issue": "Invalid email format"
                },
                "timestamp": "2024-01-15T14:30:00Z",
                "request_id": "req_12345678"
            }
        }

class HealthCheckResponse(BaseModel):
    """Schema for health check responses."""
    
    status: str = Field(..., regex=r'^(healthy|unhealthy|degraded)$', description="Overall health status")
    service: str = Field(..., description="Service name")
    version: str = Field(..., description="Service version")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Health check timestamp")
    uptime_seconds: Optional[float] = Field(None, description="Service uptime in seconds")
    checks: Optional[Dict[str, Dict[str, Any]]] = Field(None, description="Individual health checks")

    class Config:
        schema_extra = {
            "example": {
                "status": "healthy",
                "service": "Bug Bounty Automation Platform",
                "version": "1.0.0",
                "timestamp": "2024-01-15T14:30:00Z",
                "uptime_seconds": 86400.5,
                "checks": {
                    "database": {
                        "status": "healthy",
                        "response_time_ms": 12.3
                    },
                    "redis": {
                        "status": "healthy",
                        "response_time_ms": 2.1
                    }
                }
            }
        }

class SearchFilter(BaseModel):
    """Schema for search and filtering options."""
    
    query: Optional[str] = Field(None, min_length=1, max_length=500, description="Search query")
    fields: Optional[List[str]] = Field(None, description="Fields to search in")
    filters: Optional[Dict[str, Any]] = Field(None, description="Additional filters")
    sort_by: Optional[str] = Field(None, description="Sort field")
    sort_order: str = Field("asc", regex=r'^(asc|desc)$', description="Sort order")
    date_from: Optional[datetime] = Field(None, description="Date range start")
    date_to: Optional[datetime] = Field(None, description="Date range end")

    @validator('date_to')
    def validate_date_range(cls, v, values):
        date_from = values.get('date_from')
        if date_from and v and date_from > v:
            raise ValueError('date_from must be before date_to')
        return v

    class Config:
        schema_extra = {
            "example": {
                "query": "SQL injection",
                "fields": ["vulnerability_name", "description"],
                "filters": {
                    "severity": ["high", "critical"],
                    "status": "verified"
                },
                "sort_by": "discovered_at",
                "sort_order": "desc",
                "date_from": "2024-01-01T00:00:00Z",
                "date_to": "2024-01-31T23:59:59Z"
            }
        }

class BulkOperationRequest(BaseModel):
    """Schema for bulk operation requests."""
    
    item_ids: List[str] = Field(..., min_items=1, max_items=100, description="List of item IDs")
    operation: str = Field(..., description="Operation to perform")
    parameters: Optional[Dict[str, Any]] = Field(None, description="Operation parameters")
    dry_run: bool = Field(False, description="Whether to perform a dry run")

    class Config:
        schema_extra = {
            "example": {
                "item_ids": [
                    "12345678-1234-5678-9012-123456789012",
                    "87654321-4321-8765-4321-876543218765"
                ],
                "operation": "update_status",
                "parameters": {
                    "status": "verified",
                    "notes": "Bulk verification"
                },
                "dry_run": False
            }
        }

class BulkOperationResponse(BaseModel):
    """Schema for bulk operation responses."""
    
    operation: str = Field(..., description="Operation performed")
    total_items: int = Field(..., ge=0, description="Total items processed")
    successful: int = Field(..., ge=0, description="Successfully processed items")
    failed: int = Field(..., ge=0, description="Failed items")
    errors: List[Dict[str, str]] = Field(default_factory=list, description="Error details")
    duration_seconds: float = Field(..., ge=0.0, description="Operation duration")
    dry_run: bool = Field(False, description="Whether this was a dry run")

    class Config:
        schema_extra = {
            "example": {
                "operation": "update_status",
                "total_items": 5,
                "successful": 4,
                "failed": 1,
                "errors": [
                    {
                        "item_id": "87654321-4321-8765-4321-876543218765",
                        "error": "Item not found"
                    }
                ],
                "duration_seconds": 2.5,
                "dry_run": False
            }
        }

class FileUploadResponse(BaseModel):
    """Schema for file upload responses."""
    
    filename: str = Field(..., description="Uploaded filename")
    original_filename: str = Field(..., description="Original filename")
    file_size: int = Field(..., ge=0, description="File size in bytes")
    file_type: str = Field(..., description="MIME type")
    file_path: str = Field(..., description="Server file path")
    upload_id: str = Field(..., description="Upload identifier")
    uploaded_at: datetime = Field(default_factory=datetime.utcnow, description="Upload timestamp")
    uploaded_by: str = Field(..., description="User who uploaded the file")

    class Config:
        schema_extra = {
            "example": {
                "filename": "evidence_screenshot_20240115.png",
                "original_filename": "screenshot.png",
                "file_size": 2456789,
                "file_type": "image/png",
                "file_path": "/app/media/evidence/screenshot_20240115.png",
                "upload_id": "upload_12345678",
                "uploaded_at": "2024-01-15T14:30:00Z",
                "uploaded_by": "security_analyst"
            }
        }

class ExportRequest(BaseModel):
    """Schema for data export requests."""
    
    export_format: str = Field(..., regex=r'^(csv|json|xml|xlsx|pdf)$', description="Export format")
    include_metadata: bool = Field(True, description="Include metadata in export")
    filters: Optional[Dict[str, Any]] = Field(None, description="Export filters")
    fields: Optional[List[str]] = Field(None, description="Specific fields to export")
    date_range: Optional[Dict[str, datetime]] = Field(None, description="Date range for export")
    max_records: Optional[int] = Field(None, ge=1, le=10000, description="Maximum records to export")

    class Config:
        schema_extra = {
            "example": {
                "export_format": "csv",
                "include_metadata": True,
                "filters": {
                    "severity": ["high", "critical"],
                    "verified": True
                },
                "fields": ["name", "severity", "url", "discovered_at"],
                "date_range": {
                    "start": "2024-01-01T00:00:00Z",
                    "end": "2024-01-31T23:59:59Z"
                },
                "max_records": 1000
            }
        }

class ExportResponse(BaseModel):
    """Schema for data export responses."""
    
    export_id: str = Field(..., description="Export identifier")
    export_format: str = Field(..., description="Export format")
    file_path: Optional[str] = Field(None, description="Export file path")
    download_url: Optional[str] = Field(None, description="Download URL")
    record_count: int = Field(..., ge=0, description="Number of exported records")
    file_size: Optional[int] = Field(None, ge=0, description="Export file size")
    status: str = Field(..., regex=r'^(pending|processing|completed|failed)$', description="Export status")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Export creation timestamp")
    completed_at: Optional[datetime] = Field(None, description="Export completion timestamp")
    expires_at: Optional[datetime] = Field(None, description="Export expiration timestamp")

class NotificationSettings(BaseModel):
    """Schema for notification preferences."""
    
    email_notifications: bool = Field(True, description="Enable email notifications")
    webhook_notifications: bool = Field(False, description="Enable webhook notifications")
    notification_types: List[str] = Field(default_factory=list, description="Enabled notification types")
    email_addresses: List[str] = Field(default_factory=list, description="Notification email addresses")
    webhook_url: Optional[str] = Field(None, description="Webhook URL")
    notification_frequency: str = Field("immediate", regex=r'^(immediate|daily|weekly)$', description="Notification frequency")

    @validator('email_addresses', each_item=True)
    def validate_email_addresses(cls, v):
        import re
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, v):
            raise ValueError('Invalid email address format')
        return v

class UserPreferences(BaseModel):
    """Schema for user preferences."""
    
    theme: str = Field("light", regex=r'^(light|dark|auto)$', description="UI theme preference")
    language: str = Field("en", description="Language preference")
    timezone: str = Field("UTC", description="Timezone preference")
    items_per_page: int = Field(20, ge=10, le=100, description="Default items per page")
    notifications: NotificationSettings = Field(default_factory=NotificationSettings, description="Notification settings")
    dashboard_layout: Optional[Dict[str, Any]] = Field(None, description="Custom dashboard layout")

class SystemConfiguration(BaseModel):
    """Schema for system configuration settings."""
    
    maintenance_mode: bool = Field(False, description="System maintenance mode")
    max_concurrent_scans: int = Field(5, ge=1, le=20, description="Maximum concurrent scans")
    default_scan_timeout: int = Field(3600, ge=300, le=86400, description="Default scan timeout in seconds")
    rate_limit_requests: int = Field(1000, ge=100, le=10000, description="Rate limit requests per hour")
    log_level: str = Field("INFO", regex=r'^(DEBUG|INFO|WARNING|ERROR|CRITICAL)$', description="Logging level")
    backup_enabled: bool = Field(True, description="Automated backups enabled")
    retention_days: int = Field(90, ge=1, le=365, description="Data retention period in days")

# Validation schemas

class ValidationResult(BaseModel):
    """Schema for validation results."""
    
    is_valid: bool = Field(..., description="Overall validation result")
    errors: List[str] = Field(default_factory=list, description="Validation errors")
    warnings: List[str] = Field(default_factory=list, description="Validation warnings")
    field_errors: Dict[str, List[str]] = Field(default_factory=dict, description="Field-specific errors")
    suggestions: List[str] = Field(default_factory=list, description="Improvement suggestions")

class TimeRange(BaseModel):
    """Schema for time range specifications."""
    
    start: datetime = Field(..., description="Range start time")
    end: datetime = Field(..., description="Range end time")
    timezone: Optional[str] = Field(None, description="Timezone identifier")

    @validator('end')
    def validate_end_after_start(cls, v, values):
        start = values.get('start')
        if start and v <= start:
            raise ValueError('End time must be after start time')
        return v

# Export all common schemas
__all__ = [
    "PaginationMeta",
    "PaginatedResponse",
    "StatusResponse",
    "ErrorResponse", 
    "HealthCheckResponse",
    "SearchFilter",
    "BulkOperationRequest",
    "BulkOperationResponse",
    "FileUploadResponse",
    "ExportRequest",
    "ExportResponse",
    "NotificationSettings",
    "UserPreferences", 
    "SystemConfiguration",
    "ValidationResult",
    "TimeRange",
]