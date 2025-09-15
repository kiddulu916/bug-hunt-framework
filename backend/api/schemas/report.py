"""
Pydantic schemas for report management.
Defines data validation and serialization models for report-related API endpoints.
"""

from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, validator, root_validator
from datetime import datetime
from enum import Enum

from core.constants import REPORT_TYPES, REPORT_FORMATS, REPORT_TEMPLATES

class ReportBase(BaseModel):
    """Base schema for report data."""

    report_name: str = Field(..., min_length=3, max_length=255, description="Report name")
    report_type: str = Field(..., description="Type of report")
    executive_summary: Optional[str] = Field(None, max_length=5000, description="Executive summary")
    technical_details: Optional[str] = Field(None, description="Technical details section")
    methodology_used: Optional[str] = Field(None, max_length=2000, description="Methodology description")
    recommendations: Optional[str] = Field(None, description="Recommendations section")

    @validator('report_type')
    def validate_report_type(cls, v):
        """Validate report type against known types."""
        if v not in REPORT_TYPES:
            raise ValueError(f'Invalid report type. Must be one of: {", ".join(REPORT_TYPES)}')
        return v

class ReportCreate(ReportBase):
    """Schema for creating a new report."""

    scan_session_id: str = Field(..., description="Scan session ID to generate report for")
    template_name: Optional[str] = Field(None, description="Report template to use")
    template_options: Dict[str, Any] = Field(default_factory=dict, description="Template-specific options")
    include_raw_data: bool = Field(False, description="Include raw scan data")
    pii_redaction: bool = Field(True, description="Apply PII redaction")
    custom_sections: List[Dict[str, str]] = Field(default_factory=list, description="Custom report sections")

    @validator('template_name')
    def validate_template_name(cls, v):
        if v is not None and v not in REPORT_TEMPLATES:
            raise ValueError(f'Invalid template name. Must be one of: {", ".join(REPORT_TEMPLATES.keys())}')
        return v

    class Config:
        schema_extra = {
            "example": {
                "scan_session_id": "87654321-4321-8765-4321-876543218765",
                "report_name": "Security Assessment Report - Example Corp",
                "report_type": "technical",
                "template_name": "technical_report",
                "template_options": {
                    "include_methodology": True,
                    "include_tool_outputs": False,
                    "severity_threshold": "medium"
                },
                "include_raw_data": False,
                "pii_redaction": True,
                "executive_summary": "This assessment identified several security vulnerabilities...",
                "custom_sections": [
                    {
                        "title": "Infrastructure Overview",
                        "content": "The target infrastructure consists of..."
                    }
                ]
            }
        }

class ReportUpdate(BaseModel):
    """Schema for updating report data."""

    report_name: Optional[str] = Field(None, min_length=3, max_length=255)
    report_type: Optional[str] = None
    executive_summary: Optional[str] = Field(None, max_length=5000)
    technical_details: Optional[str] = None
    methodology_used: Optional[str] = Field(None, max_length=2000)
    recommendations: Optional[str] = None

    @validator('report_type')
    def validate_report_type(cls, v):
        if v is not None and v not in REPORT_TYPES:
            raise ValueError(f'Invalid report type. Must be one of: {", ".join(REPORT_TYPES)}')
        return v

class ReportResponse(ReportBase):
    """Schema for report response data."""

    id: str = Field(..., description="Report ID")
    scan_session_id: str = Field(..., description="Associated scan session ID")
    pdf_file_path: Optional[str] = Field(None, description="Path to PDF report file")
    html_file_path: Optional[str] = Field(None, description="Path to HTML report file")
    json_file_path: Optional[str] = Field(None, description="Path to JSON report file")
    total_vulnerabilities_reported: int = Field(0, description="Total vulnerabilities in report")
    critical_count: int = Field(0, description="Critical vulnerabilities count")
    high_count: int = Field(0, description="High severity vulnerabilities count")
    medium_count: int = Field(0, description="Medium severity vulnerabilities count")
    low_count: int = Field(0, description="Low severity vulnerabilities count")
    pii_redacted: bool = Field(False, description="Whether PII has been redacted")
    redaction_rules_applied: Dict[str, Any] = Field(default_factory=dict, description="Applied redaction rules")
    generated_at: datetime = Field(..., description="Report generation timestamp")
    generated_by: str = Field(..., description="User who generated the report")
    file_size_bytes: Optional[int] = Field(None, description="Total report file size")
    generation_time_seconds: Optional[float] = Field(None, description="Time taken to generate report")

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": "report-12345678-1234-5678-9012-123456789012",
                "scan_session_id": "87654321-4321-8765-4321-876543218765",
                "report_name": "Security Assessment Report - Example Corp",
                "report_type": "technical",
                "pdf_file_path": "/app/reports/technical_report_20240115.pdf",
                "html_file_path": "/app/reports/technical_report_20240115.html",
                "json_file_path": "/app/reports/technical_report_20240115.json",
                "total_vulnerabilities_reported": 23,
                "critical_count": 2,
                "high_count": 5,
                "medium_count": 11,
                "low_count": 5,
                "pii_redacted": True,
                "generated_at": "2024-01-15T18:30:00Z",
                "generated_by": "security_analyst",
                "file_size_bytes": 2456789,
                "generation_time_seconds": 45.6
            }
        }

class ReportListResponse(BaseModel):
    """Schema for paginated report list response."""

    reports: List[ReportResponse] = Field(..., description="List of reports")
    pagination: Dict[str, Any] = Field(..., description="Pagination metadata")
    type_counts: Dict[str, int] = Field(default_factory=dict, description="Count by report type")

    class Config:
        schema_extra = {
            "example": {
                "reports": [],
                "pagination": {
                    "count": 34,
                    "total_pages": 2,
                    "current_page": 1,
                    "page_size": 20,
                    "has_next": True,
                    "has_previous": False
                },
                "type_counts": {
                    "technical": 15,
                    "executive": 8,
                    "bug_bounty": 10,
                    "compliance": 1
                }
            }
        }

class ReportGeneration(BaseModel):
    """Schema for custom report generation requests."""

    report_name: str = Field(..., min_length=3, max_length=255, description="Report name")
    report_type: str = Field(..., description="Report type")
    scan_session_ids: List[str] = Field(..., min_items=1, description="Scan session IDs to include")
    template_name: str = Field(..., description="Template to use")
    output_formats: List[str] = Field(default_factory=lambda: ["pdf"], description="Output formats")

    # Content configuration
    include_executive_summary: bool = Field(True, description="Include executive summary")
    include_technical_details: bool = Field(True, description="Include technical details")
    include_methodology: bool = Field(True, description="Include methodology section")
    include_recommendations: bool = Field(True, description="Include recommendations")
    include_raw_outputs: bool = Field(False, description="Include raw tool outputs")
    include_evidence: bool = Field(True, description="Include vulnerability evidence")

    # Filtering options
    severity_filter: Optional[List[str]] = Field(None, description="Include only specified severities")
    vulnerability_types_filter: Optional[List[str]] = Field(None, description="Include only specified vulnerability types")
    verified_only: bool = Field(False, description="Include only verified vulnerabilities")
    exclude_false_positives: bool = Field(True, description="Exclude likely false positives")

    # Formatting options
    logo_path: Optional[str] = Field(None, description="Path to company logo")
    company_name: Optional[str] = Field(None, description="Company name for branding")
    report_footer: Optional[str] = Field(None, description="Custom footer text")
    custom_css: Optional[str] = Field(None, description="Custom CSS for HTML reports")

    # PII and security
    pii_redaction: bool = Field(True, description="Apply PII redaction")
    redaction_level: str = Field("standard", regex=r'^(minimal|standard|aggressive)$', description="Redaction level")
    watermark_text: Optional[str] = Field(None, description="Watermark text")

    # Metadata
    report_id: Optional[str] = Field(None, description="Generated report ID")
    status: Optional[str] = Field(None, description="Generation status")
    progress: Optional[float] = Field(None, ge=0.0, le=100.0, description="Generation progress")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion time")

    @validator('report_type')
    def validate_report_type(cls, v):
        if v not in REPORT_TYPES:
            raise ValueError(f'Invalid report type. Must be one of: {", ".join(REPORT_TYPES)}')
        return v

    @validator('template_name')
    def validate_template_name(cls, v):
        if v not in REPORT_TEMPLATES:
            raise ValueError(f'Invalid template name. Must be one of: {", ".join(REPORT_TEMPLATES.keys())}')
        return v

    @validator('output_formats', each_item=True)
    def validate_output_formats(cls, v):
        if v not in REPORT_FORMATS:
            raise ValueError(f'Invalid output format. Must be one of: {", ".join(REPORT_FORMATS)}')
        return v

    class Config:
        schema_extra = {
            "example": {
                "report_name": "Quarterly Security Assessment",
                "report_type": "executive",
                "scan_session_ids": [
                    "87654321-4321-8765-4321-876543218765",
                    "12345678-1234-5678-9012-123456789012"
                ],
                "template_name": "executive_summary",
                "output_formats": ["pdf", "html"],
                "include_executive_summary": True,
                "include_technical_details": False,
                "severity_filter": ["critical", "high"],
                "verified_only": True,
                "company_name": "Acme Security Corp",
                "pii_redaction": True,
                "redaction_level": "standard"
            }
        }

class ReportTemplate(BaseModel):
    """Schema for report templates."""

    template_name: str = Field(..., description="Template identifier")
    display_name: str = Field(..., description="Human-readable template name")
    description: str = Field(..., description="Template description")
    report_type: str = Field(..., description="Compatible report type")
    supported_formats: List[str] = Field(..., description="Supported output formats")
    default_sections: List[str] = Field(..., description="Default sections included")
    customizable_sections: List[str] = Field(default_factory=list, description="Sections that can be customized")
    template_options: Dict[str, Any] = Field(default_factory=dict, description="Available template options")
    preview_image: Optional[str] = Field(None, description="Path to template preview image")
    is_default: bool = Field(False, description="Whether this is the default template for the type")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Template creation date")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update date")

    class Config:
        schema_extra = {
            "example": {
                "template_name": "technical_report",
                "display_name": "Technical Security Report",
                "description": "Comprehensive technical report with detailed vulnerability analysis",
                "report_type": "technical",
                "supported_formats": ["pdf", "html", "json"],
                "default_sections": [
                    "executive_summary",
                    "methodology",
                    "findings",
                    "technical_details",
                    "recommendations"
                ],
                "customizable_sections": ["executive_summary", "recommendations"],
                "template_options": {
                    "include_tool_outputs": {"type": "boolean", "default": False},
                    "severity_threshold": {"type": "select", "options": ["low", "medium", "high", "critical"], "default": "medium"}
                },
                "is_default": True
            }
        }

class ReportExport(BaseModel):
    """Schema for report data export."""

    report_id: str = Field(..., description="Source report ID")
    format: str = Field(..., regex=r'^(json|xml|csv)$', description="Export format")
    data: Dict[str, Any] = Field(..., description="Exported report data")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Export metadata")
    exported_at: datetime = Field(..., description="Export timestamp")
    exported_by: str = Field(..., description="User who exported the data")
    file_size_bytes: Optional[int] = Field(None, description="Export file size")

    class Config:
        schema_extra = {
            "example": {
                "report_id": "report-12345678-1234-5678-9012-123456789012",
                "format": "json",
                "data": {
                    "report_metadata": {},
                    "vulnerabilities": [],
                    "scan_details": {},
                    "statistics": {}
                },
                "metadata": {
                    "export_version": "1.0",
                    "schema_version": "2024.01",
                    "total_records": 156
                },
                "exported_at": "2024-01-15T20:15:00Z",
                "exported_by": "data_analyst",
                "file_size_bytes": 1234567
            }
        }

class ReportFilter(BaseModel):
    """Schema for report filtering options."""

    report_types: Optional[List[str]] = Field(None, description="Filter by report types")
    scan_session_ids: Optional[List[str]] = Field(None, description="Filter by scan session IDs")
    generated_after: Optional[datetime] = Field(None, description="Generated after date")
    generated_before: Optional[datetime] = Field(None, description="Generated before date")
    generated_by: Optional[List[str]] = Field(None, description="Filter by report generators")
    min_vulnerabilities: Optional[int] = Field(None, ge=0, description="Minimum vulnerabilities count")
    max_vulnerabilities: Optional[int] = Field(None, ge=0, description="Maximum vulnerabilities count")
    has_critical: Optional[bool] = Field(None, description="Filter reports with/without critical vulnerabilities")
    pii_redacted: Optional[bool] = Field(None, description="Filter by PII redaction status")
    file_formats: Optional[List[str]] = Field(None, description="Filter by available file formats")

    @validator('report_types', each_item=True)
    def validate_report_types(cls, v):
        if v not in REPORT_TYPES:
            raise ValueError(f'Invalid report type. Must be one of: {", ".join(REPORT_TYPES)}')
        return v

    @validator('file_formats', each_item=True)
    def validate_file_formats(cls, v):
        if v not in REPORT_FORMATS:
            raise ValueError(f'Invalid file format. Must be one of: {", ".join(REPORT_FORMATS)}')
        return v

    @root_validator
    def validate_date_range(cls, values):
        generated_after = values.get('generated_after')
        generated_before = values.get('generated_before')

        if generated_after and generated_before and generated_after > generated_before:
            raise ValueError('generated_after must be before generated_before')

        return values

    @root_validator
    def validate_vulnerability_range(cls, values):
        min_vulns = values.get('min_vulnerabilities')
        max_vulns = values.get('max_vulnerabilities')

        if min_vulns is not None and max_vulns is not None and min_vulns > max_vulns:
            raise ValueError('min_vulnerabilities must be less than or equal to max_vulnerabilities')

        return values

class ReportStatistics(BaseModel):
    """Schema for report generation statistics."""

    total_reports: int = Field(..., ge=0, description="Total number of reports")
    recent_reports: int = Field(..., ge=0, description="Recent reports count")
    type_distribution: Dict[str, int] = Field(..., description="Distribution by report type")
    pii_redacted_reports: int = Field(..., ge=0, description="Reports with PII redaction")
    average_vulnerabilities_per_report: float = Field(..., ge=0.0, description="Average vulnerabilities per report")
    redaction_rate: float = Field(..., ge=0.0, le=100.0, description="PII redaction rate percentage")
    average_generation_time: float = Field(..., ge=0.0, description="Average generation time in seconds")
    most_active_generators: List[Dict[str, Union[str, int]]] = Field(default_factory=list, description="Most active report generators")

    class Config:
        schema_extra = {
            "example": {
                "total_reports": 127,
                "recent_reports": 15,
                "type_distribution": {
                    "technical": 45,
                    "executive": 32,
                    "bug_bounty": 38,
                    "compliance": 12
                },
                "pii_redacted_reports": 98,
                "average_vulnerabilities_per_report": 18.5,
                "redaction_rate": 77.2,
                "average_generation_time": 42.3,
                "most_active_generators": [
                    {"user": "security_analyst", "reports": 23},
                    {"user": "lead_researcher", "reports": 19}
                ]
            }
        }

class ReportTrends(BaseModel):
    """Schema for report generation trends."""

    period: Dict[str, Union[str, int]] = Field(..., description="Analysis period information")
    daily_generation: List[Dict[str, Union[str, int]]] = Field(..., description="Daily report generation counts")
    type_trends: List[Dict[str, Union[str, int]]] = Field(..., description="Report type trends over time")
    vulnerability_trends: List[Dict[str, Union[str, float]]] = Field(..., description="Vulnerability reporting trends")
    quality_metrics: List[Dict[str, Union[str, float]]] = Field(default_factory=list, description="Report quality trends")

class BulkReportOperation(BaseModel):
    """Schema for bulk operations on reports."""

    report_ids: List[str] = Field(..., min_items=1, description="List of report IDs")
    operation: str = Field(..., regex=r'^(regenerate|delete|export|update_redaction)', description="Operation to perform")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Operation-specific parameters")

    class Config:
        schema_extra = {
            "example": {
                "report_ids": [
                    "report-12345678-1234-5678-9012-123456789012",
                    "report-87654321-4321-8765-4321-876543218765"
                ],
                "operation": "regenerate",
                "parameters": {
                    "include_recent_findings": True,
                    "update_recommendations": True
                }
            }
        }

class ReportSection(BaseModel):
    """Schema for individual report sections."""

    section_id: str = Field(..., description="Section identifier")
    title: str = Field(..., min_length=1, max_length=200, description="Section title")
    content: str = Field(..., description="Section content")
    order: int = Field(..., ge=0, description="Section display order")
    is_custom: bool = Field(False, description="Whether section is custom-added")
    template_section: bool = Field(True, description="Whether section comes from template")
    formatting: Dict[str, Any] = Field(default_factory=dict, description="Section formatting options")

class ReportCustomization(BaseModel):
    """Schema for report customization options."""

    report_id: str = Field(..., description="Report ID to customize")
    custom_sections: List[ReportSection] = Field(default_factory=list, description="Custom sections to add")
    section_order: List[str] = Field(default_factory=list, description="Custom section ordering")
    branding: Dict[str, str] = Field(default_factory=dict, description="Branding customizations")
    formatting_options: Dict[str, Any] = Field(default_factory=dict, description="Formatting customizations")
    content_filters: Dict[str, Any] = Field(default_factory=dict, description="Content filtering options")

class ReportDelivery(BaseModel):
    """Schema for report delivery configuration."""

    report_id: str = Field(..., description="Report ID to deliver")
    delivery_method: str = Field(..., regex=r'^(email|webhook|ftp|api)', description="Delivery method")
    recipients: List[str] = Field(..., min_items=1, description="Delivery recipients")
    delivery_options: Dict[str, Any] = Field(default_factory=dict, description="Method-specific options")
    schedule: Optional[str] = Field(None, description="Delivery schedule (cron expression)")
    format_preferences: List[str] = Field(default_factory=lambda: ["pdf"], description="Preferred formats")
    encryption_required: bool = Field(False, description="Whether encryption is required")
    delivery_confirmation: bool = Field(True, description="Whether to send delivery confirmation")

    @validator('format_preferences', each_item=True)
    def validate_format_preferences(cls, v):
        if v not in REPORT_FORMATS:
            raise ValueError(f'Invalid format. Must be one of: {", ".join(REPORT_FORMATS)}')
        return v

class ReportQuality(BaseModel):
    """Schema for report quality assessment."""

    report_id: str = Field(..., description="Report ID")
    quality_score: float = Field(..., ge=0.0, le=10.0, description="Overall quality score")
    completeness_score: float = Field(..., ge=0.0, le=10.0, description="Content completeness score")
    accuracy_score: float = Field(..., ge=0.0, le=10.0, description="Information accuracy score")
    presentation_score: float = Field(..., ge=0.0, le=10.0, description="Presentation quality score")

    # Quality indicators
    missing_sections: List[str] = Field(default_factory=list, description="Missing expected sections")
    formatting_issues: List[str] = Field(default_factory=list, description="Formatting problems")
    content_gaps: List[str] = Field(default_factory=list, description="Content gaps identified")
    strengths: List[str] = Field(default_factory=list, description="Report strengths")
    improvement_suggestions: List[str] = Field(default_factory=list, description="Improvement suggestions")

    # Metrics
    readability_score: Optional[float] = Field(None, ge=0.0, le=100.0, description="Text readability score")
    word_count: Optional[int] = Field(None, ge=0, description="Total word count")
    page_count: Optional[int] = Field(None, ge=1, description="Total page count")

    assessed_at: datetime = Field(default_factory=datetime.utcnow, description="Assessment timestamp")
    assessed_by: Optional[str] = Field(None, description="Quality assessor")

class ReportApproval(BaseModel):
    """Schema for report approval workflow."""

    report_id: str = Field(..., description="Report ID")
    approval_status: str = Field(..., regex=r'^(pending|approved|rejected|revision_required)', description="Approval status")
    reviewer: str = Field(..., description="Report reviewer")
    review_comments: Optional[str] = Field(None, description="Review comments")
    approval_date: Optional[datetime] = Field(None, description="Approval timestamp")
    revision_requests: List[str] = Field(default_factory=list, description="Specific revision requests")
    approval_level: str = Field(..., regex=r'^(technical|management|client)', description="Approval level")
    next_reviewer: Optional[str] = Field(None, description="Next person in approval chain")

class ReportMetadata(BaseModel):
    """Schema for comprehensive report metadata."""

    report_id: str = Field(..., description="Report ID")
    title: str = Field(..., description="Report title")
    version: str = Field("1.0", description="Report version")
    author: str = Field(..., description="Report author")
    reviewers: List[str] = Field(default_factory=list, description="Report reviewers")
    classification: str = Field("internal", regex=r'^(public|internal|confidential|restricted)', description="Security classification")
    tags: List[str] = Field(default_factory=list, description="Report tags")
    related_reports: List[str] = Field(default_factory=list, description="Related report IDs")
    retention_period: Optional[int] = Field(None, ge=1, description="Retention period in days")
    archive_date: Optional[datetime] = Field(None, description="Archive date")
    access_permissions: Dict[str, List[str]] = Field(default_factory=dict, description="Access permissions")

class ReportValidation(BaseModel):
    """Schema for report validation results."""

    is_valid: bool = Field(..., description="Overall validation result")
    validation_errors: List[str] = Field(default_factory=list, description="Validation error messages")
    validation_warnings: List[str] = Field(default_factory=list, description="Validation warnings")
    content_issues: List[str] = Field(default_factory=list, description="Content-related issues")
    formatting_issues: List[str] = Field(default_factory=list, description="Formatting issues")
    data_consistency_issues: List[str] = Field(default_factory=list, description="Data consistency problems")
    recommendations: List[str] = Field(default_factory=list, description="Validation recommendations")
    validated_at: datetime = Field(default_factory=datetime.utcnow, description="Validation timestamp")

# Export all schemas
__all__ = [
    "ReportBase",
    "ReportCreate",
    "ReportUpdate",
    "ReportResponse",
    "ReportListResponse",
    "ReportGeneration",
    "ReportTemplate",
    "ReportExport",
    "ReportFilter",
    "ReportStatistics",
    "ReportTrends",
    "BulkReportOperation",
    "ReportSection",
    "ReportCustomization",
    "ReportDelivery",
    "ReportQuality",
    "ReportApproval",
    "ReportMetadata",
    "ReportValidation",
]
