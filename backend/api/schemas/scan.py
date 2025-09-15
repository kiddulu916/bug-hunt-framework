"""
Pydantic schemas for scan management.
Defines data validation and serialization models for scan-related API endpoints.
"""

from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, validator, root_validator
from datetime import datetime, timedelta
from enum import Enum

from apps.scans.models import ScanStatus, ToolStatus
from core.constants import RECON_PHASES, TOOL_CONFIGS

class ScanBase(BaseModel):
    """Base schema for scan session data."""

    session_name: str = Field(..., min_length=3, max_length=255, description="Scan session name")
    scan_config: Dict[str, Any] = Field(default_factory=dict, description="Scan configuration parameters")
    methodology_phases: List[str] = Field(default_factory=lambda: RECON_PHASES, description="Methodology phases to execute")

    @validator('methodology_phases')
    def validate_methodology_phases(cls, v):
        """Validate methodology phases against known phases."""
        if not v:
            return RECON_PHASES

        valid_phases = set(RECON_PHASES)
        invalid_phases = [phase for phase in v if phase not in valid_phases]

        if invalid_phases:
            raise ValueError(f'Invalid methodology phases: {", ".join(invalid_phases)}. '
                           f'Valid phases are: {", ".join(RECON_PHASES)}')

        return v

class ScanSessionCreate(ScanBase):
    """Schema for creating a new scan session."""

    target_id: str = Field(..., description="Target ID to scan")
    priority: int = Field(5, ge=1, le=10, description="Scan priority (1=lowest, 10=highest)")
    max_duration_hours: Optional[int] = Field(None, ge=1, le=48, description="Maximum scan duration in hours")
    scheduled_start: Optional[datetime] = Field(None, description="Scheduled start time")
    tools_config: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Tool-specific configurations")

    @validator('scheduled_start')
    def validate_scheduled_start(cls, v):
        """Ensure scheduled start is in the future."""
        if v is not None and v <= datetime.utcnow():
            raise ValueError('Scheduled start time must be in the future')
        return v

    @root_validator
    def validate_tools_config(cls, values):
        """Validate tool configurations."""
        tools_config = values.get('tools_config', {})

        for tool_name, config in tools_config.items():
            if tool_name not in TOOL_CONFIGS:
                raise ValueError(f'Unknown tool: {tool_name}. '
                               f'Valid tools are: {", ".join(TOOL_CONFIGS.keys())}')

        return values

    class Config:
        schema_extra = {
            "example": {
                "target_id": "12345678-1234-5678-9012-123456789012",
                "session_name": "Comprehensive Security Assessment",
                "scan_config": {
                    "depth": "comprehensive",
                    "include_passive": True,
                    "include_active": True,
                    "include_exploitation": False
                },
                "methodology_phases": [
                    "passive_recon",
                    "active_recon",
                    "vulnerability_testing"
                ],
                "priority": 7,
                "max_duration_hours": 12,
                "tools_config": {
                    "amass": {
                        "passive_only": True,
                        "timeout": 3600
                    },
                    "nuclei": {
                        "severity": ["critical", "high", "medium"]
                    }
                }
            }
        }

class ScanSessionUpdate(BaseModel):
    """Schema for updating scan session data."""

    session_name: Optional[str] = Field(None, min_length=3, max_length=255)
    scan_config: Optional[Dict[str, Any]] = None
    methodology_phases: Optional[List[str]] = None
    priority: Optional[int] = Field(None, ge=1, le=10)
    max_duration_hours: Optional[int] = Field(None, ge=1, le=48)
    scheduled_start: Optional[datetime] = None
    tools_config: Optional[Dict[str, Dict[str, Any]]] = None

    @validator('methodology_phases')
    def validate_methodology_phases(cls, v):
        if v is not None:
            valid_phases = set(RECON_PHASES)
            invalid_phases = [phase for phase in v if phase not in valid_phases]
            if invalid_phases:
                raise ValueError(f'Invalid methodology phases: {", ".join(invalid_phases)}')
        return v

    @validator('scheduled_start')
    def validate_scheduled_start(cls, v):
        if v is not None and v <= datetime.utcnow():
            raise ValueError('Scheduled start time must be in the future')
        return v

class ScanSessionResponse(ScanBase):
    """Schema for scan session response data."""

    id: str = Field(..., description="Scan session ID")
    target_id: str = Field(..., description="Target ID")
    status: ScanStatus = Field(..., description="Current scan status")
    current_phase: Optional[str] = Field(None, description="Current execution phase")
    phase_progress: Dict[str, Any] = Field(default_factory=dict, description="Progress per phase")
    total_progress: float = Field(0.0, ge=0.0, le=100.0, description="Overall progress percentage")
    priority: int = Field(5, description="Scan priority")
    max_duration_hours: Optional[int] = Field(None, description="Maximum duration in hours")
    started_at: Optional[datetime] = Field(None, description="Actual start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Completion timestamp")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion time")
    total_subdomains_found: int = Field(0, description="Total subdomains discovered")
    total_endpoints_found: int = Field(0, description="Total endpoints discovered")
    total_vulnerabilities: int = Field(0, description="Total vulnerabilities found")
    critical_vulnerabilities: int = Field(0, description="Critical vulnerabilities found")
    high_vulnerabilities: int = Field(0, description="High severity vulnerabilities found")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    @validator('total_progress')
    def validate_progress(cls, v):
        """Ensure progress is within valid range."""
        return max(0.0, min(100.0, v))

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": "87654321-4321-8765-4321-876543218765",
                "target_id": "12345678-1234-5678-9012-123456789012",
                "session_name": "Comprehensive Security Assessment",
                "status": "running",
                "current_phase": "active_recon",
                "phase_progress": {
                    "passive_recon": 100.0,
                    "active_recon": 45.0,
                    "vulnerability_testing": 0.0
                },
                "total_progress": 48.3,
                "priority": 7,
                "max_duration_hours": 12,
                "started_at": "2024-01-15T10:00:00Z",
                "estimated_completion": "2024-01-15T22:00:00Z",
                "total_subdomains_found": 23,
                "total_endpoints_found": 147,
                "total_vulnerabilities": 8,
                "critical_vulnerabilities": 1,
                "high_vulnerabilities": 3,
                "created_at": "2024-01-15T09:45:00Z",
                "updated_at": "2024-01-15T12:30:00Z"
            }
        }

class ScanSessionListResponse(BaseModel):
    """Schema for paginated scan session list response."""

    scan_sessions: List[ScanSessionResponse] = Field(..., description="List of scan sessions")
    pagination: Dict[str, Any] = Field(..., description="Pagination metadata")
    status_counts: Dict[str, int] = Field(default_factory=dict, description="Count by status")
    applied_filters: Dict[str, Any] = Field(default_factory=dict, description="Applied filters")

    class Config:
        schema_extra = {
            "example": {
                "scan_sessions": [],
                "pagination": {
                    "count": 45,
                    "total_pages": 3,
                    "current_page": 1,
                    "page_size": 15,
                    "has_next": True,
                    "has_previous": False
                },
                "status_counts": {
                    "queued": 5,
                    "running": 3,
                    "paused": 1,
                    "completed": 32,
                    "failed": 3,
                    "cancelled": 1
                },
                "applied_filters": {
                    "status": "running"
                }
            }
        }

class ScanConfiguration(BaseModel):
    """Schema for detailed scan configuration."""

    target_id: str = Field(..., description="Target ID")
    phases: List[str] = Field(..., description="Scan phases to execute")
    tools: List[str] = Field(..., description="Tools to use in scan")
    tool_configurations: Dict[str, Dict[str, Any]] = Field(..., description="Per-tool configurations")
    rate_limiting: Dict[str, Union[float, int]] = Field(..., description="Rate limiting settings")
    timeout_settings: Dict[str, int] = Field(..., description="Timeout configurations")
    output_settings: Dict[str, Any] = Field(..., description="Output and logging settings")
    advanced_options: Dict[str, Any] = Field(default_factory=dict, description="Advanced scan options")

    class Config:
        schema_extra = {
            "example": {
                "target_id": "12345678-1234-5678-9012-123456789012",
                "phases": ["passive_recon", "active_recon", "vulnerability_testing"],
                "tools": ["amass", "subfinder", "httpx", "nuclei"],
                "tool_configurations": {
                    "amass": {
                        "passive": True,
                        "brute": False,
                        "timeout": 3600
                    },
                    "nuclei": {
                        "severity": ["critical", "high"],
                        "exclude_tags": ["dos", "intrusive"]
                    }
                },
                "rate_limiting": {
                    "requests_per_second": 5.0,
                    "concurrent_requests": 10
                },
                "timeout_settings": {
                    "tool_timeout": 3600,
                    "phase_timeout": 7200
                },
                "output_settings": {
                    "format": "json",
                    "verbose": True,
                    "save_raw_output": True
                }
            }
        }

class ScanProgress(BaseModel):
    """Schema for real-time scan progress information."""

    scan_session_id: str = Field(..., description="Scan session ID")
    overall_progress: float = Field(..., ge=0.0, le=100.0, description="Overall progress percentage")
    current_phase: Optional[str] = Field(None, description="Currently executing phase")
    phase_progress: Dict[str, float] = Field(default_factory=dict, description="Progress per phase")
    active_tools: List[str] = Field(default_factory=list, description="Currently running tools")
    completed_tools: List[str] = Field(default_factory=list, description="Completed tools")
    failed_tools: List[str] = Field(default_factory=list, description="Failed tools")
    estimated_time_remaining: Optional[int] = Field(None, description="Estimated time remaining in seconds")
    resources_discovered: Dict[str, int] = Field(default_factory=dict, description="Resources discovered so far")
    recent_findings: List[str] = Field(default_factory=list, description="Recent significant findings")
    last_updated: datetime = Field(default_factory=datetime.utcnow, description="Last progress update")

    class Config:
        schema_extra = {
            "example": {
                "scan_session_id": "87654321-4321-8765-4321-876543218765",
                "overall_progress": 65.5,
                "current_phase": "vulnerability_testing",
                "phase_progress": {
                    "passive_recon": 100.0,
                    "active_recon": 100.0,
                    "vulnerability_testing": 32.5
                },
                "active_tools": ["nuclei"],
                "completed_tools": ["amass", "subfinder", "httpx"],
                "failed_tools": [],
                "estimated_time_remaining": 4320,
                "resources_discovered": {
                    "subdomains": 45,
                    "endpoints": 234,
                    "vulnerabilities": 12
                },
                "recent_findings": [
                    "High severity SQL injection found in login form",
                    "Subdomain takeover vulnerability detected"
                ],
                "last_updated": "2024-01-15T14:30:00Z"
            }
        }

class ToolExecutionBase(BaseModel):
    """Base schema for tool execution data."""

    tool_name: str = Field(..., description="Name of the tool")
    tool_category: str = Field(..., description="Tool category")
    command_executed: str = Field(..., description="Command that was executed")
    tool_parameters: Dict[str, Any] = Field(default_factory=dict, description="Tool parameters")

class ToolExecutionResponse(ToolExecutionBase):
    """Schema for tool execution response data."""

    id: str = Field(..., description="Tool execution ID")
    scan_session_id: str = Field(..., description="Parent scan session ID")
    status: ToolStatus = Field(..., description="Tool execution status")
    started_at: Optional[datetime] = Field(None, description="Start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Completion timestamp")
    execution_time_seconds: Optional[float] = Field(None, description="Execution duration")
    output_file_path: Optional[str] = Field(None, description="Path to output file")
    parsed_results_count: int = Field(0, description="Number of parsed results")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    exit_code: Optional[int] = Field(None, description="Process exit code")
    created_at: datetime = Field(..., description="Creation timestamp")

    class Config:
        orm_mode = True
        schema_extra = {
            "example": {
                "id": "tool-12345678-1234-5678-9012-123456789012",
                "scan_session_id": "87654321-4321-8765-4321-876543218765",
                "tool_name": "nuclei",
                "tool_category": "vulnerability_scanning",
                "command_executed": "nuclei -u https://example.com -severity critical,high -json",
                "status": "completed",
                "started_at": "2024-01-15T12:00:00Z",
                "completed_at": "2024-01-15T12:45:00Z",
                "execution_time_seconds": 2700.5,
                "output_file_path": "/app/scan_results/nuclei_output_20240115.json",
                "parsed_results_count": 8,
                "error_message": None,
                "exit_code": 0,
                "created_at": "2024-01-15T12:00:00Z"
            }
        }

class ScanResults(BaseModel):
    """Schema for comprehensive scan results."""

    scan_session_id: str = Field(..., description="Scan session ID")
    target_name: str = Field(..., description="Target name")
    scan_duration_seconds: Optional[float] = Field(None, description="Total scan duration")
    phases_completed: List[str] = Field(default_factory=list, description="Completed phases")
    tools_executed: List[str] = Field(default_factory=list, description="Tools that were executed")

    # Discovery results
    subdomains_discovered: int = Field(0, description="Total subdomains discovered")
    endpoints_discovered: int = Field(0, description="Total endpoints discovered")
    services_discovered: int = Field(0, description="Total services discovered")
    technologies_identified: List[str] = Field(default_factory=list, description="Identified technologies")

    # Vulnerability results
    vulnerabilities_found: int = Field(0, description="Total vulnerabilities found")
    vulnerability_breakdown: Dict[str, int] = Field(default_factory=dict, description="Vulnerabilities by severity")
    top_vulnerability_types: List[Dict[str, Union[str, int]]] = Field(default_factory=list, description="Most common vulnerability types")

    # Tool results summary
    tool_results: List[Dict[str, Any]] = Field(default_factory=list, description="Per-tool result summaries")
    successful_tools: List[str] = Field(default_factory=list, description="Successfully executed tools")
    failed_tools: List[str] = Field(default_factory=list, description="Failed tool executions")

    # File paths
    raw_output_files: Dict[str, str] = Field(default_factory=dict, description="Paths to raw output files")
    processed_results_file: Optional[str] = Field(None, description="Path to processed results file")

    # Metadata
    scan_completed_at: Optional[datetime] = Field(None, description="Scan completion timestamp")
    results_generated_at: datetime = Field(default_factory=datetime.utcnow, description="Results generation timestamp")

    class Config:
        schema_extra = {
            "example": {
                "scan_session_id": "87654321-4321-8765-4321-876543218765",
                "target_name": "Example Corp Bug Bounty",
                "scan_duration_seconds": 8640.2,
                "phases_completed": ["passive_recon", "active_recon", "vulnerability_testing"],
                "tools_executed": ["amass", "subfinder", "httpx", "nuclei"],
                "subdomains_discovered": 67,
                "endpoints_discovered": 342,
                "services_discovered": 15,
                "technologies_identified": ["nginx", "php", "mysql", "wordpress"],
                "vulnerabilities_found": 23,
                "vulnerability_breakdown": {
                    "critical": 2,
                    "high": 5,
                    "medium": 11,
                    "low": 5,
                    "info": 0
                },
                "top_vulnerability_types": [
                    {"type": "xss_reflected", "count": 7},
                    {"type": "sql_injection", "count": 3},
                    {"type": "csrf", "count": 2}
                ],
                "successful_tools": ["amass", "subfinder", "httpx", "nuclei"],
                "failed_tools": [],
                "raw_output_files": {
                    "amass": "/app/scan_results/amass_20240115.txt",
                    "nuclei": "/app/scan_results/nuclei_20240115.json"
                },
                "scan_completed_at": "2024-01-15T16:30:00Z"
            }
        }

class ScanFilter(BaseModel):
    """Schema for scan filtering options."""

    statuses: Optional[List[ScanStatus]] = Field(None, description="Filter by scan statuses")
    target_ids: Optional[List[str]] = Field(None, description="Filter by target IDs")
    created_after: Optional[datetime] = Field(None, description="Created after date")
    created_before: Optional[datetime] = Field(None, description="Created before date")
    completed_after: Optional[datetime] = Field(None, description="Completed after date")
    completed_before: Optional[datetime] = Field(None, description="Completed before date")
    min_duration_hours: Optional[float] = Field(None, ge=0.0, description="Minimum duration in hours")
    max_duration_hours: Optional[float] = Field(None, ge=0.0, description="Maximum duration in hours")
    min_vulnerabilities: Optional[int] = Field(None, ge=0, description="Minimum vulnerabilities found")
    max_vulnerabilities: Optional[int] = Field(None, ge=0, description="Maximum vulnerabilities found")
    phases: Optional[List[str]] = Field(None, description="Filter by methodology phases")
    tools: Optional[List[str]] = Field(None, description="Filter by tools used")
    priority_range: Optional[List[int]] = Field(None, min_items=2, max_items=2, description="Priority range [min, max]")

    @validator('priority_range')
    def validate_priority_range(cls, v):
        if v is not None:
            if len(v) != 2:
                raise ValueError('Priority range must contain exactly 2 values [min, max]')
            if v[0] > v[1]:
                raise ValueError('Priority range minimum must be <= maximum')
            if not all(1 <= p <= 10 for p in v):
                raise ValueError('Priority values must be between 1 and 10')
        return v

    @root_validator
    def validate_date_ranges(cls, values):
        """Validate date range consistency."""
        created_after = values.get('created_after')
        created_before = values.get('created_before')
        completed_after = values.get('completed_after')
        completed_before = values.get('completed_before')

        if created_after and created_before and created_after > created_before:
            raise ValueError('created_after must be before created_before')

        if completed_after and completed_before and completed_after > completed_before:
            raise ValueError('completed_after must be before completed_before')

        return values

class ScanStatistics(BaseModel):
    """Schema for scan statistics."""

    total_scans: int = Field(..., ge=0, description="Total number of scans")
    recent_scans: int = Field(..., ge=0, description="Recent scans count")
    status_distribution: Dict[str, int] = Field(..., description="Distribution by status")
    average_duration_seconds: float = Field(..., ge=0.0, description="Average scan duration")
    success_rate: float = Field(..., ge=0.0, le=100.0, description="Success rate percentage")
    most_productive_tools: List[Dict[str, Union[str, int]]] = Field(default_factory=list, description="Most productive tools")
    vulnerability_discovery_rate: float = Field(0.0, ge=0.0, description="Average vulnerabilities per scan")

    class Config:
        schema_extra = {
            "example": {
                "total_scans": 152,
                "recent_scans": 23,
                "status_distribution": {
                    "queued": 5,
                    "running": 3,
                    "completed": 135,
                    "failed": 7,
                    "cancelled": 2
                },
                "average_duration_seconds": 7245.6,
                "success_rate": 88.8,
                "most_productive_tools": [
                    {"tool": "nuclei", "vulnerabilities_found": 234},
                    {"tool": "sqlmap", "vulnerabilities_found": 67}
                ],
                "vulnerability_discovery_rate": 15.6
            }
        }

class ScanTrends(BaseModel):
    """Schema for scan trends analysis."""

    period: Dict[str, Union[str, int]] = Field(..., description="Analysis period information")
    daily_scans: List[Dict[str, Union[str, int]]] = Field(..., description="Daily scan counts")
    status_trends: List[Dict[str, Union[str, int]]] = Field(..., description="Status trends over time")
    duration_trends: List[Dict[str, Union[str, float]]] = Field(..., description="Duration trends over time")
    vulnerability_discovery_trends: List[Dict[str, Union[str, int]]] = Field(..., description="Vulnerability discovery trends")

class BulkScanOperation(BaseModel):
    """Schema for bulk operations on scan sessions."""

    scan_session_ids: List[str] = Field(..., min_items=1, description="List of scan session IDs")
    operation: str = Field(..., regex=r'^(start|pause|resume|stop|delete|update_priority)', description="Operation to perform")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Operation-specific parameters")

    class Config:
        schema_extra = {
            "example": {
                "scan_session_ids": [
                    "87654321-4321-8765-4321-876543218765",
                    "12345678-1234-5678-9012-123456789012"
                ],
                "operation": "update_priority",
                "parameters": {
                    "priority": 8
                }
            }
        }

class ScanTemplate(BaseModel):
    """Schema for scan templates."""

    template_name: str = Field(..., min_length=3, max_length=100, description="Template name")
    description: str = Field(..., min_length=10, max_length=500, description="Template description")
    methodology_phases: List[str] = Field(..., description="Methodology phases")
    tools_config: Dict[str, Dict[str, Any]] = Field(..., description="Tool configurations")
    default_priority: int = Field(5, ge=1, le=10, description="Default priority")
    estimated_duration_hours: Optional[float] = Field(None, ge=0.1, description="Estimated duration")
    suitable_for: List[str] = Field(default_factory=list, description="Suitable target types")
    created_by: str = Field(..., description="Template creator")
    is_public: bool = Field(False, description="Whether template is publicly available")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")
    updated_at: datetime = Field(default_factory=datetime.utcnow, description="Last update timestamp")

    class Config:
        schema_extra = {
            "example": {
                "template_name": "Comprehensive Web App Scan",
                "description": "Full-scope web application security assessment including OWASP Top 10",
                "methodology_phases": ["passive_recon", "active_recon", "vulnerability_testing"],
                "tools_config": {
                    "amass": {"passive": True, "timeout": 3600},
                    "nuclei": {"severity": ["critical", "high", "medium"]}
                },
                "default_priority": 7,
                "estimated_duration_hours": 4.5,
                "suitable_for": ["web_application", "api", "saas"],
                "created_by": "security_team",
                "is_public": True
            }
        }

class ScanSchedule(BaseModel):
    """Schema for scheduled scans."""

    schedule_name: str = Field(..., min_length=3, max_length=100, description="Schedule name")
    target_id: str = Field(..., description="Target ID to scan")
    scan_template: str = Field(..., description="Scan template to use")
    cron_expression: str = Field(..., description="Cron expression for scheduling")
    is_active: bool = Field(True, description="Whether schedule is active")
    max_concurrent: int = Field(1, ge=1, le=5, description="Maximum concurrent scans")
    next_run: Optional[datetime] = Field(None, description="Next scheduled run")
    last_run: Optional[datetime] = Field(None, description="Last execution time")
    total_runs: int = Field(0, ge=0, description="Total number of executions")
    successful_runs: int = Field(0, ge=0, description="Successful executions")
    created_by: str = Field(..., description="Schedule creator")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Creation timestamp")

    @validator('cron_expression')
    def validate_cron_expression(cls, v):
        """Basic cron expression validation."""
        parts = v.split()
        if len(parts) != 5:
            raise ValueError('Cron expression must have 5 parts (minute hour day month weekday)')
        return v

class ScanExport(BaseModel):
    """Schema for scan export data."""

    scan_sessions: List[ScanSessionResponse] = Field(..., description="Scan sessions to export")
    export_format: str = Field(..., regex=r'^(csv|json|xml)', description="Export format")
    include_results: bool = Field(False, description="Include detailed scan results")
    include_tool_outputs: bool = Field(False, description="Include tool output files")
    filters: Dict[str, Any] = Field(default_factory=dict, description="Applied filters")
    generated_at: datetime = Field(default_factory=datetime.utcnow, description="Export generation timestamp")
    generated_by: str = Field(..., description="User who generated the export")

class ScanValidation(BaseModel):
    """Schema for scan validation results."""

    is_valid: bool = Field(..., description="Overall validation result")
    validation_errors: List[str] = Field(default_factory=list, description="Validation error messages")
    validation_warnings: List[str] = Field(default_factory=list, description="Validation warnings")
    configuration_issues: List[str] = Field(default_factory=list, description="Configuration issues")
    resource_requirements: Dict[str, Any] = Field(default_factory=dict, description="Estimated resource requirements")
    estimated_duration: Optional[timedelta] = Field(None, description="Estimated scan duration")
    recommendations: List[str] = Field(default_factory=list, description="Optimization recommendations")

class ScanMetrics(BaseModel):
    """Schema for detailed scan metrics."""

    scan_session_id: str = Field(..., description="Scan session ID")
    cpu_usage_percent: float = Field(0.0, ge=0.0, le=100.0, description="CPU usage percentage")
    memory_usage_mb: float = Field(0.0, ge=0.0, description="Memory usage in MB")
    disk_usage_mb: float = Field(0.0, ge=0.0, description="Disk usage in MB")
    network_requests_sent: int = Field(0, ge=0, description="Total network requests sent")
    network_bytes_received: int = Field(0, ge=0, description="Total bytes received")
    active_connections: int = Field(0, ge=0, description="Active network connections")
    tool_performance: Dict[str, Dict[str, float]] = Field(default_factory=dict, description="Per-tool performance metrics")
    bottlenecks: List[str] = Field(default_factory=list, description="Identified performance bottlenecks")
    measured_at: datetime = Field(default_factory=datetime.utcnow, description="Measurement timestamp")

# Export all schemas
__all__ = [
    "ScanBase",
    "ScanSessionCreate",
    "ScanSessionUpdate",
    "ScanSessionResponse",
    "ScanSessionListResponse",
    "ScanConfiguration",
    "ScanProgress",
    "ToolExecutionBase",
    "ToolExecutionResponse",
    "ScanResults",
    "ScanFilter",
    "ScanStatistics",
    "ScanTrends",
    "BulkScanOperation",
    "ScanTemplate",
    "ScanSchedule",
    "ScanExport",
    "ScanValidation",
    "ScanMetrics",
    "ScanQueryFilters",
]

class ScanQueryFilters(BaseModel):
    """Query filters for scan session listing."""
    
    page: int = Field(1, ge=1, description="Page number")
    page_size: int = Field(20, ge=1, le=100, description="Items per page")
    status: Optional[str] = Field(None, description="Filter by scan status")
    target_id: Optional[str] = Field(None, description="Filter by target ID")
    scan_type: Optional[str] = Field(None, description="Filter by scan type")
    created_by: Optional[str] = Field(None, description="Filter by creator")
    search: Optional[str] = Field(None, description="Search in scan names")
    sort_by: str = Field("created_at", description="Sort field")
    sort_order: str = Field("desc", regex=r'^(asc|desc)$', description="Sort order")
