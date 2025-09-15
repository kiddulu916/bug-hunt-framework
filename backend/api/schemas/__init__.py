"""
Pydantic schemas initialization.
This module imports and exposes all API schemas for data validation and serialization.
"""

# Import all schema modules
from . import vulnerability, target, scan, report, common

# Import commonly used schemas for easy access
from .common import (
    PaginationMeta,
    PaginatedResponse,
    StatusResponse,
    ErrorResponse,
    HealthCheckResponse,
    SearchFilter,
    BulkOperationRequest,
    BulkOperationResponse,
    FileUploadResponse,
    ExportRequest,
    ExportResponse,
    ValidationResult,
    TimeRange,
)

from .vulnerability import (
    VulnerabilityCreate,
    VulnerabilityUpdate,
    VulnerabilityResponse,
    VulnerabilityListResponse,
    VulnerabilityAnalysis,
    BulkVulnerabilityOperation,
    VulnerabilityExport,
    VulnerabilityFilter,
    ExploitationChain,
    VulnerabilityStatistics,
    VulnerabilityTrends,
)

from .target import (
    TargetCreate,
    TargetUpdate,
    TargetResponse,
    TargetListResponse,
    ScopeValidation,
    TargetConfiguration,
    ConnectivityTest,
    TargetStatistics,
    TargetFilter,
    BulkTargetOperation,
    TargetExport,
)

from .scan import (
    ScanSessionCreate,
    ScanSessionUpdate,
    ScanSessionResponse,
    ScanSessionListResponse,
    ScanConfiguration,
    ScanProgress,
    ToolExecutionResponse,
    ScanResults,
    ScanFilter,
    ScanStatistics,
    ScanTrends,
    BulkScanOperation,
    ScanTemplate,
    ScanExport,
)

from .report import (
    ReportCreate,
    ReportUpdate,
    ReportResponse,
    ReportListResponse,
    ReportGeneration,
    ReportTemplate,
    ReportExport,
    ReportFilter,
    ReportStatistics,
    ReportTrends,
    BulkReportOperation,
)

# Export all imported schemas
__all__ = [
    # Common schemas
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
    "ValidationResult",
    "TimeRange",
    
    # Vulnerability schemas
    "VulnerabilityCreate",
    "VulnerabilityUpdate",
    "VulnerabilityResponse",
    "VulnerabilityListResponse",
    "VulnerabilityAnalysis",
    "BulkVulnerabilityOperation",
    "VulnerabilityExport",
    "VulnerabilityFilter",
    "ExploitationChain",
    "VulnerabilityStatistics",
    "VulnerabilityTrends",
    
    # Target schemas
    "TargetCreate",
    "TargetUpdate",
    "TargetResponse",
    "TargetListResponse",
    "ScopeValidation",
    "TargetConfiguration",
    "ConnectivityTest",
    "TargetStatistics",
    "TargetFilter",
    "BulkTargetOperation",
    "TargetExport",
    
    # Scan schemas
    "ScanSessionCreate",
    "ScanSessionUpdate",
    "ScanSessionResponse",
    "ScanSessionListResponse",
    "ScanConfiguration",
    "ScanProgress",
    "ToolExecutionResponse",
    "ScanResults",
    "ScanFilter",
    "ScanStatistics",
    "ScanTrends",
    "BulkScanOperation",
    "ScanTemplate",
    "ScanExport",
    
    # Report schemas
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
    
    # Schema modules for direct import
    "vulnerability",
    "target",
    "scan",
    "report",
    "common",
]