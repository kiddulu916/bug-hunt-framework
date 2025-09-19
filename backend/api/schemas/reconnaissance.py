"""
Pydantic schemas for reconnaissance API endpoints
"""

from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, validator
from uuid import UUID


class ReconConfigSchema(BaseModel):
    """Configuration schema for reconnaissance operations"""
    passive_only: bool = Field(False, description="Only perform passive reconnaissance")
    max_subdomains: int = Field(1000, ge=1, le=10000, description="Maximum subdomains to discover")
    max_endpoints: int = Field(5000, ge=1, le=50000, description="Maximum endpoints to discover")
    port_scan_top_ports: int = Field(1000, ge=1, le=65535, description="Number of top ports to scan")
    enable_service_detection: bool = Field(True, description="Enable service detection on open ports")
    enable_technology_detection: bool = Field(True, description="Enable web technology detection")
    enable_certificate_transparency: bool = Field(True, description="Enable certificate transparency search")
    enable_search_engines: bool = Field(True, description="Enable search engine dorking")
    enable_web_crawling: bool = Field(True, description="Enable web crawling for endpoint discovery")
    crawl_depth: int = Field(3, ge=1, le=10, description="Maximum crawling depth")
    wordlist_size: str = Field("medium", description="Wordlist size for brute force")
    timeout_seconds: int = Field(30, ge=5, le=300, description="Operation timeout in seconds")
    
    @validator('wordlist_size')
    def validate_wordlist_size(cls, v):
        if v not in ['small', 'medium', 'large']:
            raise ValueError('wordlist_size must be one of: small, medium, large')
        return v


class ReconResultSchema(BaseModel):
    """Schema for reconnaissance results"""
    id: str
    result_type: str
    discovered_asset: str
    ip_address: Optional[str] = None
    port: Optional[int] = None
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    technologies: List[str] = []
    discovered_by_tool: str
    discovery_method: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    is_in_scope: Optional[bool] = None
    scope_validation_reason: Optional[str] = None
    discovered_at: str
    additional_info: Dict[str, Any] = {}
    
    class Config:
        from_attributes = True


class ReconResultCreate(BaseModel):
    """Schema for creating reconnaissance results"""
    result_type: str
    discovered_asset: str
    ip_address: Optional[str] = None
    port: Optional[int] = None
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    technologies: List[str] = []
    discovered_by_tool: str
    discovery_method: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    additional_info: Dict[str, Any] = {}


class ReconResultUpdate(BaseModel):
    """Schema for updating reconnaissance results"""
    is_in_scope: Optional[bool] = None
    scope_validation_reason: Optional[str] = None
    confidence_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    additional_info: Optional[Dict[str, Any]] = None


class ReconStatisticsSchema(BaseModel):
    """Schema for reconnaissance statistics"""
    total_discovered: int
    in_scope: int
    out_of_scope: int
    by_type: Dict[str, int]
    by_tool: Dict[str, int]
    by_method: Dict[str, int]
    high_confidence: int


class SubdomainResultSchema(BaseModel):
    """Schema for subdomain discovery results"""
    subdomain: str
    ip_address: Optional[str] = None
    discovered_by: str
    discovery_method: str
    confidence_score: float
    discovered_at: str
    is_in_scope: bool


class EndpointResultSchema(BaseModel):
    """Schema for endpoint discovery results"""
    url: str
    discovery_method: str
    discovered_by: str
    confidence_score: float
    discovered_at: str
    additional_info: Dict[str, Any] = {}
    is_in_scope: bool


class ServiceResultSchema(BaseModel):
    """Schema for service discovery results"""
    host: str
    port: int
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    discovered_by: str
    discovery_method: str
    confidence_score: float
    discovered_at: str
    additional_info: Dict[str, Any] = {}
    is_in_scope: bool


class TechnologyResultSchema(BaseModel):
    """Schema for technology detection results"""
    url: str
    technologies: List[Dict[str, Any]]
    discovered_at: str
    is_in_scope: bool


class ReconExportRequest(BaseModel):
    """Schema for reconnaissance export requests"""
    format: str = Field("json", description="Export format")
    include_out_of_scope: bool = Field(False, description="Include out-of-scope results")
    result_types: Optional[List[str]] = Field(None, description="Filter by result types")
    
    @validator('format')
    def validate_format(cls, v):
        if v.lower() not in ['json', 'csv']:
            raise ValueError('format must be either json or csv')
        return v.lower()


class ReconProgressSchema(BaseModel):
    """Schema for reconnaissance progress"""
    scan_session_id: str
    current_phase: str
    phase_progress: Dict[str, float]
    total_progress: float
    subdomains_found: int
    endpoints_found: int
    services_found: int
    estimated_completion: Optional[str] = None


class ReconSummarySchema(BaseModel):
    """Schema for reconnaissance summary"""
    total_subdomains: int
    in_scope_count: int
    subdomains: List[SubdomainResultSchema]


class EndpointSummarySchema(BaseModel):
    """Schema for endpoint summary"""
    total_endpoints: int
    endpoints: List[EndpointResultSchema]


class ServiceSummarySchema(BaseModel):
    """Schema for service summary"""
    total_services: int
    services: List[ServiceResultSchema]


class TechnologySummarySchema(BaseModel):
    """Schema for technology summary"""
    total_urls: int
    technologies: List[TechnologyResultSchema]


class ReconStatusSchema(BaseModel):
    """Schema for reconnaissance status"""
    scan_session_id: str
    status: str
    current_phase: Optional[str] = None
    phase_progress: Dict[str, float] = {}
    total_progress: float = 0.0
    total_subdomains_found: int = 0
    total_endpoints_found: int = 0
    started_at: Optional[str] = None
    estimated_completion: Optional[str] = None


class ReconToolExecutionSchema(BaseModel):
    """Schema for reconnaissance tool execution"""
    tool_name: str
    tool_category: str
    command_executed: str
    status: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    execution_time_seconds: Optional[float] = None
    parsed_results_count: int = 0
    error_message: Optional[str] = None


class ReconDashboardSchema(BaseModel):
    """Schema for reconnaissance dashboard data"""
    scan_session_id: str
    target_name: str
    recon_status: ReconStatusSchema
    statistics: ReconStatisticsSchema
    recent_discoveries: List[ReconResultSchema]
    top_technologies: List[Dict[str, Any]]
    subdomain_trends: List[Dict[str, Any]]
    discovery_timeline: List[Dict[str, Any]]


class PassiveReconConfigSchema(BaseModel):
    """Schema specifically for passive reconnaissance configuration"""
    enable_certificate_transparency: bool = True
    enable_dns_enumeration: bool = True
    enable_search_engines: bool = True
    enable_osint: bool = True
    max_subdomains: int = Field(1000, ge=1, le=10000)
    timeout_seconds: int = Field(30, ge=5, le=300)


class ActiveReconConfigSchema(BaseModel):
    """Schema specifically for active reconnaissance configuration"""
    enable_dns_brute_force: bool = True
    enable_port_scanning: bool = True
    enable_service_detection: bool = True
    enable_web_crawling: bool = True
    enable_api_discovery: bool = True
    wordlist_size: str = Field("medium")
    port_scan_top_ports: int = Field(1000, ge=1, le=65535)
    crawl_depth: int = Field(3, ge=1, le=10)
    max_endpoints: int = Field(5000, ge=1, le=50000)
    timeout_seconds: int = Field(30, ge=5, le=300)
    
    @validator('wordlist_size')
    def validate_wordlist_size(cls, v):
        if v not in ['small', 'medium', 'large']:
            raise ValueError('wordlist_size must be one of: small, medium, large')
        return v


class ReconResultFilterSchema(BaseModel):
    """Schema for filtering reconnaissance results"""
    result_types: Optional[List[str]] = None
    discovery_methods: Optional[List[str]] = None
    tools: Optional[List[str]] = None
    in_scope_only: bool = True
    min_confidence: float = Field(0.0, ge=0.0, le=1.0)
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    has_ip_address: Optional[bool] = None
    has_port: Optional[bool] = None
    technologies: Optional[List[str]] = None


class BulkReconUpdateSchema(BaseModel):
    """Schema for bulk updating reconnaissance results"""
    result_ids: List[str]
    updates: ReconResultUpdate


class ReconComparisonSchema(BaseModel):
    """Schema for comparing reconnaissance results between scans"""
    base_scan_id: str
    comparison_scan_id: str
    new_discoveries: List[ReconResultSchema]
    disappeared_assets: List[ReconResultSchema]
    changed_assets: List[Dict[str, Any]]
    statistics: Dict[str, Any]


class ReconValidationSchema(BaseModel):
    """Schema for validating reconnaissance results"""
    result_id: str
    validation_status: str  # 'valid', 'invalid', 'needs_review'
    validation_notes: Optional[str] = None
    validated_by: str
    validated_at: datetime
    
    @validator('validation_status')
    def validate_status(cls, v):
        if v not in ['valid', 'invalid', 'needs_review']:
            raise ValueError('validation_status must be one of: valid, invalid, needs_review')
        return v


class ReconMetricsSchema(BaseModel):
    """Schema for reconnaissance metrics and analytics"""
    scan_session_id: str
    discovery_rate: Dict[str, float]  # discoveries per hour by type
    tool_effectiveness: Dict[str, Dict[str, Any]]  # success rate by tool
    scope_coverage: Dict[str, float]  # coverage percentage by asset type
    false_positive_rate: float
    average_confidence: float
    discovery_timeline: List[Dict[str, Any]]
    performance_metrics: Dict[str, Any]
    