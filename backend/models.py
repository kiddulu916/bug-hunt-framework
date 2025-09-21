"""
Centralized SQLAlchemy Models for Bug Bounty Automation Platform
This module provides SQLAlchemy models that mirror Django models for FastAPI services
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any

from sqlalchemy import (
    Column, String, Text, DateTime, Boolean, JSON, Integer, Float,
    ForeignKey, Enum as SQLEnum, ARRAY
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship

# Base class for all models
Base = declarative_base()


# Enums
class BugBountyPlatform(str, Enum):
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    SYNACK = "synack"
    YESWEHACK = "yeswehack"
    PRIVATE = "private"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ToolStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class VulnSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ExploitationDifficulty(str, Enum):
    EASY = "easy"
    MEDIUM = "medium"
    HARD = "hard"
    UNKNOWN = "unknown"


class RemediationPriority(str, Enum):
    IMMEDIATE = "immediate"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO_ONLY = "info_only"


class ReconResultType(str, Enum):
    SUBDOMAIN = "subdomain"
    ENDPOINT = "endpoint"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    EMAIL = "email"
    IP_ADDRESS = "ip_address"
    PORT = "port"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"


class DiscoveryMethod(str, Enum):
    DNS_ENUM = "dns_enum"
    PORT_SCAN = "port_scan"
    WEB_CRAWLING = "web_crawling"
    CERTIFICATE_TRANSPARENCY = "cert_transparency"
    SEARCH_ENGINE = "search_engine"
    SOCIAL_MEDIA = "social_media"
    CODE_REPOSITORY = "code_repository"
    ARCHIVE_SEARCH = "archive_search"


# Models
class Target(Base):
    """Target company and bug bounty program information"""
    __tablename__ = "targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_name = Column(String(255), unique=True, nullable=False)
    platform = Column(SQLEnum(BugBountyPlatform), nullable=False)
    researcher_username = Column(String(100), nullable=False)
    main_url = Column(String(500), nullable=False)
    wildcard_url = Column(String(500), nullable=True)

    # Scope Management (stored as JSON arrays)
    in_scope_urls = Column(JSON, default=list)
    out_of_scope_urls = Column(JSON, default=list)
    in_scope_assets = Column(JSON, default=list)
    out_of_scope_assets = Column(JSON, default=list)

    # Rate Limiting & Request Configuration
    requests_per_second = Column(Float, default=5.0)
    concurrent_requests = Column(Integer, default=10)
    request_delay_ms = Column(Integer, default=200)

    # HTTP Configuration
    required_headers = Column(JSON, default=dict)
    authentication_headers = Column(JSON, default=dict)
    user_agents = Column(JSON, default=list)

    # Program Specific Notes
    program_notes = Column(Text, default="")
    special_requirements = Column(Text, default="")
    pii_redaction_rules = Column(JSON, default=dict)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    is_active = Column(Boolean, default=True)

    # Relationships
    scan_sessions = relationship("ScanSession", back_populates="target")


class ScanSession(Base):
    """Individual penetration testing sessions"""
    __tablename__ = "scan_sessions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id"), nullable=False)

    session_name = Column(String(255), nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.QUEUED)

    # Scan Configuration
    scan_config = Column(JSON, default=dict)
    methodology_phases = Column(JSON, default=list)

    # Progress Tracking
    current_phase = Column(String(50), nullable=True)
    phase_progress = Column(JSON, default=dict)
    total_progress = Column(Float, default=0.0)

    # Timing
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    estimated_completion = Column(DateTime, nullable=True)

    # Results Summary
    total_subdomains_found = Column(Integer, default=0)
    total_endpoints_found = Column(Integer, default=0)
    total_vulnerabilities = Column(Integer, default=0)
    critical_vulnerabilities = Column(Integer, default=0)
    high_vulnerabilities = Column(Integer, default=0)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    target = relationship("Target", back_populates="scan_sessions")
    recon_results = relationship("ReconResult", back_populates="scan_session")
    vulnerabilities = relationship("Vulnerability", back_populates="scan_session")
    tool_executions = relationship("ToolExecution", back_populates="scan_session")


class ReconResult(Base):
    """Reconnaissance results from passive and active discovery"""
    __tablename__ = "recon_results"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_session_id = Column(UUID(as_uuid=True), ForeignKey("scan_sessions.id"), nullable=False)

    # Discovery Information
    result_type = Column(SQLEnum(ReconResultType), nullable=False)
    discovered_asset = Column(String(1000), nullable=False)

    # Asset Details
    ip_address = Column(String(45), nullable=True)  # Support IPv6
    port = Column(Integer, nullable=True)
    protocol = Column(String(20), nullable=True)
    service_name = Column(String(100), nullable=True)
    service_version = Column(String(200), nullable=True)

    # HTTP Specific Details
    status_code = Column(Integer, nullable=True)
    response_size = Column(Integer, nullable=True)
    title = Column(String(500), nullable=True)
    technologies = Column(JSON, default=list)

    # Discovery Source
    discovered_by_tool = Column(String(100), nullable=False)
    discovery_method = Column(SQLEnum(DiscoveryMethod), nullable=False)
    confidence_score = Column(Float, default=0.0)

    # Scope Validation
    is_in_scope = Column(Boolean, nullable=True)
    scope_validation_reason = Column(String(500), nullable=True)

    # Additional Data
    headers = Column(JSON, default=dict)
    additional_info = Column(JSON, default=dict)

    # Metadata
    discovered_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan_session = relationship("ScanSession", back_populates="recon_results")


class Vulnerability(Base):
    """Discovered vulnerabilities and security issues"""
    __tablename__ = "vulnerabilities"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_session_id = Column(UUID(as_uuid=True), ForeignKey("scan_sessions.id"), nullable=False)

    # Vulnerability Classification
    vulnerability_name = Column(String(255), nullable=False)
    vulnerability_type = Column(String(100), nullable=False)
    owasp_category = Column(String(50), nullable=True)
    cwe_id = Column(String(20), nullable=True)

    # Severity and Impact
    severity = Column(SQLEnum(VulnSeverity), nullable=False)
    cvss_score = Column(Float, nullable=True)
    impact_description = Column(Text, nullable=False)

    # Location Information
    affected_url = Column(String(1000), nullable=False)
    affected_parameter = Column(String(255), nullable=True)
    http_method = Column(String(10), nullable=True)

    # Technical Details
    payload_used = Column(Text, nullable=True)
    request_data = Column(Text, nullable=True)
    response_data = Column(Text, nullable=True)

    # Discovery Information
    discovered_by_tool = Column(String(100), nullable=False)
    discovery_method = Column(String(200), nullable=False)
    confidence_level = Column(Float, default=0.0)
    false_positive_likelihood = Column(Float, default=0.0)

    # Evidence
    screenshot_paths = Column(JSON, default=list)
    additional_evidence = Column(JSON, default=dict)

    # Exploitation Details
    is_exploitable = Column(Boolean, default=False)
    exploitation_difficulty = Column(SQLEnum(ExploitationDifficulty), nullable=True)
    exploitation_notes = Column(Text, nullable=True)

    # Remediation
    remediation_suggestion = Column(Text, nullable=True)
    remediation_priority = Column(SQLEnum(RemediationPriority), nullable=True)

    # Validation Status
    manually_verified = Column(Boolean, default=False)
    verification_notes = Column(Text, nullable=True)

    # Metadata
    discovered_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scan_session = relationship("ScanSession", back_populates="vulnerabilities")
    exploitation_chains = relationship("ExploitationChain", back_populates="vulnerability")


class ExploitationChain(Base):
    """Vulnerability chains for maximum impact exploitation"""
    __tablename__ = "exploitation_chains"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id"), nullable=False)

    chain_name = Column(String(255), nullable=False)
    chain_description = Column(Text, nullable=False)

    # Chain Details
    step_number = Column(Integer, nullable=False)
    total_steps = Column(Integer, nullable=False)

    # Exploitation Step
    step_description = Column(Text, nullable=False)
    payload = Column(Text, nullable=True)
    expected_result = Column(Text, nullable=True)
    actual_result = Column(Text, nullable=True)

    # Evidence
    screenshot_path = Column(String(500), nullable=True)
    request_response_log = Column(Text, nullable=True)

    # Success Tracking
    step_successful = Column(Boolean, default=False)
    chain_successful = Column(Boolean, default=False)

    # Impact Assessment
    impact_increase = Column(String(50), nullable=True)
    final_impact_description = Column(Text, nullable=True)

    # Metadata
    executed_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="exploitation_chains")


class ToolExecution(Base):
    """Track individual tool execution within scan sessions"""
    __tablename__ = "tool_executions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_session_id = Column(UUID(as_uuid=True), ForeignKey("scan_sessions.id"), nullable=False)

    tool_name = Column(String(100), nullable=False)
    tool_category = Column(String(50), nullable=False)
    command_executed = Column(Text, nullable=False)

    status = Column(SQLEnum(ToolStatus), default=ToolStatus.PENDING)

    # Execution Details
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    execution_time_seconds = Column(Float, nullable=True)

    # Results
    output_file_path = Column(String(500), nullable=True)
    raw_output = Column(Text, nullable=True)
    parsed_results_count = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)

    # Configuration
    tool_parameters = Column(JSON, default=dict)

    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    scan_session = relationship("ScanSession", back_populates="tool_executions")


class User(Base):
    """User accounts for authentication"""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(150), unique=True, nullable=False)
    email = Column(String(254), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)

    # Profile
    first_name = Column(String(150), nullable=True)
    last_name = Column(String(150), nullable=True)

    # Permissions
    is_active = Column(Boolean, default=True)
    is_staff = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)
    permissions = Column(JSON, default=list)
    roles = Column(JSON, default=list)

    # Security
    last_login = Column(DateTime, nullable=True)
    failed_login_attempts = Column(Integer, default=0)
    account_locked_until = Column(DateTime, nullable=True)

    # Metadata
    date_joined = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Report(Base):
    """Generated reports for vulnerability assessments"""
    __tablename__ = "reports"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_session_id = Column(UUID(as_uuid=True), ForeignKey("scan_sessions.id"), nullable=False)

    report_name = Column(String(255), nullable=False)
    report_type = Column(String(50), nullable=False)  # executive, technical, compliance
    format = Column(String(20), nullable=False)  # pdf, html, json, csv

    # Report Content
    executive_summary = Column(Text, nullable=True)
    methodology = Column(Text, nullable=True)
    findings_summary = Column(JSON, default=dict)

    # File Information
    file_path = Column(String(500), nullable=True)
    file_size = Column(Integer, nullable=True)

    # Report Configuration
    template_used = Column(String(100), nullable=True)
    include_screenshots = Column(Boolean, default=True)
    include_raw_data = Column(Boolean, default=False)

    # Status
    generation_status = Column(String(20), default="pending")  # pending, generating, completed, failed
    error_message = Column(Text, nullable=True)

    # Metadata
    generated_at = Column(DateTime, default=datetime.utcnow)
    generated_by = Column(String(150), nullable=True)

    # Relationships
    scan_session = relationship("ScanSession")


# Export all models and enums for easy importing
__all__ = [
    "Base",
    "BugBountyPlatform",
    "ScanStatus",
    "ToolStatus",
    "VulnSeverity",
    "ExploitationDifficulty",
    "RemediationPriority",
    "ReconResultType",
    "DiscoveryMethod",
    "Target",
    "ScanSession",
    "ReconResult",
    "Vulnerability",
    "ExploitationChain",
    "ToolExecution",
    "User",
    "Report"
]