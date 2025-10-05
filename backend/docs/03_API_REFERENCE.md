# API Reference

## Overview

The Bug Hunt Framework provides a RESTful API built with FastAPI, offering high-performance async endpoints for all platform operations.

## Base Information

- **Base URL**: `http://localhost:8000/api`
- **API Version**: v1
- **Documentation**: `/api/docs` (Swagger UI)
- **Alternative Docs**: `/api/redoc` (ReDoc)
- **OpenAPI Schema**: `/api/openapi.json`

## Authentication

### JWT Token Authentication

All protected endpoints require JWT authentication via the `Authorization` header.

**Header Format**:
```
Authorization: Bearer <access_token>
```

### Authentication Endpoints

#### Login
```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "secure_password"
}
```

**Response** (200 OK):
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "expires_in": 900
}
```

#### Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJ0eXAiOiJKV1QiLCJhbGc..."
}
```

**Response** (200 OK):
```json
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "bearer",
  "expires_in": 900
}
```

#### Get Current User
```http
GET /api/auth/me
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "id": 1,
  "email": "user@example.com",
  "username": "johndoe",
  "role": "security_analyst",
  "is_active": true,
  "created_at": "2025-01-15T10:30:00Z"
}
```

## Targets API

### List Targets

```http
GET /api/targets/
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `platform` (optional): Filter by platform (hackerone, bugcrowd, etc.)
- `is_active` (optional): Filter by active status (true/false)
- `search` (optional): Search in target_name, main_url
- `sort_by` (optional): Sort field (created_at, target_name)
- `order` (optional): Sort order (asc, desc)
- `page` (optional): Page number (default: 1)
- `page_size` (optional): Items per page (default: 20, max: 100)

**Response** (200 OK):
```json
{
  "items": [
    {
      "id": 1,
      "target_name": "example-program",
      "main_url": "https://example.com",
      "platform": "hackerone",
      "in_scope_urls": ["https://example.com/*", "https://api.example.com/*"],
      "out_of_scope_urls": ["https://example.com/admin/*"],
      "is_active": true,
      "rate_limit": 10,
      "created_at": "2025-01-15T10:30:00Z",
      "updated_at": "2025-01-15T10:30:00Z"
    }
  ],
  "total": 42,
  "page": 1,
  "page_size": 20,
  "total_pages": 3
}
```

### Create Target

```http
POST /api/targets/
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "target_name": "example-program",
  "main_url": "https://example.com",
  "platform": "hackerone",
  "in_scope_urls": ["https://example.com/*"],
  "out_of_scope_urls": ["https://example.com/admin/*"],
  "in_scope_assets": ["192.168.1.0/24"],
  "out_of_scope_assets": [],
  "rate_limit": 10,
  "scan_config": {
    "nuclei_templates": ["cves", "vulnerabilities"],
    "tools_enabled": ["nuclei", "httpx", "subfinder"]
  }
}
```

**Response** (201 Created):
```json
{
  "id": 1,
  "target_name": "example-program",
  "main_url": "https://example.com",
  "platform": "hackerone",
  "in_scope_urls": ["https://example.com/*"],
  "out_of_scope_urls": ["https://example.com/admin/*"],
  "is_active": true,
  "rate_limit": 10,
  "created_at": "2025-01-15T10:30:00Z"
}
```

### Get Target

```http
GET /api/targets/{target_id}
Authorization: Bearer <access_token>
```

**Response** (200 OK): Same as create response

### Update Target

```http
PUT /api/targets/{target_id}
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "target_name": "updated-name",
  "rate_limit": 15
}
```

**Response** (200 OK): Updated target object

### Delete Target

```http
DELETE /api/targets/{target_id}
Authorization: Bearer <access_token>
```

**Response** (204 No Content)

**Requires**: Admin role

### Validate Scope

```http
POST /api/targets/{target_id}/validate-scope
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "asset": "https://subdomain.example.com/api/users"
}
```

**Response** (200 OK):
```json
{
  "in_scope": true,
  "matched_rule": "https://example.com/*",
  "scope_type": "in_scope_urls"
}
```

### Test Connectivity

```http
POST /api/targets/{target_id}/test-connectivity
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "reachable": true,
  "status_code": 200,
  "response_time_ms": 245
}
```

### Get Target Statistics

```http
GET /api/targets/{target_id}/statistics
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "total_scans": 15,
  "total_vulnerabilities": 42,
  "critical_count": 2,
  "high_count": 8,
  "medium_count": 18,
  "low_count": 14,
  "last_scan_date": "2025-01-15T10:30:00Z"
}
```

## Scans API

### List Scans

```http
GET /api/scans/
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `target_id` (optional): Filter by target
- `status` (optional): Filter by status (queued, running, completed, failed)
- `workflow_type` (optional): Filter by workflow (standard, quick, deep)
- `created_by` (optional): Filter by user ID
- `page`, `page_size`: Pagination

**Response** (200 OK):
```json
{
  "items": [
    {
      "id": 1,
      "session_name": "Full Scan - Jan 2025",
      "target_id": 1,
      "target_name": "example-program",
      "status": "running",
      "workflow_type": "standard",
      "current_phase": "VULNERABILITY_TESTING",
      "progress_percentage": 65.5,
      "findings_count": 12,
      "started_at": "2025-01-15T10:00:00Z",
      "created_at": "2025-01-15T09:55:00Z"
    }
  ],
  "total": 50,
  "page": 1,
  "page_size": 20
}
```

### Create Scan

```http
POST /api/scans/
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "session_name": "Full Scan - Jan 2025",
  "target_id": 1,
  "workflow_type": "standard",
  "methodology_phases": [
    "INITIALIZATION",
    "PASSIVE_RECON",
    "ACTIVE_RECON",
    "VULNERABILITY_TESTING",
    "EXPLOITATION",
    "REPORTING",
    "CLEANUP"
  ],
  "scan_config": {
    "max_depth": 3,
    "timeout": 3600,
    "rate_limit": 10,
    "nuclei_templates": ["cves", "vulnerabilities", "misconfigurations"]
  }
}
```

**Response** (202 Accepted):
```json
{
  "id": 1,
  "session_name": "Full Scan - Jan 2025",
  "target_id": 1,
  "status": "queued",
  "workflow_type": "standard",
  "message": "Scan queued successfully. Monitor progress at /api/scans/1/progress"
}
```

### Get Scan

```http
GET /api/scans/{scan_id}
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "id": 1,
  "session_name": "Full Scan - Jan 2025",
  "target_id": 1,
  "target": {
    "id": 1,
    "target_name": "example-program",
    "main_url": "https://example.com"
  },
  "status": "completed",
  "workflow_type": "standard",
  "current_phase": "CLEANUP",
  "progress_percentage": 100.0,
  "findings_count": 42,
  "critical_count": 2,
  "high_count": 8,
  "medium_count": 18,
  "low_count": 14,
  "started_at": "2025-01-15T10:00:00Z",
  "completed_at": "2025-01-15T14:30:00Z",
  "total_duration": "4:30:00",
  "created_at": "2025-01-15T09:55:00Z"
}
```

### Start Scan

```http
POST /api/scans/{scan_id}/start
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "message": "Scan started successfully",
  "scan_id": 1,
  "status": "running"
}
```

### Pause Scan

```http
POST /api/scans/{scan_id}/pause
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "message": "Scan paused successfully",
  "scan_id": 1,
  "status": "paused"
}
```

### Resume Scan

```http
POST /api/scans/{scan_id}/resume
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "message": "Scan resumed successfully",
  "scan_id": 1,
  "status": "running"
}
```

### Stop Scan

```http
POST /api/scans/{scan_id}/stop
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "message": "Scan stopped successfully",
  "scan_id": 1,
  "status": "cancelled"
}
```

### Get Scan Progress

```http
GET /api/scans/{scan_id}/progress
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "scan_id": 1,
  "status": "running",
  "current_phase": "VULNERABILITY_TESTING",
  "progress_percentage": 65.5,
  "phases": [
    {
      "name": "INITIALIZATION",
      "status": "completed",
      "progress": 100.0
    },
    {
      "name": "PASSIVE_RECON",
      "status": "completed",
      "progress": 100.0
    },
    {
      "name": "VULNERABILITY_TESTING",
      "status": "running",
      "progress": 45.0
    }
  ],
  "findings_count": 12,
  "elapsed_time": "2:15:30",
  "estimated_time_remaining": "1:45:00"
}
```

### Get Scan Results

```http
GET /api/scans/{scan_id}/results
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "scan_id": 1,
  "status": "completed",
  "summary": {
    "total_vulnerabilities": 42,
    "critical": 2,
    "high": 8,
    "medium": 18,
    "low": 14,
    "total_assets_discovered": 150
  },
  "vulnerabilities": [
    {
      "id": 1,
      "vulnerability_name": "SQL Injection in login form",
      "severity": "critical",
      "cvss_score": 9.8,
      "affected_url": "https://example.com/login"
    }
  ],
  "recon_results": {
    "subdomains": 45,
    "urls": 230,
    "technologies": ["nginx", "php", "mysql"]
  }
}
```

### Get Tool Executions

```http
GET /api/scans/{scan_id}/tools
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "scan_id": 1,
  "tools": [
    {
      "id": 1,
      "tool_name": "nuclei",
      "tool_category": "scanner",
      "status": "completed",
      "findings_count": 15,
      "started_at": "2025-01-15T11:00:00Z",
      "completed_at": "2025-01-15T11:30:00Z",
      "duration": "0:30:00"
    }
  ]
}
```

## Vulnerabilities API

### List Vulnerabilities

```http
GET /api/vulnerabilities/
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `target_id` (optional): Filter by target
- `scan_id` (optional): Filter by scan session
- `severity` (optional): Filter by severity (critical, high, medium, low, info)
- `status` (optional): Filter by status (new, verified, reported, resolved)
- `vulnerability_type` (optional): Filter by type (sql_injection, xss, etc.)
- `manually_verified` (optional): Filter by verification status (true/false)
- `false_positive` (optional): Exclude false positives (true/false)
- `min_cvss` (optional): Minimum CVSS score
- `max_cvss` (optional): Maximum CVSS score
- `discovered_after` (optional): ISO date filter
- `discovered_before` (optional): ISO date filter

**Response** (200 OK):
```json
{
  "items": [
    {
      "id": 1,
      "vulnerability_name": "SQL Injection in login form",
      "vulnerability_type": "sql_injection",
      "severity": "critical",
      "cvss_score": 9.8,
      "confidence_level": "high",
      "affected_url": "https://example.com/login",
      "affected_parameter": "username",
      "description": "SQL injection vulnerability allows...",
      "impact_description": "Attacker can access entire database...",
      "manually_verified": true,
      "status": "verified",
      "discovered_at": "2025-01-15T11:15:00Z"
    }
  ],
  "total": 42,
  "page": 1,
  "page_size": 20
}
```

### Create Vulnerability

```http
POST /api/vulnerabilities/
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "scan_session_id": 1,
  "target_id": 1,
  "vulnerability_name": "SQL Injection in login form",
  "vulnerability_type": "sql_injection",
  "severity": "critical",
  "affected_url": "https://example.com/login",
  "affected_parameter": "username",
  "description": "SQL injection vulnerability allows authentication bypass",
  "impact_description": "Attacker can access entire database",
  "proof_of_concept": "' OR '1'='1",
  "remediation": "Use parameterized queries",
  "cwe_id": "CWE-89",
  "owasp_category": "A03:2021-Injection"
}
```

**Response** (201 Created): Vulnerability object

### Get Vulnerability

```http
GET /api/vulnerabilities/{vulnerability_id}
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "id": 1,
  "vulnerability_name": "SQL Injection in login form",
  "vulnerability_type": "sql_injection",
  "severity": "critical",
  "cvss_score": 9.8,
  "confidence_level": "high",
  "cwe_id": "CWE-89",
  "owasp_category": "A03:2021-Injection",
  "affected_url": "https://example.com/login",
  "affected_parameter": "username",
  "affected_component": "Authentication Module",
  "description": "SQL injection vulnerability...",
  "impact_description": "Attacker can access...",
  "remediation": "Use parameterized queries...",
  "proof_of_concept": "' OR '1'='1",
  "screenshot_paths": ["/evidence/screenshots/vuln-1-1.png"],
  "http_requests": ["POST /login HTTP/1.1\n..."],
  "http_responses": ["HTTP/1.1 200 OK\n..."],
  "manually_verified": true,
  "verification_notes": "Confirmed via manual testing",
  "false_positive": false,
  "status": "verified",
  "discovered_by": "nuclei",
  "discovered_at": "2025-01-15T11:15:00Z",
  "target": {
    "id": 1,
    "target_name": "example-program"
  },
  "scan_session": {
    "id": 1,
    "session_name": "Full Scan - Jan 2025"
  }
}
```

### Update Vulnerability

```http
PUT /api/vulnerabilities/{vulnerability_id}
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "severity": "high",
  "cvss_score": 8.5,
  "verification_notes": "Updated after retest"
}
```

**Response** (200 OK): Updated vulnerability object

### Analyze Vulnerability

```http
POST /api/vulnerabilities/{vulnerability_id}/analyze
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "vulnerability_id": 1,
  "analysis": {
    "attack_vectors": ["Web Application", "Authentication Bypass"],
    "exploitability": "high",
    "impact": "critical",
    "remediation_priority": "immediate",
    "proof_of_concept": "Detailed PoC...",
    "enhanced_remediation": "1. Implement parameterized queries...",
    "references": [
      "https://cwe.mitre.org/data/definitions/89.html",
      "https://owasp.org/www-community/attacks/SQL_Injection"
    ]
  }
}
```

### Verify Vulnerability

```http
POST /api/vulnerabilities/{vulnerability_id}/verify
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "verification_notes": "Manually verified using Burp Suite",
  "is_valid": true
}
```

**Response** (200 OK):
```json
{
  "vulnerability_id": 1,
  "manually_verified": true,
  "verification_notes": "Manually verified using Burp Suite",
  "verified_at": "2025-01-15T15:00:00Z"
}
```

### Upload Evidence

```http
POST /api/vulnerabilities/{vulnerability_id}/evidence
Authorization: Bearer <access_token>
Content-Type: multipart/form-data

file: <screenshot.png>
evidence_type: screenshot
description: SQL injection proof
```

**Response** (200 OK):
```json
{
  "vulnerability_id": 1,
  "evidence_added": {
    "type": "screenshot",
    "path": "/evidence/screenshots/vuln-1-2.png",
    "description": "SQL injection proof"
  }
}
```

### Get Exploitation Chains

```http
GET /api/vulnerabilities/{vulnerability_id}/exploitation-chains
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "vulnerability_id": 1,
  "chains": [
    {
      "id": 1,
      "chain_name": "Authentication Bypass to Admin Access",
      "steps": [
        {
          "step_number": 1,
          "description": "SQL injection in login",
          "payload": "' OR '1'='1",
          "expected_result": "Authentication bypass"
        },
        {
          "step_number": 2,
          "description": "Access admin panel",
          "payload": null,
          "expected_result": "Admin panel access"
        }
      ],
      "success_probability": 85.5,
      "impact_level": "critical"
    }
  ]
}
```

### Bulk Operations

```http
POST /api/vulnerabilities/bulk-operations
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "operation": "verify",
  "vulnerability_ids": [1, 2, 3],
  "data": {
    "verification_notes": "Batch verification completed"
  }
}
```

**Operations**:
- `verify` - Bulk verification
- `update_status` - Update status
- `update_severity` - Update severity
- `delete` - Bulk delete (admin only)

**Response** (200 OK):
```json
{
  "operation": "verify",
  "processed": 3,
  "successful": 3,
  "failed": 0,
  "results": [
    {"id": 1, "status": "success"},
    {"id": 2, "status": "success"},
    {"id": 3, "status": "success"}
  ]
}
```

### Export Vulnerabilities

```http
GET /api/vulnerabilities/export/{format}
Authorization: Bearer <access_token>
```

**Formats**: `csv`, `json`, `xml`, `pdf`

**Query Parameters**: Same as list vulnerabilities (for filtering)

**Response** (200 OK):
- Content-Type varies by format
- File download initiated

### Get Statistics

```http
GET /api/vulnerabilities/statistics/summary
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "total_vulnerabilities": 150,
  "by_severity": {
    "critical": 5,
    "high": 25,
    "medium": 60,
    "low": 50,
    "info": 10
  },
  "by_status": {
    "new": 30,
    "verified": 80,
    "reported": 25,
    "resolved": 15
  },
  "by_type": {
    "sql_injection": 10,
    "xss": 25,
    "csrf": 15,
    "ssrf": 8
  },
  "avg_cvss_score": 6.5,
  "verification_rate": 53.3
}
```

### Get Trends

```http
GET /api/vulnerabilities/statistics/trends
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `period` (optional): day, week, month, year (default: month)
- `group_by` (optional): severity, type, target (default: severity)

**Response** (200 OK):
```json
{
  "period": "month",
  "trends": [
    {
      "date": "2025-01",
      "critical": 2,
      "high": 8,
      "medium": 18,
      "low": 14,
      "total": 42
    }
  ]
}
```

## Reconnaissance API

### List Recon Results

```http
GET /api/reconnaissance/
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `scan_id` (optional)
- `target_id` (optional)
- `asset_type` (optional): subdomain, url, ip_address, port, etc.
- `is_in_scope` (optional)
- `is_verified` (optional)

**Response** (200 OK):
```json
{
  "items": [
    {
      "id": 1,
      "asset_type": "subdomain",
      "asset_value": "api.example.com",
      "discovery_method": "passive_dns",
      "tool_used": "subfinder",
      "confidence_score": 95.5,
      "technologies_detected": ["nginx", "php"],
      "is_verified": true,
      "is_in_scope": true,
      "discovered_at": "2025-01-15T10:30:00Z"
    }
  ],
  "total": 150
}
```

## Exploitation API

### List Exploit Attempts

```http
GET /api/exploitation/attempts
Authorization: Bearer <access_token>
```

**Query Parameters**:
- `vulnerability_id` (optional)
- `success_status` (optional)
- `risk_level` (optional)

**Response** (200 OK):
```json
{
  "items": [
    {
      "id": 1,
      "vulnerability_id": 1,
      "exploit_type": "authentication_bypass",
      "success_status": "success",
      "callback_received": true,
      "impact_assessment": "Full admin access achieved",
      "risk_level": "safe",
      "executed_at": "2025-01-15T12:00:00Z"
    }
  ]
}
```

### Create Exploit Attempt

```http
POST /api/exploitation/attempts
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "vulnerability_id": 1,
  "exploit_type": "sql_injection",
  "payload_used": "' OR '1'='1",
  "is_safe": true
}
```

**Response** (201 Created): Exploit attempt object

## Reports API

### List Reports

```http
GET /api/reports/
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "items": [
    {
      "id": 1,
      "report_name": "Full Security Assessment - Jan 2025",
      "report_type": "technical",
      "format": "pdf",
      "scan_session_id": 1,
      "target_id": 1,
      "file_path": "/reports/report-1.pdf",
      "file_size": 2048576,
      "generated_at": "2025-01-15T15:00:00Z"
    }
  ]
}
```

### Generate Report

```http
POST /api/reports/generate
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "scan_session_id": 1,
  "report_name": "Security Assessment Report",
  "report_type": "technical",
  "format": "pdf",
  "include_sections": [
    "executive_summary",
    "findings",
    "recommendations",
    "appendices"
  ]
}
```

**Response** (202 Accepted):
```json
{
  "report_id": 1,
  "status": "generating",
  "message": "Report generation started. Check status at /api/reports/1"
}
```

### Download Report

```http
GET /api/reports/{report_id}/download
Authorization: Bearer <access_token>
```

**Response** (200 OK):
- Content-Type: application/pdf (or appropriate format)
- Content-Disposition: attachment; filename="report.pdf"
- Binary file data

## Callbacks API

### Register Callback

```http
POST /api/callbacks/register
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "vulnerability_id": 1,
  "callback_type": "http",
  "identifier": "unique-callback-id"
}
```

**Response** (200 OK):
```json
{
  "callback_url": "https://callback.bughunt.local/c/unique-callback-id",
  "callback_dns": "unique-callback-id.callback.bughunt.local",
  "identifier": "unique-callback-id"
}
```

### List Callbacks

```http
GET /api/callbacks/
Authorization: Bearer <access_token>
```

**Response** (200 OK):
```json
{
  "items": [
    {
      "id": 1,
      "vulnerability_id": 1,
      "callback_type": "http",
      "identifier": "unique-callback-id",
      "received": true,
      "received_at": "2025-01-15T12:05:00Z",
      "request_data": {
        "method": "GET",
        "headers": {...},
        "ip": "192.168.1.100"
      }
    }
  ]
}
```

## Error Responses

### Standard Error Format

```json
{
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid input data",
    "details": {
      "field": "email",
      "issue": "Invalid email format"
    }
  }
}
```

### Common Error Codes

- `400 Bad Request` - Invalid input/validation error
- `401 Unauthorized` - Missing or invalid authentication
- `403 Forbidden` - Insufficient permissions
- `404 Not Found` - Resource not found
- `409 Conflict` - Resource conflict (duplicate)
- `422 Unprocessable Entity` - Validation failed
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error
- `503 Service Unavailable` - Service temporarily unavailable

## Rate Limiting

**Global Limits**:
- Anonymous: 100 requests per hour
- Authenticated: 1000 requests per hour
- Admin: 5000 requests per hour

**Headers**:
```
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 950
X-RateLimit-Reset: 1642252800
```

**Rate Limit Response** (429):
```json
{
  "error": {
    "code": "RATE_LIMIT_EXCEEDED",
    "message": "Rate limit exceeded. Retry after 300 seconds",
    "retry_after": 300
  }
}
```

## Pagination

**Request**:
```http
GET /api/vulnerabilities/?page=2&page_size=50
```

**Response Metadata**:
```json
{
  "items": [...],
  "total": 250,
  "page": 2,
  "page_size": 50,
  "total_pages": 5,
  "has_next": true,
  "has_previous": true,
  "next_page": 3,
  "previous_page": 1
}
```

## WebSocket Endpoints

### Scan Progress Stream

```javascript
const ws = new WebSocket('ws://localhost:8000/api/ws/scans/1/progress');

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log('Progress:', data.progress_percentage);
};
```

**Message Format**:
```json
{
  "type": "progress_update",
  "scan_id": 1,
  "progress_percentage": 65.5,
  "current_phase": "VULNERABILITY_TESTING",
  "findings_count": 12
}
```

## Best Practices

### Using the API Efficiently

1. **Use Filtering**: Apply filters to reduce response size
2. **Pagination**: Use appropriate page sizes (20-50 items)
3. **Field Selection**: Request only needed fields when available
4. **Caching**: Respect cache headers for frequently accessed data
5. **Batch Operations**: Use bulk endpoints for multiple operations
6. **WebSockets**: Use WebSocket for real-time updates

### Error Handling

```python
import requests

response = requests.post(
    'http://localhost:8000/api/scans/',
    headers={'Authorization': f'Bearer {token}'},
    json=scan_data
)

if response.status_code == 202:
    scan = response.json()
    print(f"Scan created: {scan['id']}")
elif response.status_code == 429:
    retry_after = response.headers.get('Retry-After')
    print(f"Rate limited. Retry after {retry_after}s")
else:
    error = response.json()
    print(f"Error: {error['error']['message']}")
```
