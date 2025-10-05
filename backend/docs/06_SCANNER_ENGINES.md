# Scanner Engines Documentation

## Overview

The Bug Hunt Framework implements a modular scanner engine architecture based on OWASP testing methodology. Each engine is responsible for specific types of security testing, and all engines are coordinated by the Scan Orchestrator.

## Scanner Architecture

### Engine Hierarchy

```
ScanOrchestrator (Coordinator)
├── ReconEngine (Asset Discovery)
├── NucleiEngine (Template-Based Scanning)
├── CustomWebEngine (Web Application Testing)
├── CustomAPIEngine (API Security Testing)
└── CustomInfraEngine (Infrastructure Testing)
```

## Scan Orchestrator

**Location**: `backend/services/scanner_engines/scan_orchestrator.py`

The central coordinator that manages the complete scanning workflow.

### Scanning Methodology

The orchestrator implements a 7-phase OWASP-based methodology:

```python
class ScanPhase(Enum):
    """Scan methodology phases"""
    INITIALIZATION = "initialization"
    PASSIVE_RECON = "passive_reconnaissance"
    ACTIVE_RECON = "active_reconnaissance"
    VULNERABILITY_TESTING = "vulnerability_testing"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    CLEANUP = "cleanup"
```

### Phase Details

#### Phase 1: Initialization (5% weight)
**Purpose**: Setup and validation

**Operations**:
- Validate target accessibility
- Verify tool availability
- Check scope configuration
- Initialize scan context
- Setup rate limiting
- Create working directories

**Tools Used**:
- Internal validators
- Connectivity checks

**Output**:
```json
{
  "phase": "INITIALIZATION",
  "status": "completed",
  "target_reachable": true,
  "tools_available": ["nuclei", "httpx", "subfinder"],
  "scope_validated": true
}
```

#### Phase 2: Passive Reconnaissance (15% weight)
**Purpose**: Non-intrusive information gathering

**Operations**:
- Subdomain enumeration (passive sources)
- Certificate transparency logs
- DNS records gathering
- WHOIS information
- Technology fingerprinting
- OSINT data collection

**Tools Used**:
- Subfinder
- Amass (passive mode)
- CT logs
- Shodan/Censys APIs

**Output**:
```json
{
  "phase": "PASSIVE_RECON",
  "subdomains_found": 150,
  "technologies_detected": ["nginx", "php", "mysql"],
  "dns_records": {...},
  "certificates": [...]
}
```

#### Phase 3: Active Reconnaissance (20% weight)
**Purpose**: Active probing and asset discovery

**Operations**:
- Port scanning
- Service detection
- Web server probing
- URL crawling
- JavaScript analysis
- Screenshot capture
- Response header analysis

**Tools Used**:
- Nmap
- Masscan
- HTTPX
- GoSpider
- Aquatone

**Output**:
```json
{
  "phase": "ACTIVE_RECON",
  "open_ports": [80, 443, 8080],
  "live_hosts": 45,
  "urls_discovered": 230,
  "screenshots_captured": 45,
  "services_identified": {...}
}
```

#### Phase 4: Vulnerability Testing (35% weight)
**Purpose**: Security vulnerability identification

**Operations**:
- Nuclei template scanning
- Custom web vulnerability checks
- API security testing
- Parameter fuzzing
- Authentication testing
- Authorization bypass attempts
- Input validation testing

**Tools Used**:
- Nuclei
- Custom web engine
- Custom API engine
- FFUF (fuzzing)

**Output**:
```json
{
  "phase": "VULNERABILITY_TESTING",
  "vulnerabilities_found": 42,
  "critical": 2,
  "high": 8,
  "medium": 18,
  "low": 14
}
```

#### Phase 5: Exploitation (15% weight)
**Purpose**: Vulnerability verification and PoC generation

**Operations**:
- Safe exploit execution
- Callback verification
- Impact assessment
- Proof-of-concept generation
- Evidence collection

**Tools Used**:
- Custom exploitation engine
- Callback server
- PoC generators

**Output**:
```json
{
  "phase": "EXPLOITATION",
  "verified_vulnerabilities": 35,
  "poc_generated": 28,
  "callbacks_received": 12,
  "exploitation_chains": 5
}
```

#### Phase 6: Reporting (8% weight)
**Purpose**: Report generation and documentation

**Operations**:
- Technical report generation
- Executive summary creation
- Evidence compilation
- Remediation recommendations
- Export to various formats

**Tools Used**:
- Internal report generator
- Template engine

**Output**:
```json
{
  "phase": "REPORTING",
  "reports_generated": [
    "technical_report.pdf",
    "executive_summary.pdf",
    "findings.json"
  ]
}
```

#### Phase 7: Cleanup (2% weight)
**Purpose**: Resource cleanup

**Operations**:
- Remove temporary files
- Archive scan results
- Close connections
- Release resources
- Update scan status

### Scan Context

```python
@dataclass
class ScanContext:
    """Context object passed through scan phases"""

    scan_session: ScanSession
    target: Target
    config: dict
    current_phase: ScanPhase
    results: dict
    start_time: datetime
    rate_limiter: RateLimiter

    # Phase-specific data
    discovered_subdomains: List[str] = field(default_factory=list)
    discovered_urls: List[str] = field(default_factory=list)
    discovered_vulnerabilities: List[dict] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
```

### Workflow Types

```python
class WorkflowType(Enum):
    """Predefined scanning workflows"""

    STANDARD = "standard"  # All 7 phases
    QUICK = "quick"        # Passive recon + basic vuln testing
    DEEP = "deep"          # Extended fuzzing and testing
    CUSTOM = "custom"      # User-defined phases
```

**Standard Workflow**:
```python
WORKFLOWS = {
    'standard': [
        'INITIALIZATION',
        'PASSIVE_RECON',
        'ACTIVE_RECON',
        'VULNERABILITY_TESTING',
        'EXPLOITATION',
        'REPORTING',
        'CLEANUP'
    ],
    'quick': [
        'INITIALIZATION',
        'PASSIVE_RECON',
        'VULNERABILITY_TESTING',
        'REPORTING',
        'CLEANUP'
    ],
    'deep': [
        'INITIALIZATION',
        'PASSIVE_RECON',
        'ACTIVE_RECON',
        'VULNERABILITY_TESTING',
        'FUZZING',  # Extended fuzzing
        'EXPLOITATION',
        'REPORTING',
        'CLEANUP'
    ]
}
```

### Progress Tracking

```python
class ProgressTracker:
    """Real-time progress tracking"""

    PHASE_WEIGHTS = {
        'INITIALIZATION': 5,
        'PASSIVE_RECON': 15,
        'ACTIVE_RECON': 20,
        'VULNERABILITY_TESTING': 35,
        'EXPLOITATION': 15,
        'REPORTING': 8,
        'CLEANUP': 2
    }

    def calculate_progress(self, completed_phases: list, current_phase: str) -> Decimal:
        """
        Calculate overall progress percentage

        Returns:
            Decimal: Progress (0-100)
        """
```

### Rate Limiting

```python
class RateLimiter:
    """Token bucket rate limiter"""

    def __init__(self, requests_per_second: int, burst_size: int = None):
        """
        Initialize rate limiter

        Args:
            requests_per_second: Sustained rate
            burst_size: Maximum burst (default: 2x rate)
        """

    async def acquire(self):
        """Wait for token availability"""

    def get_wait_time(self) -> float:
        """Get wait time until next available token"""
```

**Rate Limit Configuration**:
```python
# Target-specific rate limits
target_rate_limit = target.rate_limit  # e.g., 10 req/sec

# Scanner-specific limits
SCANNER_LIMITS = {
    'nuclei': 150,      # req/sec
    'httpx': 100,
    'nmap': 50,
    'ffuf': 50
}
```

## Reconnaissance Engine

**Location**: `backend/services/scanner_engines/recon_engine.py`

Comprehensive asset discovery and reconnaissance.

### ReconEngine Class

```python
class ReconEngine:
    """Reconnaissance engine for asset discovery"""

    def __init__(self, target: Target, config: dict):
        self.target = target
        self.config = config
        self.results = []

    async def execute_passive_recon(self) -> dict:
        """
        Execute passive reconnaissance

        Returns:
            dict: {
                'subdomains': list,
                'ips': list,
                'technologies': list,
                'osint_data': dict
            }
        """

    async def execute_active_recon(self) -> dict:
        """
        Execute active reconnaissance

        Returns:
            dict: {
                'open_ports': list,
                'services': dict,
                'urls': list,
                'screenshots': list
            }
        """

    async def enumerate_subdomains(self, method: str = 'passive') -> list:
        """
        Subdomain enumeration

        Args:
            method: 'passive' or 'active'

        Returns:
            list: Discovered subdomains
        """

    async def scan_ports(self, hosts: list) -> dict:
        """
        Port scanning

        Returns:
            dict: Host -> ports mapping
        """

    async def crawl_website(self, url: str) -> list:
        """
        Web crawling

        Returns:
            list: Discovered URLs
        """
```

### Tool Integrations

**Subfinder** (Passive Subdomain Enumeration):
```bash
subfinder -d example.com -all -silent -json
```

**Amass** (Comprehensive Recon):
```bash
amass enum -d example.com -passive -json output.json
```

**HTTPX** (HTTP Probing):
```bash
httpx -l urls.txt -json -silent -threads 50
```

**Nmap** (Port Scanning):
```bash
nmap -p- -T4 --open -oX output.xml target.com
```

**GoSpider** (Web Crawling):
```bash
gospider -s https://example.com -d 3 -c 10 -t 20 -o output
```

## Nuclei Engine

**Location**: `backend/services/scanner_engines/nuclei_engine.py`

Template-based vulnerability scanning using Nuclei.

### NucleiEngine Class

```python
class NucleiEngine:
    """Nuclei template-based vulnerability scanner"""

    def __init__(self, config: dict):
        self.config = config
        self.nuclei_path = config.get('nuclei_path', '/usr/bin/nuclei')

    async def execute_scan(
        self,
        targets: list,
        templates: list = None,
        severity: list = None
    ) -> list:
        """
        Execute Nuclei scan

        Args:
            targets: List of URLs to scan
            templates: Template categories (default: all)
            severity: Severity filter (critical, high, etc.)

        Returns:
            list: Discovered vulnerabilities
        """

    def parse_nuclei_output(self, output: str) -> list:
        """
        Parse Nuclei JSON output

        Returns:
            list: Parsed vulnerabilities
        """

    async def update_templates(self) -> bool:
        """Update Nuclei templates"""

    def get_available_templates(self) -> list:
        """Get list of available templates"""
```

### Template Categories

**Default Categories**:
```python
NUCLEI_TEMPLATES = {
    'cves': 'CVE templates',
    'vulnerabilities': 'Known vulnerabilities',
    'misconfigurations': 'Security misconfigurations',
    'exposures': 'Information exposures',
    'tokens': 'Token/secret exposures',
    'default-logins': 'Default credentials',
    'takeovers': 'Subdomain takeovers',
    'injection': 'Injection vulnerabilities',
    'xss': 'XSS vulnerabilities'
}
```

**Nuclei Command**:
```bash
nuclei \
  -l targets.txt \
  -t cves/ -t vulnerabilities/ \
  -severity critical,high \
  -json -silent \
  -rate-limit 150 \
  -bulk-size 25 \
  -c 25 \
  -o output.json
```

### Nuclei Configuration

```python
NUCLEI_CONFIG = {
    'rate_limit': 150,          # Requests per second
    'bulk_size': 25,            # Parallel templates
    'concurrency': 25,          # Parallel targets
    'timeout': 10,              # Request timeout (seconds)
    'retries': 1,               # Retry failed requests
    'max_host_error': 30,       # Max errors per host
    'update_templates': True,   # Auto-update templates
}
```

## Custom Web Engine

**Location**: `backend/services/scanner_engines/custom_web_engine.py`

Custom web application security testing.

### CustomWebEngine Class

```python
class CustomWebEngine:
    """Custom web application security scanner"""

    async def scan_sql_injection(self, url: str, parameters: list) -> list:
        """
        Test for SQL injection

        Returns:
            list: SQLi vulnerabilities
        """

    async def scan_xss(self, url: str, parameters: list) -> list:
        """
        Test for XSS vulnerabilities

        Returns:
            list: XSS vulnerabilities
        """

    async def scan_csrf(self, url: str, forms: list) -> list:
        """
        Test for CSRF vulnerabilities

        Returns:
            list: CSRF vulnerabilities
        """

    async def scan_authentication(self, url: str) -> dict:
        """
        Test authentication mechanisms

        Returns:
            dict: Authentication issues
        """

    async def scan_authorization(self, url: str) -> list:
        """
        Test authorization/access control

        Returns:
            list: Authorization issues
        """

    async def fuzz_parameters(
        self,
        url: str,
        parameters: list,
        wordlist: str
    ) -> list:
        """
        Fuzz parameters for vulnerabilities

        Returns:
            list: Findings from fuzzing
        """
```

### Vulnerability Tests

**SQL Injection Payloads**:
```python
SQL_INJECTION_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' UNION SELECT NULL--",
    "1' AND 1=1--",
    "admin'--",
    "' OR 1=1#",
]
```

**XSS Payloads**:
```python
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "javascript:alert('XSS')",
    "<svg onload=alert('XSS')>",
]
```

**Directory Traversal**:
```python
PATH_TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
]
```

## Custom API Engine

**Location**: `backend/services/scanner_engines/custom_api_engine.py`

API-specific security testing.

### CustomAPIEngine Class

```python
class CustomAPIEngine:
    """API security testing engine"""

    async def test_authentication(self, api_url: str) -> dict:
        """
        Test API authentication

        Tests:
        - Missing authentication
        - Weak authentication
        - Token security
        - OAuth implementation

        Returns:
            dict: Authentication findings
        """

    async def test_authorization(self, api_url: str) -> list:
        """
        Test API authorization

        Tests:
        - IDOR vulnerabilities
        - Privilege escalation
        - Resource access control
        - BOLA (Broken Object Level Authorization)

        Returns:
            list: Authorization issues
        """

    async def test_rate_limiting(self, api_url: str) -> dict:
        """
        Test rate limiting

        Returns:
            dict: Rate limiting analysis
        """

    async def test_mass_assignment(self, api_url: str) -> list:
        """
        Test for mass assignment

        Returns:
            list: Mass assignment vulnerabilities
        """

    async def fuzz_api_parameters(self, api_url: str) -> list:
        """
        Fuzz API parameters

        Returns:
            list: Fuzzing findings
        """

    async def test_graphql(self, graphql_url: str) -> list:
        """
        GraphQL-specific testing

        Tests:
        - Introspection enabled
        - Query complexity
        - Batching attacks
        - Injection vulnerabilities

        Returns:
            list: GraphQL vulnerabilities
        """
```

### API Security Tests

**OWASP API Security Top 10**:
1. Broken Object Level Authorization (BOLA)
2. Broken User Authentication
3. Excessive Data Exposure
4. Lack of Resources & Rate Limiting
5. Broken Function Level Authorization
6. Mass Assignment
7. Security Misconfiguration
8. Injection
9. Improper Assets Management
10. Insufficient Logging & Monitoring

## Custom Infrastructure Engine

**Location**: `backend/services/scanner_engines/custom_infra_engine.py`

Infrastructure and network security testing.

### CustomInfraEngine Class

```python
class CustomInfraEngine:
    """Infrastructure security scanner"""

    async def scan_ssl_tls(self, host: str, port: int = 443) -> dict:
        """
        SSL/TLS security analysis

        Checks:
        - Protocol versions
        - Cipher suites
        - Certificate validity
        - Certificate chain
        - HSTS header
        - Certificate transparency

        Returns:
            dict: SSL/TLS findings
        """

    async def scan_dns_security(self, domain: str) -> dict:
        """
        DNS security checks

        Checks:
        - DNSSEC
        - SPF records
        - DMARC policy
        - CAA records
        - Zone transfer

        Returns:
            dict: DNS security findings
        """

    async def scan_email_security(self, domain: str) -> dict:
        """
        Email security configuration

        Returns:
            dict: Email security findings
        """

    async def test_default_credentials(self, service: dict) -> list:
        """
        Test for default credentials

        Returns:
            list: Default credential findings
        """

    async def scan_network_services(self, host: str, ports: list) -> list:
        """
        Scan network services

        Returns:
            list: Service vulnerabilities
        """
```

## Scan Orchestration Flow

```
User initiates scan
    ↓
ScanOrchestrator.execute_scan()
    ↓
┌─────────────────────────────────────┐
│  Phase 1: INITIALIZATION            │
│  - Validate target                  │
│  - Check tools                      │
│  - Setup context                    │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Phase 2: PASSIVE_RECON             │
│  - ReconEngine.execute_passive()    │
│  - Subdomain enumeration            │
│  - OSINT gathering                  │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Phase 3: ACTIVE_RECON              │
│  - ReconEngine.execute_active()     │
│  - Port scanning                    │
│  - Web crawling                     │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Phase 4: VULNERABILITY_TESTING     │
│  - NucleiEngine.execute_scan()      │
│  - CustomWebEngine.scan_*()         │
│  - CustomAPIEngine.test_*()         │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Phase 5: EXPLOITATION              │
│  - ExploitationService.verify()     │
│  - Generate PoCs                    │
│  - Collect evidence                 │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Phase 6: REPORTING                 │
│  - ReportingService.generate()      │
│  - Compile findings                 │
└─────────────────────────────────────┘
    ↓
┌─────────────────────────────────────┐
│  Phase 7: CLEANUP                   │
│  - Remove temp files                │
│  - Update scan status               │
└─────────────────────────────────────┘
    ↓
Scan Complete
```

## Deduplication & Prioritization

### Vulnerability Deduplication

```python
def deduplicate_vulnerabilities(vulnerabilities: list) -> list:
    """
    Remove duplicate vulnerabilities

    Deduplication criteria:
    - Same vulnerability type
    - Same affected URL
    - Same affected parameter
    - Similar evidence

    Returns:
        list: Deduplicated vulnerabilities
    """
    seen = set()
    unique = []

    for vuln in vulnerabilities:
        key = (
            vuln['type'],
            vuln['url'],
            vuln.get('parameter', '')
        )

        if key not in seen:
            seen.add(key)
            unique.append(vuln)

    return unique
```

### Prioritization

```python
def prioritize_vulnerabilities(vulnerabilities: list) -> list:
    """
    Sort vulnerabilities by priority

    Priority factors:
    1. Severity (critical > high > medium > low)
    2. Exploitability
    3. Confidence level
    4. Impact

    Returns:
        list: Sorted vulnerabilities
    """
    severity_order = {
        'critical': 4,
        'high': 3,
        'medium': 2,
        'low': 1,
        'info': 0
    }

    return sorted(
        vulnerabilities,
        key=lambda v: (
            severity_order.get(v['severity'], 0),
            v.get('cvss_score', 0),
            v.get('confidence', 0)
        ),
        reverse=True
    )
```

## Custom Engine Development

### Creating a New Scanner Engine

```python
from typing import List, Dict
from abc import ABC, abstractmethod

class BaseScannerEngine(ABC):
    """Base class for all scanner engines"""

    def __init__(self, config: dict):
        self.config = config
        self.results = []

    @abstractmethod
    async def execute_scan(self, context: ScanContext) -> dict:
        """
        Execute scan

        Args:
            context: Scan context object

        Returns:
            dict: Scan results
        """
        pass

    @abstractmethod
    def parse_results(self, output: str) -> list:
        """
        Parse tool output

        Args:
            output: Raw tool output

        Returns:
            list: Parsed findings
        """
        pass

    def validate_config(self) -> bool:
        """Validate engine configuration"""
        return True

    async def cleanup(self):
        """Cleanup resources"""
        pass
```

### Example: Custom SSRF Scanner

```python
class SSRFEngine(BaseScannerEngine):
    """Custom SSRF vulnerability scanner"""

    async def execute_scan(self, context: ScanContext) -> dict:
        """Execute SSRF scan"""

        vulnerabilities = []

        for url in context.discovered_urls:
            # Test SSRF
            findings = await self.test_ssrf(url)
            vulnerabilities.extend(findings)

        return {
            'engine': 'ssrf',
            'vulnerabilities': vulnerabilities,
            'urls_tested': len(context.discovered_urls)
        }

    async def test_ssrf(self, url: str) -> list:
        """Test for SSRF vulnerabilities"""

        payloads = [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost/',
            'http://127.0.0.1:8080/'
        ]

        findings = []

        for payload in payloads:
            # Test SSRF with callback verification
            callback_id = self.callback_server.register()

            response = await self.send_request(
                url,
                params={'url': f'{callback_id}.callback.local'}
            )

            if self.callback_server.check_received(callback_id):
                findings.append({
                    'type': 'ssrf',
                    'url': url,
                    'severity': 'high',
                    'evidence': response.text
                })

        return findings

    def parse_results(self, output: str) -> list:
        """Parse SSRF findings"""
        # Implementation
        pass
```

## Performance Optimization

### Parallel Scanning

```python
import asyncio

async def parallel_scan(urls: list, scan_func) -> list:
    """Execute scans in parallel"""

    tasks = [scan_func(url) for url in urls]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    # Filter out exceptions
    return [r for r in results if not isinstance(r, Exception)]
```

### Batch Processing

```python
def batch_urls(urls: list, batch_size: int = 50) -> list:
    """Split URLs into batches"""

    return [
        urls[i:i + batch_size]
        for i in range(0, len(urls), batch_size)
    ]

# Usage
for batch in batch_urls(all_urls, batch_size=50):
    results = await scan_batch(batch)
```

### Caching Results

```python
from functools import lru_cache

@lru_cache(maxsize=1000)
def get_technology_fingerprint(url: str) -> list:
    """Cached technology detection"""
    return detect_technologies(url)
```

## Error Handling

### Retry Logic

```python
from tenacity import retry, stop_after_attempt, wait_exponential

@retry(
    stop=stop_after_attempt(3),
    wait=wait_exponential(multiplier=1, min=4, max=10)
)
async def scan_with_retry(url: str):
    """Scan with automatic retry"""
    return await execute_scan(url)
```

### Graceful Degradation

```python
async def execute_phase(phase: str, context: ScanContext):
    """Execute phase with error handling"""

    try:
        result = await phase_executor(phase, context)
        return result
    except ToolNotFoundError:
        logger.warning(f"Tool not found for {phase}, skipping")
        return {'status': 'skipped', 'reason': 'tool_unavailable'}
    except TimeoutError:
        logger.error(f"Timeout in {phase}")
        return {'status': 'timeout'}
    except Exception as e:
        logger.error(f"Error in {phase}: {e}")
        return {'status': 'error', 'message': str(e)}
```

## Best Practices

### Scanner Development

1. **Follow base class pattern**: Inherit from `BaseScannerEngine`
2. **Implement async methods**: Use `async/await` for I/O operations
3. **Respect rate limits**: Use rate limiter from context
4. **Parse output properly**: Handle various output formats
5. **Deduplicate findings**: Remove duplicate vulnerabilities
6. **Add comprehensive logging**: Log all important operations
7. **Handle errors gracefully**: Don't crash the entire scan
8. **Validate configuration**: Check config before execution
9. **Clean up resources**: Implement cleanup method
10. **Document thoroughly**: Add docstrings and comments
