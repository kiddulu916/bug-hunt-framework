# Services Layer

## Overview

The service layer contains all business logic for the Bug Hunt Framework. Services are stateless, reusable components that orchestrate operations across models, external tools, and APIs.

## Service Architecture Pattern

All services follow a consistent pattern:

```python
class ServiceName:
    """Service for [specific domain]"""

    def __init__(self):
        """Initialize with dependencies"""
        self.dependency = DependencyService()

    def operation(self, **kwargs):
        """
        Perform business operation

        Args:
            **kwargs: Operation parameters

        Returns:
            Result of operation

        Raises:
            ServiceException: On operation failure
        """
        # Validate input
        # Execute logic
        # Return result
```

## Core Services

### Target Service

**Location**: `backend/services/target_service.py`

Manages bug bounty targets and scope validation.

```python
class TargetService:
    """Service for target management and scope validation"""

    @staticmethod
    def validate_scope(target: Target, asset: str) -> dict:
        """
        Validate if asset is in scope for target

        Args:
            target: Target instance
            asset: Asset URL/domain to validate

        Returns:
            dict: {
                'in_scope': bool,
                'matched_rule': str,
                'scope_type': str
            }
        """

    @staticmethod
    def validate_asset_scope(target: Target, asset_type: str, asset_value: str) -> bool:
        """
        Validate specific asset type against scope

        Args:
            target: Target instance
            asset_type: Type of asset (subdomain, ip, etc.)
            asset_value: Asset value

        Returns:
            bool: True if in scope
        """

    @staticmethod
    def generate_scan_configuration(target: Target, scan_type: str = 'standard') -> dict:
        """
        Generate tool-specific scan configuration

        Args:
            target: Target instance
            scan_type: Type of scan (standard, quick, deep)

        Returns:
            dict: Scan configuration for orchestrator
        """

    @staticmethod
    def test_connectivity(target: Target) -> dict:
        """
        Test if target is reachable

        Returns:
            dict: {
                'reachable': bool,
                'status_code': int,
                'response_time_ms': float
            }
        """

    @staticmethod
    def get_target_statistics(target: Target) -> dict:
        """
        Get comprehensive target statistics

        Returns:
            dict: Statistics including scans, vulns, etc.
        """
```

**Key Features**:
- URL pattern matching with wildcards
- CIDR range validation for IPs
- Subdomain scope validation
- Connectivity testing
- Configuration generation

**Usage Example**:
```python
from services.target_service import TargetService

target = Target.objects.get(id=1)
result = TargetService.validate_scope(
    target=target,
    asset="https://api.example.com/users"
)

if result['in_scope']:
    print(f"In scope via rule: {result['matched_rule']}")
```

### Scanning Service

**Location**: `backend/services/scanning_service.py`

Orchestrates scan execution and management.

```python
class ScanningService:
    """Service for scan orchestration and management"""

    def __init__(self):
        self.orchestrator = ScanOrchestrator()

    async def execute_scan_session(self, scan_session: ScanSession) -> dict:
        """
        Execute complete scan session

        Args:
            scan_session: ScanSession instance

        Returns:
            dict: Scan results summary
        """

    def validate_scan_config(self, config: dict) -> bool:
        """
        Validate scan configuration

        Args:
            config: Scan configuration dict

        Returns:
            bool: True if valid

        Raises:
            ValidationError: If invalid
        """

    def calculate_scan_progress(self, scan_session: ScanSession) -> Decimal:
        """
        Calculate current scan progress percentage

        Returns:
            Decimal: Progress percentage (0-100)
        """

    def pause_scan_session(self, scan_session: ScanSession) -> bool:
        """Pause running scan"""

    def resume_scan_session(self, scan_session: ScanSession) -> bool:
        """Resume paused scan"""

    def stop_scan_session(self, scan_session: ScanSession) -> bool:
        """Stop scan execution"""

    def get_scan_results(self, scan_session: ScanSession) -> dict:
        """
        Retrieve complete scan results

        Returns:
            dict: {
                'vulnerabilities': [...],
                'recon_results': [...],
                'statistics': {...}
            }
        """
```

**Key Features**:
- Async scan execution via Celery
- Real-time progress tracking
- Scan lifecycle management (pause/resume/stop)
- Result aggregation

**Usage Example**:
```python
from services.scanning_service import ScanningService

service = ScanningService()
scan = ScanSession.objects.get(id=1)

# Execute scan asynchronously
await service.execute_scan_session(scan)

# Check progress
progress = service.calculate_scan_progress(scan)
print(f"Scan progress: {progress}%")
```

### Vulnerability Scanner

**Location**: `backend/services/vulnerability_scanner.py`

Executes vulnerability scanning operations.

```python
class VulnerabilityScanner:
    """Service for vulnerability detection"""

    def run_nuclei_scan(self, target_url: str, templates: list = None) -> list:
        """
        Execute Nuclei template scan

        Args:
            target_url: URL to scan
            templates: List of template categories

        Returns:
            list: Discovered vulnerabilities
        """

    def run_custom_checks(self, target: Target, check_types: list) -> list:
        """
        Run custom vulnerability checks

        Args:
            target: Target instance
            check_types: Types of checks to run

        Returns:
            list: Vulnerabilities found
        """

    def run_fuzzing(self, url: str, parameters: list, wordlist: str) -> list:
        """
        Execute fuzzing on parameters

        Args:
            url: Target URL
            parameters: Parameters to fuzz
            wordlist: Path to wordlist file

        Returns:
            list: Fuzzing results
        """

    def deduplicate_findings(self, vulnerabilities: list) -> list:
        """
        Remove duplicate vulnerabilities

        Args:
            vulnerabilities: List of vulnerability dicts

        Returns:
            list: Deduplicated vulnerabilities
        """

    def prioritize_findings(self, vulnerabilities: list) -> list:
        """
        Sort vulnerabilities by priority

        Returns:
            list: Sorted vulnerabilities (critical first)
        """

    def calculate_cvss_score(self, vulnerability: dict) -> Decimal:
        """
        Calculate CVSS v3.1 score

        Args:
            vulnerability: Vulnerability data with vectors

        Returns:
            Decimal: CVSS score (0.0-10.0)
        """
```

**Key Features**:
- Nuclei integration with custom templates
- Custom vulnerability checks
- Parameter fuzzing
- Deduplication logic
- CVSS calculation

### Vulnerability Analyzer

**Location**: `backend/services/vulnerability_analyzer.py`

Provides deep analysis of vulnerabilities.

```python
class VulnerabilityAnalyzer:
    """Service for vulnerability analysis and enrichment"""

    def analyze_vulnerability(self, vulnerability: Vulnerability) -> dict:
        """
        Perform initial vulnerability analysis

        Args:
            vulnerability: Vulnerability instance

        Returns:
            dict: Analysis results with recommendations
        """

    def comprehensive_analysis(self, vulnerability: Vulnerability) -> dict:
        """
        Deep analysis with attack vectors and remediation

        Returns:
            dict: {
                'attack_vectors': [...],
                'exploitability': str,
                'impact': str,
                'remediation': str,
                'references': [...]
            }
        """

    def adjust_confidence_level(self, vulnerability: Vulnerability, evidence: dict) -> str:
        """
        Adjust confidence level based on evidence

        Args:
            vulnerability: Vulnerability instance
            evidence: Evidence dictionary

        Returns:
            str: New confidence level
        """

    def generate_proof_of_concept(self, vulnerability: Vulnerability) -> str:
        """
        Generate PoC for vulnerability

        Returns:
            str: Proof of concept code/payload
        """

    def identify_attack_vectors(self, vulnerability: Vulnerability) -> list:
        """
        Identify possible attack vectors

        Returns:
            list: Attack vector descriptions
        """

    def generate_remediation(self, vulnerability: Vulnerability) -> str:
        """
        Generate remediation recommendations

        Returns:
            str: Detailed remediation steps
        """

    def enrich_with_cwe_info(self, vulnerability: Vulnerability) -> dict:
        """
        Enrich with CWE database information

        Returns:
            dict: CWE details and references
        """
```

**Key Features**:
- Attack vector identification
- Exploitability assessment
- PoC generation
- Remediation recommendations
- CWE/OWASP mapping

**Usage Example**:
```python
from services.vulnerability_analyzer import VulnerabilityAnalyzer

analyzer = VulnerabilityAnalyzer()
vuln = Vulnerability.objects.get(id=1)

analysis = analyzer.comprehensive_analysis(vuln)
print(f"Exploitability: {analysis['exploitability']}")
print(f"Attack vectors: {analysis['attack_vectors']}")
```

### Reconnaissance Service

**Location**: `backend/services/recon_service.py`

Handles all reconnaissance operations.

```python
class ReconService:
    """Service for reconnaissance and asset discovery"""

    def enumerate_subdomains_passive(self, domain: str) -> list:
        """
        Passive subdomain enumeration

        Args:
            domain: Base domain

        Returns:
            list: Discovered subdomains
        """

    def enumerate_subdomains_active(self, domain: str, wordlist: str = None) -> list:
        """
        Active subdomain brute-forcing

        Args:
            domain: Base domain
            wordlist: Path to wordlist (optional)

        Returns:
            list: Discovered subdomains
        """

    def gather_osint(self, target: Target) -> dict:
        """
        Gather OSINT data

        Returns:
            dict: {
                'emails': [...],
                'social_media': [...],
                'leaked_credentials': [...]
            }
        """

    def profile_technology_passive(self, url: str) -> list:
        """
        Passive technology fingerprinting

        Args:
            url: Target URL

        Returns:
            list: Detected technologies
        """

    def scan_ports(self, host: str, port_range: str = '1-1000') -> list:
        """
        Port scanning

        Args:
            host: Target host
            port_range: Port range (e.g., '1-1000')

        Returns:
            list: Open ports with service info
        """

    def identify_services(self, host: str, ports: list) -> dict:
        """
        Service identification on open ports

        Args:
            host: Target host
            ports: List of open ports

        Returns:
            dict: Port -> service mapping
        """

    def crawl_web_assets(self, url: str, max_depth: int = 3) -> list:
        """
        Web crawling for URLs and assets

        Args:
            url: Starting URL
            max_depth: Maximum crawl depth

        Returns:
            list: Discovered URLs and assets
        """

    def screenshot_urls(self, urls: list) -> dict:
        """
        Take screenshots of URLs

        Args:
            urls: List of URLs

        Returns:
            dict: URL -> screenshot path mapping
        """
```

**Key Features**:
- Passive & active subdomain enumeration
- OSINT data gathering
- Technology fingerprinting
- Port scanning & service detection
- Web crawling
- Screenshot capture

**Tool Integrations**:
- Subfinder (passive subdomain)
- Amass (comprehensive recon)
- HTTPX (HTTP probing)
- Nmap (port scanning)
- Nuclei (technology detection)

### Exploitation Service

**Location**: `backend/services/exploitation_service.py`

Manages vulnerability exploitation and verification.

```python
class ExploitationService:
    """Service for safe exploitation and verification"""

    def __init__(self):
        self.callback_server = CallbackServer()

    def verify_vulnerability(self, vulnerability: Vulnerability) -> dict:
        """
        Verify vulnerability is exploitable

        Args:
            vulnerability: Vulnerability instance

        Returns:
            dict: Verification results
        """

    def generate_poc(self, vulnerability: Vulnerability) -> str:
        """
        Generate proof-of-concept exploit

        Returns:
            str: PoC code/payload
        """

    def execute_safe_exploit(self, vulnerability: Vulnerability, payload: str) -> dict:
        """
        Execute exploitation safely

        Args:
            vulnerability: Vulnerability instance
            payload: Exploit payload

        Returns:
            dict: Exploitation results

        Raises:
            UnsafeOperationError: If exploit deemed unsafe
        """

    def assess_impact(self, exploit_result: dict) -> str:
        """
        Assess exploitation impact

        Args:
            exploit_result: Result from execution

        Returns:
            str: Impact assessment text
        """

    def setup_callback_listener(self, vulnerability: Vulnerability) -> dict:
        """
        Setup callback for blind vulnerabilities

        Returns:
            dict: {
                'callback_url': str,
                'callback_dns': str,
                'identifier': str
            }
        """

    def check_callback_received(self, identifier: str) -> dict:
        """
        Check if callback was received

        Args:
            identifier: Callback identifier

        Returns:
            dict: Callback data if received
        """

    def validate_exploit_safety(self, vulnerability: Vulnerability, payload: str) -> bool:
        """
        Validate exploit won't cause damage

        Returns:
            bool: True if safe to execute
        """
```

**Key Features**:
- Safe exploitation within boundaries
- PoC generation
- Callback server integration
- Impact assessment
- Safety validation

**Safety Checks**:
- No destructive operations (DROP, DELETE, etc.)
- Read-only database queries
- Limited scope execution
- Pre-execution validation

### Reporting Service

**Location**: `backend/services/reporting_service.py`

Generates professional security reports.

```python
class ReportingService:
    """Service for report generation"""

    def __init__(self):
        self.template_engine = TemplateEngine()

    def generate_technical_report(self, scan_session: ScanSession, format: str = 'pdf') -> str:
        """
        Generate technical vulnerability report

        Args:
            scan_session: Scan session
            format: Output format (pdf, html, markdown)

        Returns:
            str: Path to generated report
        """

    def generate_executive_summary(self, scan_session: ScanSession) -> str:
        """
        Generate executive summary report

        Returns:
            str: Path to executive summary
        """

    def generate_bug_bounty_report(self, vulnerability: Vulnerability, platform: str) -> str:
        """
        Generate bug bounty platform report

        Args:
            vulnerability: Vulnerability to report
            platform: Platform (hackerone, bugcrowd, etc.)

        Returns:
            str: Formatted report for platform
        """

    def export_vulnerabilities(self, vulnerabilities: QuerySet, format: str) -> str:
        """
        Export vulnerabilities to various formats

        Args:
            vulnerabilities: Vulnerability queryset
            format: Export format (csv, json, xml, pdf)

        Returns:
            str: Path to export file
        """

    def generate_compliance_report(self, scan_session: ScanSession, standard: str) -> str:
        """
        Generate compliance report

        Args:
            scan_session: Scan session
            standard: Compliance standard (pci_dss, hipaa, etc.)

        Returns:
            str: Path to compliance report
        """

    def add_executive_summary(self, report_id: int, summary: str) -> None:
        """Add executive summary to report"""

    def customize_report_template(self, template_name: str, customizations: dict) -> None:
        """Customize report template"""
```

**Report Types**:
- **Technical**: Detailed findings with PoCs
- **Executive**: High-level summary for management
- **Bug Bounty**: Platform-specific format
- **Compliance**: Standards-based (PCI DSS, HIPAA)

**Export Formats**:
- PDF (professional reports)
- HTML (web-viewable)
- JSON (programmatic access)
- CSV (spreadsheet import)
- XML (data exchange)
- Markdown (documentation)

### Notification Service

**Location**: `backend/services/notification_service.py`

Manages notifications and alerts.

```python
class NotificationService:
    """Service for notifications and alerts"""

    @staticmethod
    def send_notification(notification_type: str, data: dict, channels: list = None) -> None:
        """
        Send notification through multiple channels

        Args:
            notification_type: Type of notification
            data: Notification data
            channels: Channels to use (email, slack, webhook)
        """

    @staticmethod
    def send_scan_started_notification(scan_session: ScanSession) -> None:
        """Notify scan started"""

    @staticmethod
    def send_scan_completed_notification(scan_session: ScanSession) -> None:
        """Notify scan completed"""

    @staticmethod
    def send_vulnerability_found_notification(vulnerability: Vulnerability) -> None:
        """Notify vulnerability discovered"""

    @staticmethod
    def send_critical_vulnerability_alert(vulnerability: Vulnerability) -> None:
        """Send urgent alert for critical vulnerability"""

    @staticmethod
    def send_email(to: str, subject: str, body: str, attachments: list = None) -> bool:
        """Send email notification"""

    @staticmethod
    def send_slack_message(channel: str, message: str, blocks: list = None) -> bool:
        """Send Slack notification"""

    @staticmethod
    def send_webhook(url: str, payload: dict, headers: dict = None) -> bool:
        """Send webhook notification"""
```

**Notification Types**:
- `scan_started` - Scan initiated
- `scan_completed` - Scan finished
- `vulnerability_found` - New vulnerability
- `critical_vulnerability_found` - Critical vuln alert
- `scan_failed` - Scan error
- `report_generated` - Report ready

**Channels**:
- Email (SMTP)
- Slack (Webhook)
- Discord (Webhook)
- Custom Webhooks
- Database (for in-app notifications)

### Callback Server

**Location**: `backend/services/callback_server.py`

Out-of-band interaction detection.

```python
class CallbackServer:
    """Service for callback/interaction detection"""

    def generate_callback_identifier(self) -> str:
        """
        Generate unique callback identifier

        Returns:
            str: Unique identifier
        """

    def register_callback(self, vulnerability_id: int, callback_type: str) -> dict:
        """
        Register callback for vulnerability

        Args:
            vulnerability_id: Vulnerability ID
            callback_type: Type (http, dns, smtp)

        Returns:
            dict: {
                'callback_url': str,
                'callback_dns': str,
                'identifier': str
            }
        """

    def handle_http_callback(self, identifier: str, request_data: dict) -> None:
        """
        Handle HTTP callback

        Args:
            identifier: Callback identifier
            request_data: HTTP request data
        """

    def handle_dns_callback(self, identifier: str, dns_query: dict) -> None:
        """
        Handle DNS callback

        Args:
            identifier: Callback identifier
            dns_query: DNS query data
        """

    def get_callback_data(self, identifier: str) -> dict:
        """
        Retrieve callback data

        Args:
            identifier: Callback identifier

        Returns:
            dict: Callback data if received
        """

    def cleanup_old_callbacks(self, days: int = 7) -> int:
        """
        Clean up old callbacks

        Args:
            days: Age threshold in days

        Returns:
            int: Number of callbacks removed
        """
```

**Use Cases**:
- Blind SSRF verification
- Blind XSS detection
- Blind XXE exploitation
- DNS exfiltration
- Email callback verification

**Callback URLs**:
```
HTTP: https://callback.bughunt.local/c/{identifier}
DNS:  {identifier}.callback.bughunt.local
```

### Scan Scheduler

**Location**: `backend/services/scan_scheduler.py`

Manages scan scheduling and queuing.

```python
class ScanScheduler:
    """Service for scan scheduling"""

    def schedule_scan(self, scan_session: ScanSession, schedule_time: datetime) -> bool:
        """
        Schedule scan for future execution

        Args:
            scan_session: Scan session
            schedule_time: When to execute

        Returns:
            bool: True if scheduled successfully
        """

    def schedule_recurring_scan(
        self,
        target: Target,
        cron_expression: str,
        scan_config: dict
    ) -> dict:
        """
        Schedule recurring scan

        Args:
            target: Target to scan
            cron_expression: Cron schedule
            scan_config: Scan configuration

        Returns:
            dict: Schedule details
        """

    def cancel_scheduled_scan(self, schedule_id: int) -> bool:
        """Cancel scheduled scan"""

    def get_scheduled_scans(self, target: Target = None) -> list:
        """
        Get scheduled scans

        Args:
            target: Optional target filter

        Returns:
            list: Scheduled scans
        """

    def execute_scheduled_scan(self, schedule_id: int) -> ScanSession:
        """
        Execute scheduled scan

        Args:
            schedule_id: Schedule ID

        Returns:
            ScanSession: Created scan session
        """

    def manage_scan_queue(self) -> dict:
        """
        Manage scan queue and priority

        Returns:
            dict: Queue statistics
        """
```

**Features**:
- One-time scheduled scans
- Recurring scans (cron-based)
- Priority queue management
- Concurrent scan limits
- Auto-retry on failure

## Vulnerability Services

### Evidence Service

**Location**: `backend/services/vulnerability_services/evidence.py`

Manages vulnerability evidence collection.

```python
class EvidenceService:
    """Service for evidence management"""

    def add_screenshot(self, vulnerability: Vulnerability, screenshot_path: str) -> None:
        """Add screenshot evidence"""

    def add_http_request_response(
        self,
        vulnerability: Vulnerability,
        request: str,
        response: str
    ) -> None:
        """Add HTTP request/response evidence"""

    def add_raw_evidence(self, vulnerability: Vulnerability, evidence: str) -> None:
        """Add raw evidence data"""

    def collect_automated_evidence(self, vulnerability: Vulnerability) -> dict:
        """
        Automatically collect evidence

        Returns:
            dict: Collected evidence
        """

    def generate_evidence_report(self, vulnerability: Vulnerability) -> str:
        """
        Generate evidence report

        Returns:
            str: Path to evidence report
        """

    def validate_evidence(self, evidence_data: dict) -> bool:
        """Validate evidence completeness"""
```

**Evidence Types**:
- Screenshots
- HTTP requests/responses
- Raw tool output
- Exploit payloads
- Callback data
- Video recordings

## Service Integration Examples

### Complete Scan Workflow

```python
from services.scanning_service import ScanningService
from services.notification_service import NotificationService
from services.reporting_service import ReportingService

# Initialize services
scanning_service = ScanningService()
notification_service = NotificationService()
reporting_service = ReportingService()

# Create scan
scan = ScanSession.objects.create(
    target_id=1,
    session_name="Monthly Security Scan",
    workflow_type="standard"
)

# Send start notification
notification_service.send_scan_started_notification(scan)

# Execute scan
await scanning_service.execute_scan_session(scan)

# Generate report
report_path = reporting_service.generate_technical_report(
    scan_session=scan,
    format='pdf'
)

# Send completion notification
notification_service.send_scan_completed_notification(scan)
```

### Vulnerability Analysis & Reporting

```python
from services.vulnerability_analyzer import VulnerabilityAnalyzer
from services.exploitation_service import ExploitationService
from services.reporting_service import ReportingService

analyzer = VulnerabilityAnalyzer()
exploit_service = ExploitationService()
reporting_service = ReportingService()

# Get vulnerability
vuln = Vulnerability.objects.get(id=1)

# Analyze
analysis = analyzer.comprehensive_analysis(vuln)

# Verify
verification = exploit_service.verify_vulnerability(vuln)

# Generate bug bounty report
report = reporting_service.generate_bug_bounty_report(
    vulnerability=vuln,
    platform='hackerone'
)
```

## Creating New Services

### Service Template

```python
from typing import Optional
from apps.targets.models import Target

class NewService:
    """
    Service for [specific functionality]

    Attributes:
        dependency: Description of dependency
    """

    def __init__(self):
        """Initialize service with dependencies"""
        self.dependency = SomeDependency()

    def primary_operation(
        self,
        target: Target,
        param: str,
        optional_param: Optional[str] = None
    ) -> dict:
        """
        Description of operation

        Args:
            target: Target instance
            param: Required parameter
            optional_param: Optional parameter

        Returns:
            dict: Result of operation

        Raises:
            ServiceException: On operation failure
            ValidationError: On invalid input
        """
        # Input validation
        if not param:
            raise ValidationError("param is required")

        # Business logic
        result = self._internal_operation(target, param)

        # Return result
        return {
            'success': True,
            'data': result
        }

    def _internal_operation(self, target: Target, param: str):
        """Internal helper method"""
        # Implementation
        pass
```

### Service Best Practices

1. **Single Responsibility**: Each service handles one domain
2. **Stateless**: No instance state between operations
3. **Dependency Injection**: Pass dependencies in constructor
4. **Error Handling**: Raise specific exceptions
5. **Documentation**: Comprehensive docstrings
6. **Type Hints**: Use type hints for all methods
7. **Testing**: Unit test all public methods
8. **Logging**: Log important operations

### Testing Services

```python
import pytest
from services.target_service import TargetService
from apps.targets.models import Target

@pytest.mark.django_db
class TestTargetService:
    """Test suite for TargetService"""

    def test_validate_scope_in_scope(self):
        """Test scope validation for in-scope asset"""
        target = Target.objects.create(
            target_name="test",
            main_url="https://example.com",
            in_scope_urls=["https://example.com/*"]
        )

        result = TargetService.validate_scope(
            target=target,
            asset="https://example.com/api/users"
        )

        assert result['in_scope'] is True
        assert result['matched_rule'] == "https://example.com/*"

    def test_validate_scope_out_of_scope(self):
        """Test scope validation for out-of-scope asset"""
        target = Target.objects.create(
            target_name="test",
            main_url="https://example.com",
            in_scope_urls=["https://example.com/*"],
            out_of_scope_urls=["https://example.com/admin/*"]
        )

        result = TargetService.validate_scope(
            target=target,
            asset="https://example.com/admin/users"
        )

        assert result['in_scope'] is False
```

## Service Dependencies Graph

```
NotificationService
    ↑
    |
ScanningService ← → VulnerabilityScanner
    ↑                       ↑
    |                       |
ReportingService    VulnerabilityAnalyzer
    ↑                       ↑
    |                       |
TargetService      ExploitationService
                            ↑
                            |
                    CallbackServer
                            ↑
                            |
                    ReconService
```

All services can be used independently or composed for complex workflows.
