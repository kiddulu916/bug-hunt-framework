# Database Models

## Overview

The Bug Hunt Framework uses Django ORM models with PostgreSQL as the primary database. All models are organized into Django apps based on domain responsibility.

## Model Relationships Diagram

```
┌──────────────┐          ┌──────────────────┐
│    Target    │◄────────┤   ScanSession    │
└──────────────┘          └──────────────────┘
                                   │
                                   ▼
                          ┌──────────────────┐
                          │  ToolExecution   │
                          └──────────────────┘
                                   │
                                   ▼
                          ┌──────────────────┐
                          │   ReconResult    │
                          └──────────────────┘
                                   │
                                   ▼
┌──────────────┐          ┌──────────────────┐
│Vulnerability │◄────────┤  ScanSession     │
└──────────────┘          └──────────────────┘
       │
       ▼
┌──────────────────┐
│ExploitationChain │
└──────────────────┘
       │
       ▼
┌──────────────┐
│ExploitAttempt│
└──────────────┘
       │
       ▼
┌──────────────┐
│    Report    │
└──────────────┘
```

## Target Management

### Target Model
**Location**: `backend/apps/targets/models.py`

Represents bug bounty programs and penetration testing targets.

```python
class Target(models.Model):
    # Basic Information
    target_name: CharField(max_length=255, unique=True)
    main_url: URLField
    platform: CharField(choices=BugBountyPlatform.choices)

    # Scope Definition
    in_scope_urls: JSONField(default=list)
    out_of_scope_urls: JSONField(default=list)
    in_scope_assets: JSONField(default=list)
    out_of_scope_assets: JSONField(default=list)

    # Configuration
    scan_config: JSONField(default=dict)
    rate_limit: IntegerField(default=10)  # requests per second

    # Status
    is_active: BooleanField(default=True)

    # Metadata
    created_at: DateTimeField(auto_now_add=True)
    updated_at: DateTimeField(auto_now=True)
```

**Fields**:
- `target_name`: Unique identifier for the target
- `main_url`: Primary URL/domain for the target
- `platform`: Bug bounty platform (HackerOne, Bugcrowd, Intigriti, etc.)
- `in_scope_urls`: List of in-scope URL patterns
- `out_of_scope_urls`: List of out-of-scope URL patterns
- `in_scope_assets`: Additional in-scope assets (IPs, domains)
- `out_of_scope_assets`: Excluded assets
- `scan_config`: Tool-specific scan configuration
- `rate_limit`: Maximum requests per second
- `is_active`: Target activation status

**Platform Choices** (`BugBountyPlatform`):
- `HACKERONE` - HackerOne
- `BUGCROWD` - Bugcrowd
- `INTIGRITI` - Intigriti
- `YESWEHACK` - YesWeHack
- `SYNACK` - Synack
- `PRIVATE` - Private program
- `OTHER` - Other platforms

**Methods**:
- `validate_scope(asset: str) -> bool`: Check if asset is in scope
- `get_scan_configuration() -> dict`: Generate scan config
- `test_connectivity() -> bool`: Test target availability

**Relationships**:
- One-to-many with `ScanSession`
- One-to-many with `Vulnerability` (through ScanSession)

## Scanning Management

### ScanSession Model
**Location**: `backend/apps/scanning/models.py`

Represents a complete vulnerability scan execution.

```python
class ScanSession(models.Model):
    # Identification
    session_name: CharField(max_length=255)
    target: ForeignKey(Target, on_delete=CASCADE, related_name='scan_sessions')

    # Configuration
    methodology_phases: JSONField(default=list)
    scan_config: JSONField(default=dict)
    workflow_type: CharField(choices=WorkflowType.choices, default='STANDARD')

    # Status Tracking
    status: CharField(choices=ScanStatus.choices, default='QUEUED')
    current_phase: CharField(max_length=100, blank=True)
    progress_percentage: DecimalField(max_digits=5, decimal_places=2, default=0)

    # Timing
    started_at: DateTimeField(null=True, blank=True)
    completed_at: DateTimeField(null=True, blank=True)
    total_duration: DurationField(null=True, blank=True)

    # Results
    findings_count: IntegerField(default=0)
    critical_count: IntegerField(default=0)
    high_count: IntegerField(default=0)
    medium_count: IntegerField(default=0)
    low_count: IntegerField(default=0)

    # Metadata
    created_by: ForeignKey(User, on_delete=SET_NULL, null=True)
    created_at: DateTimeField(auto_now_add=True)
    updated_at: DateTimeField(auto_now=True)
```

**Status Choices** (`ScanStatus`):
- `QUEUED` - Waiting to start
- `RUNNING` - Currently executing
- `PAUSED` - Temporarily paused
- `COMPLETED` - Successfully finished
- `FAILED` - Failed with errors
- `CANCELLED` - Manually cancelled

**Workflow Types** (`WorkflowType`):
- `STANDARD` - Full 7-phase scan
- `QUICK` - Fast scan (recon + basic vuln testing)
- `DEEP` - Comprehensive scan with fuzzing
- `CUSTOM` - User-defined phases

**Methodology Phases**:
1. `INITIALIZATION` - Setup and validation
2. `PASSIVE_RECON` - Passive reconnaissance
3. `ACTIVE_RECON` - Active reconnaissance
4. `VULNERABILITY_TESTING` - Security testing
5. `EXPLOITATION` - Verification
6. `REPORTING` - Report generation
7. `CLEANUP` - Resource cleanup

**Methods**:
- `calculate_progress() -> Decimal`: Calculate completion percentage
- `update_findings_count()`: Update vulnerability counts
- `get_duration() -> timedelta`: Get scan duration
- `can_pause() -> bool`: Check if pauseable
- `can_resume() -> bool`: Check if resumable

**Relationships**:
- Many-to-one with `Target`
- One-to-many with `ToolExecution`
- One-to-many with `ReconResult`
- One-to-many with `Vulnerability`

### ToolExecution Model
**Location**: `backend/apps/scanning/models.py`

Tracks individual security tool executions within a scan.

```python
class ToolExecution(models.Model):
    # Relationships
    scan_session: ForeignKey(ScanSession, on_delete=CASCADE, related_name='tool_executions')

    # Tool Information
    tool_name: CharField(max_length=100)
    tool_category: CharField(choices=ToolCategory.choices)
    tool_version: CharField(max_length=50, blank=True)

    # Execution Details
    command_executed: TextField()
    status: CharField(choices=ExecutionStatus.choices, default='PENDING')

    # Output
    output_file_path: FilePathField(blank=True)
    stdout: TextField(blank=True)
    stderr: TextField(blank=True)
    exit_code: IntegerField(null=True, blank=True)

    # Results
    findings_count: IntegerField(default=0)
    errors_encountered: JSONField(default=list)

    # Timing
    started_at: DateTimeField(null=True, blank=True)
    completed_at: DateTimeField(null=True, blank=True)
    duration: DurationField(null=True, blank=True)
```

**Tool Categories** (`ToolCategory`):
- `RECON` - Reconnaissance tools
- `SCANNER` - Vulnerability scanners
- `FUZZER` - Fuzzing tools
- `EXPLOIT` - Exploitation tools
- `UTILITY` - Utility tools

**Execution Status**:
- `PENDING` - Not started
- `RUNNING` - Currently executing
- `COMPLETED` - Finished successfully
- `FAILED` - Failed with error
- `TIMEOUT` - Exceeded time limit

**Methods**:
- `get_output() -> str`: Read output file
- `calculate_duration() -> timedelta`: Calculate execution time
- `parse_results() -> dict`: Parse tool output

## Reconnaissance

### ReconResult Model
**Location**: `backend/apps/reconnaissance/models.py`

Stores discovered assets during reconnaissance.

```python
class ReconResult(models.Model):
    # Relationships
    scan_session: ForeignKey(ScanSession, on_delete=CASCADE, related_name='recon_results')
    target: ForeignKey(Target, on_delete=CASCADE, related_name='recon_results')

    # Asset Information
    asset_type: CharField(choices=AssetType.choices)
    asset_value: CharField(max_length=1024)

    # Discovery Details
    discovery_method: CharField(max_length=100)
    tool_used: CharField(max_length=100, blank=True)
    confidence_score: DecimalField(max_digits=5, decimal_places=2)

    # Metadata
    technologies_detected: JSONField(default=list)
    response_data: JSONField(default=dict)
    dns_records: JSONField(default=dict)
    ssl_info: JSONField(default=dict)

    # Validation
    is_verified: BooleanField(default=False)
    is_in_scope: BooleanField(default=True)

    # Timestamps
    discovered_at: DateTimeField(auto_now_add=True)
    last_seen: DateTimeField(auto_now=True)
```

**Asset Types** (`AssetType`):
- `SUBDOMAIN` - Subdomain discovery
- `URL` - URL/endpoint
- `IP_ADDRESS` - IP address
- `PORT` - Open port
- `EMAIL` - Email address
- `TECHNOLOGY` - Technology stack
- `PARAMETER` - URL parameter
- `CREDENTIAL` - Found credential
- `API_ENDPOINT` - API endpoint

**Discovery Methods**:
- `passive_dns` - Passive DNS enumeration
- `active_dns` - Active DNS brute-force
- `certificate_transparency` - CT logs
- `web_crawling` - Web crawler
- `port_scanning` - Port scan
- `api_discovery` - API enumeration

**Methods**:
- `verify_asset() -> bool`: Verify asset exists
- `update_metadata(data: dict)`: Update asset metadata
- `check_scope() -> bool`: Validate against target scope

## Vulnerability Management

### Vulnerability Model
**Location**: `backend/apps/vulnerabilities/models.py`

Core model for vulnerability tracking and management.

```python
class Vulnerability(models.Model):
    # Relationships
    scan_session: ForeignKey(ScanSession, on_delete=CASCADE, related_name='vulnerabilities')
    target: ForeignKey(Target, on_delete=CASCADE, related_name='vulnerabilities')

    # Identification
    vulnerability_name: CharField(max_length=500)
    vulnerability_type: CharField(max_length=100)

    # Classification
    severity: CharField(choices=Severity.choices)
    cvss_score: DecimalField(max_digits=3, decimal_places=1, null=True)
    confidence_level: CharField(choices=ConfidenceLevel.choices)

    # Standards Mapping
    cwe_id: CharField(max_length=20, blank=True)
    owasp_category: CharField(max_length=100, blank=True)

    # Location
    affected_url: URLField()
    affected_parameter: CharField(max_length=255, blank=True)
    affected_component: CharField(max_length=255, blank=True)

    # Technical Details
    description: TextField()
    impact_description: TextField()
    remediation: TextField()
    references: JSONField(default=list)

    # Evidence
    proof_of_concept: TextField(blank=True)
    screenshot_paths: JSONField(default=list)
    raw_evidence: TextField(blank=True)
    http_requests: JSONField(default=list)
    http_responses: JSONField(default=list)

    # Verification
    manually_verified: BooleanField(default=False)
    verification_notes: TextField(blank=True)
    false_positive: BooleanField(default=False)

    # Discovery
    discovered_by: CharField(max_length=100)
    discovered_at: DateTimeField(auto_now_add=True)

    # Status
    status: CharField(choices=VulnStatus.choices, default='NEW')
    reported_to_platform: BooleanField(default=False)
    bounty_amount: DecimalField(max_digits=10, decimal_places=2, null=True)
```

**Severity Levels** (`Severity`):
- `CRITICAL` - Critical risk (CVSS 9.0-10.0)
- `HIGH` - High risk (CVSS 7.0-8.9)
- `MEDIUM` - Medium risk (CVSS 4.0-6.9)
- `LOW` - Low risk (CVSS 0.1-3.9)
- `INFO` - Informational (CVSS 0.0)

**Confidence Levels** (`ConfidenceLevel`):
- `CONFIRMED` - Manually verified (100%)
- `HIGH` - High confidence (80-99%)
- `MEDIUM` - Medium confidence (50-79%)
- `LOW` - Low confidence (<50%)
- `FALSE_POSITIVE` - Confirmed false positive

**Vulnerability Status** (`VulnStatus`):
- `NEW` - Newly discovered
- `VERIFIED` - Verified as valid
- `REPORTED` - Reported to platform
- `TRIAGED` - Triaged by program
- `RESOLVED` - Fixed by program
- `DUPLICATE` - Duplicate of another
- `INVALID` - Invalid/false positive

**Common Vulnerability Types**:
- SQL Injection
- Cross-Site Scripting (XSS)
- Cross-Site Request Forgery (CSRF)
- Authentication Bypass
- Authorization Bypass
- Server-Side Request Forgery (SSRF)
- Remote Code Execution (RCE)
- Local File Inclusion (LFI)
- XML External Entity (XXE)
- Insecure Deserialization

**Methods**:
- `calculate_cvss_score() -> Decimal`: Auto-calculate CVSS
- `generate_report() -> str`: Generate vulnerability report
- `add_evidence(evidence_type: str, data: dict)`: Add evidence
- `verify(notes: str)`: Mark as manually verified
- `mark_false_positive(reason: str)`: Flag as false positive

### ExploitationChain Model
**Location**: `backend/apps/exploitation/models.py`

Represents multi-step vulnerability exploitation chains.

```python
class ExploitationChain(models.Model):
    # Relationships
    vulnerability: ForeignKey(Vulnerability, on_delete=CASCADE, related_name='exploitation_chains')

    # Chain Information
    chain_name: CharField(max_length=255)
    description: TextField()

    # Steps
    step_number: IntegerField()
    step_description: TextField()
    payload_used: TextField(blank=True)
    expected_result: TextField()

    # Analysis
    success_probability: DecimalField(max_digits=5, decimal_places=2)
    impact_level: CharField(choices=ImpactLevel.choices)

    # Metadata
    created_at: DateTimeField(auto_now_add=True)
```

**Impact Levels** (`ImpactLevel`):
- `CRITICAL` - Complete system compromise
- `HIGH` - Significant data access
- `MEDIUM` - Limited access
- `LOW` - Minimal impact

**Methods**:
- `execute_step() -> dict`: Execute single step
- `validate_chain() -> bool`: Validate exploitation path

## Exploitation

### ExploitAttempt Model
**Location**: `backend/apps/exploitation/models.py`

Tracks exploitation and verification attempts.

```python
class ExploitAttempt(models.Model):
    # Relationships
    vulnerability: ForeignKey(Vulnerability, on_delete=CASCADE, related_name='exploit_attempts')
    exploitation_chain: ForeignKey(ExploitationChain, on_delete=SET_NULL, null=True)

    # Attempt Details
    exploit_type: CharField(max_length=100)
    payload_used: TextField()

    # Execution
    executed_at: DateTimeField(auto_now_add=True)
    success_status: CharField(choices=SuccessStatus.choices)

    # Results
    result_data: JSONField(default=dict)
    callback_received: BooleanField(default=False)
    callback_data: JSONField(default=dict)

    # Impact Assessment
    impact_assessment: TextField()
    evidence_collected: JSONField(default=list)

    # Safety
    is_safe: BooleanField(default=True)
    risk_level: CharField(choices=RiskLevel.choices)
```

**Success Status**:
- `SUCCESS` - Exploit successful
- `PARTIAL` - Partial success
- `FAILED` - Failed attempt
- `ERROR` - Error during execution

**Risk Levels** (`RiskLevel`):
- `SAFE` - No impact to production
- `LOW_RISK` - Minimal impact
- `MEDIUM_RISK` - Moderate impact
- `HIGH_RISK` - Significant impact
- `UNSAFE` - Potential damage

**Methods**:
- `validate_safety() -> bool`: Pre-execution safety check
- `record_callback(data: dict)`: Record callback data
- `assess_impact() -> str`: Generate impact assessment

## Reporting

### Report Model
**Location**: `backend/apps/reporting/models.py`

Professional vulnerability reports.

```python
class Report(models.Model):
    # Relationships
    scan_session: ForeignKey(ScanSession, on_delete=CASCADE, related_name='reports')
    target: ForeignKey(Target, on_delete=CASCADE, related_name='reports')

    # Report Information
    report_name: CharField(max_length=255)
    report_type: CharField(choices=ReportType.choices)
    format: CharField(choices=ReportFormat.choices)

    # Content
    summary: TextField()
    executive_summary: TextField(blank=True)
    findings_summary: JSONField(default=dict)
    recommendations: TextField(blank=True)

    # File Information
    file_path: FilePathField()
    file_size: BigIntegerField()

    # Metadata
    generated_at: DateTimeField(auto_now_add=True)
    generated_by: ForeignKey(User, on_delete=SET_NULL, null=True)
```

**Report Types** (`ReportType`):
- `TECHNICAL` - Technical vulnerability report
- `EXECUTIVE` - Executive summary
- `BUG_BOUNTY` - Bug bounty platform report
- `COMPLIANCE` - Compliance report (PCI, HIPAA, etc.)
- `CUSTOM` - Custom format

**Report Formats** (`ReportFormat`):
- `PDF` - PDF document
- `HTML` - HTML report
- `JSON` - JSON export
- `XML` - XML export
- `CSV` - CSV spreadsheet
- `MARKDOWN` - Markdown format

**Methods**:
- `generate() -> str`: Generate report file
- `include_vulnerabilities(vulns: QuerySet)`: Add vulnerabilities
- `add_executive_summary(summary: str)`: Add exec summary
- `export_to_platform(platform: str) -> bool`: Export to bug bounty platform

## Database Indexes

Performance-critical indexes:

```python
# Target Model
class Meta:
    indexes = [
        Index(fields=['target_name']),
        Index(fields=['platform']),
        Index(fields=['is_active']),
        Index(fields=['created_at']),
    ]

# ScanSession Model
class Meta:
    indexes = [
        Index(fields=['target', 'status']),
        Index(fields=['status', 'created_at']),
        Index(fields=['created_by']),
    ]

# Vulnerability Model
class Meta:
    indexes = [
        Index(fields=['severity', 'discovered_at']),
        Index(fields=['target', 'status']),
        Index(fields=['vulnerability_type']),
        Index(fields=['cvss_score']),
        Index(fields=['manually_verified', 'false_positive']),
    ]

# ReconResult Model
class Meta:
    indexes = [
        Index(fields=['asset_type', 'is_in_scope']),
        Index(fields=['scan_session']),
        Index(fields=['confidence_score']),
    ]
```

## Constraints and Validations

### Model-Level Constraints

```python
# Target - Unique target names
class Meta:
    constraints = [
        UniqueConstraint(fields=['target_name'], name='unique_target_name')
    ]

# Vulnerability - Prevent duplicates
class Meta:
    constraints = [
        UniqueConstraint(
            fields=['target', 'vulnerability_type', 'affected_url', 'affected_parameter'],
            name='unique_vulnerability'
        )
    ]

# ReconResult - Unique assets per scan
class Meta:
    constraints = [
        UniqueConstraint(
            fields=['scan_session', 'asset_type', 'asset_value'],
            name='unique_recon_result'
        )
    ]
```

### Field Validators

```python
from django.core.validators import MinValueValidator, MaxValueValidator, URLValidator

# CVSS Score validation (0.0 - 10.0)
cvss_score = DecimalField(
    validators=[MinValueValidator(0.0), MaxValueValidator(10.0)]
)

# Rate limit validation (1-1000 req/sec)
rate_limit = IntegerField(
    validators=[MinValueValidator(1), MaxValueValidator(1000)]
)

# URL validation
affected_url = URLField(validators=[URLValidator()])

# Confidence score (0-100)
confidence_score = DecimalField(
    validators=[MinValueValidator(0), MaxValueValidator(100)]
)
```

## Signals and Events

### Pre-Save Signals

```python
@receiver(pre_save, sender=Vulnerability)
def calculate_cvss_before_save(sender, instance, **kwargs):
    """Auto-calculate CVSS score if not set"""
    if not instance.cvss_score:
        instance.cvss_score = instance.calculate_cvss_score()

@receiver(pre_save, sender=ScanSession)
def update_scan_duration(sender, instance, **kwargs):
    """Update total duration on save"""
    if instance.started_at and instance.completed_at:
        instance.total_duration = instance.completed_at - instance.started_at
```

### Post-Save Signals

```python
@receiver(post_save, sender=Vulnerability)
def notify_critical_vulnerability(sender, instance, created, **kwargs):
    """Send notification for critical vulnerabilities"""
    if created and instance.severity == 'CRITICAL':
        NotificationService.send_notification(
            type='critical_vulnerability_found',
            data={'vulnerability_id': instance.id}
        )

@receiver(post_save, sender=ScanSession)
def update_target_statistics(sender, instance, **kwargs):
    """Update target statistics after scan"""
    if instance.status == 'COMPLETED':
        instance.target.update_statistics()
```

## Query Optimization Tips

### Use select_related() for Foreign Keys

```python
# Good - Single query with JOIN
vulnerabilities = Vulnerability.objects.select_related(
    'target', 'scan_session'
).all()

# Bad - N+1 queries
vulnerabilities = Vulnerability.objects.all()
for vuln in vulnerabilities:
    print(vuln.target.name)  # Additional query per iteration
```

### Use prefetch_related() for Reverse Relations

```python
# Good - Two queries total
targets = Target.objects.prefetch_related('vulnerabilities').all()

# Bad - N+1 queries
targets = Target.objects.all()
for target in targets:
    vulns = target.vulnerabilities.all()  # Query per target
```

### Filter in Database, Not Python

```python
# Good - Database filtering
critical_vulns = Vulnerability.objects.filter(severity='CRITICAL')

# Bad - Loads all into memory
all_vulns = Vulnerability.objects.all()
critical_vulns = [v for v in all_vulns if v.severity == 'CRITICAL']
```

### Use only() and defer() for Large Models

```python
# Only load specific fields
vulns = Vulnerability.objects.only(
    'id', 'vulnerability_name', 'severity'
)

# Defer loading heavy fields
vulns = Vulnerability.objects.defer(
    'raw_evidence', 'proof_of_concept'
)
```

## Migration Best Practices

### Safe Migrations

```python
# Always provide defaults for new fields
class Migration(migrations.Migration):
    operations = [
        migrations.AddField(
            model_name='vulnerability',
            name='new_field',
            field=models.CharField(max_length=100, default=''),
        ),
    ]

# Use RunPython for data migrations
def migrate_data(apps, schema_editor):
    Vulnerability = apps.get_model('vulnerabilities', 'Vulnerability')
    for vuln in Vulnerability.objects.all():
        # Migrate data
        vuln.new_field = calculate_value(vuln)
        vuln.save()

class Migration(migrations.Migration):
    operations = [
        migrations.RunPython(migrate_data),
    ]
```

### Index Creation

```python
# Add indexes in separate migration for large tables
class Migration(migrations.Migration):
    operations = [
        migrations.AddIndex(
            model_name='vulnerability',
            index=models.Index(fields=['severity', 'discovered_at']),
        ),
    ]
```
