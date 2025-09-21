"""
Model factories for Bug Bounty Automation Platform tests using factory_boy
"""

import factory
import uuid
from datetime import datetime, timedelta
from django.contrib.auth import get_user_model
from factory.django import DjangoModelFactory
from factory import Faker, SubFactory, LazyAttribute, LazyFunction

from apps.targets.models import Target, BugBountyPlatform
from apps.vulnerabilities.models import (
    Vulnerability, VulnSeverity, ExploitationDifficulty,
    RemediationPriority, ExploitationChain
)
from apps.scanning.models import ScanSession, ScanStatus, ToolExecution, ToolStatus
from apps.exploitation.models import (
    ExploitationSession, ExploitResult, ExploitChain, ExploitTemplate,
    ExploitationType, ExploitationStatus, ExploitationSeverity
)
from apps.reconnaissance.models import ReconSession, ReconResult
from apps.reporting.models import Report, ReportFormat, ReportStatus

User = get_user_model()


class UserFactory(DjangoModelFactory):
    """Factory for creating test users"""

    class Meta:
        model = User

    username = Faker('user_name')
    email = Faker('email')
    first_name = Faker('first_name')
    last_name = Faker('last_name')
    is_active = True
    is_staff = False
    is_superuser = False


class AdminUserFactory(UserFactory):
    """Factory for creating admin users"""

    is_staff = True
    is_superuser = True
    username = 'admin'
    email = 'admin@bugbounty.local'


class TargetFactory(DjangoModelFactory):
    """Factory for creating test targets"""

    class Meta:
        model = Target

    target_name = Faker('company')
    platform = factory.Iterator([choice[0] for choice in BugBountyPlatform.choices])
    researcher_username = Faker('user_name')
    main_url = Faker('url')
    wildcard_url = factory.LazyAttribute(
        lambda obj: f"*.{obj.main_url.split('://')[1]}" if obj.main_url else None
    )

    # Scope arrays
    in_scope_urls = factory.LazyAttribute(
        lambda obj: [obj.main_url, f"api.{obj.main_url.split('://')[1]}"]
    )
    out_of_scope_urls = factory.LazyAttribute(
        lambda obj: [f"blog.{obj.main_url.split('://')[1]}"]
    )
    in_scope_assets = ['192.168.1.0/24', '10.0.0.0/16']
    out_of_scope_assets = ['192.168.1.100', '10.0.0.1']

    # Rate limiting
    requests_per_second = factory.Faker('pyfloat', min_value=1.0, max_value=10.0)
    concurrent_requests = factory.Faker('pyint', min_value=5, max_value=50)
    request_delay_ms = factory.Faker('pyint', min_value=100, max_value=1000)

    # Headers
    required_headers = factory.LazyFunction(
        lambda: {'User-Agent': 'BugBountyBot/1.0', 'Accept': 'application/json'}
    )
    authentication_headers = factory.LazyFunction(
        lambda: {'Authorization': 'Bearer fake-token-for-testing'}
    )
    user_agents = [
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36',
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36'
    ]

    # Notes
    program_notes = Faker('text', max_nb_chars=500)
    special_requirements = Faker('text', max_nb_chars=200)
    pii_redaction_rules = factory.LazyFunction(
        lambda: {'email_pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'}
    )

    is_active = True


class ScanSessionFactory(DjangoModelFactory):
    """Factory for creating test scan sessions"""

    class Meta:
        model = ScanSession

    target = SubFactory(TargetFactory)
    session_name = Faker('sentence', nb_words=4)
    status = factory.Iterator([choice[0] for choice in ScanStatus.choices])

    scan_config = factory.LazyFunction(
        lambda: {
            'tools': ['nuclei', 'nmap', 'amass', 'subfinder'],
            'intensity': 'medium',
            'concurrent_scans': 5,
            'timeout': 3600
        }
    )
    methodology_phases = [
        'reconnaissance', 'enumeration', 'vulnerability_scanning',
        'exploitation', 'post_exploitation', 'reporting'
    ]

    current_phase = factory.Iterator(methodology_phases)
    phase_progress = factory.LazyFunction(
        lambda: {
            'reconnaissance': 100,
            'enumeration': 75,
            'vulnerability_scanning': 50,
            'exploitation': 25,
            'post_exploitation': 0,
            'reporting': 0
        }
    )
    total_progress = factory.Faker('pyfloat', min_value=0.0, max_value=100.0)

    # Results summary
    total_subdomains_found = factory.Faker('pyint', min_value=0, max_value=100)
    total_endpoints_found = factory.Faker('pyint', min_value=0, max_value=500)
    total_vulnerabilities = factory.Faker('pyint', min_value=0, max_value=50)
    critical_vulnerabilities = factory.Faker('pyint', min_value=0, max_value=5)
    high_vulnerabilities = factory.Faker('pyint', min_value=0, max_value=15)


class ToolExecutionFactory(DjangoModelFactory):
    """Factory for creating test tool executions"""

    class Meta:
        model = ToolExecution

    scan_session = SubFactory(ScanSessionFactory)
    tool_name = factory.Iterator([
        'nuclei', 'nmap', 'amass', 'subfinder', 'httpx', 'gobuster',
        'ffuf', 'sqlmap', 'nikto', 'masscan'
    ])
    tool_category = factory.Iterator([
        'reconnaissance', 'vulnerability_scanning', 'enumeration',
        'exploitation', 'post_exploitation'
    ])
    command_executed = factory.LazyAttribute(
        lambda obj: f"{obj.tool_name} -u {obj.scan_session.target.main_url}"
    )
    status = factory.Iterator([choice[0] for choice in ToolStatus.choices])

    execution_time_seconds = factory.Faker('pyfloat', min_value=1.0, max_value=3600.0)
    parsed_results_count = factory.Faker('pyint', min_value=0, max_value=100)

    tool_parameters = factory.LazyFunction(
        lambda: {
            'concurrency': 25,
            'rate_limit': 150,
            'timeout': 30,
            'retries': 3
        }
    )

    raw_output = Faker('text', max_nb_chars=1000)
    error_message = factory.Maybe(
        'status',
        yes_declaration='',
        no_declaration=Faker('sentence'),
        condition=lambda obj: obj.status != 'failed'
    )


class VulnerabilityFactory(DjangoModelFactory):
    """Factory for creating test vulnerabilities"""

    class Meta:
        model = Vulnerability

    scan_session = SubFactory(ScanSessionFactory)
    vulnerability_name = factory.Iterator([
        'SQL Injection in Login Form',
        'Cross-Site Scripting (XSS) in Search',
        'Cross-Site Request Forgery (CSRF)',
        'Information Disclosure in Error Messages',
        'Insecure Direct Object Reference',
        'Command Injection in File Upload',
        'Server-Side Request Forgery (SSRF)',
        'XML External Entity (XXE) Injection',
        'Insecure Deserialization',
        'Security Misconfiguration'
    ])

    vulnerability_type = factory.Iterator([
        'sql_injection', 'xss', 'csrf', 'information_disclosure',
        'idor', 'command_injection', 'ssrf', 'xxe', 'deserialization',
        'security_misconfiguration'
    ])

    owasp_category = factory.Iterator([
        'A01', 'A02', 'A03', 'A04', 'A05', 'A06', 'A07', 'A08', 'A09', 'A10'
    ])

    cwe_id = factory.Iterator([
        'CWE-79', 'CWE-89', 'CWE-352', 'CWE-200', 'CWE-639',
        'CWE-78', 'CWE-918', 'CWE-611', 'CWE-502', 'CWE-16'
    ])

    severity = factory.Iterator([choice[0] for choice in VulnSeverity.choices])
    cvss_score = factory.LazyAttribute(
        lambda obj: {
            'critical': factory.Faker('pyfloat', min_value=9.0, max_value=10.0).generate(),
            'high': factory.Faker('pyfloat', min_value=7.0, max_value=8.9).generate(),
            'medium': factory.Faker('pyfloat', min_value=4.0, max_value=6.9).generate(),
            'low': factory.Faker('pyfloat', min_value=0.1, max_value=3.9).generate(),
            'info': 0.0
        }.get(obj.severity, 5.0)
    )

    impact_description = Faker('text', max_nb_chars=500)
    affected_url = factory.LazyAttribute(
        lambda obj: f"{obj.scan_session.target.main_url}/vulnerable-endpoint"
    )
    affected_parameter = factory.Iterator([
        'username', 'password', 'search', 'id', 'file', 'url', 'data', 'token'
    ])
    http_method = factory.Iterator(['GET', 'POST', 'PUT', 'DELETE', 'PATCH'])

    payload_used = factory.LazyAttribute(
        lambda obj: {
            'sql_injection': "admin' OR '1'='1' --",
            'xss': '<script>alert("XSS")</script>',
            'command_injection': '; cat /etc/passwd',
            'ssrf': 'http://localhost:8080/admin'
        }.get(obj.vulnerability_type, 'test_payload')
    )

    request_data = factory.LazyAttribute(
        lambda obj: f"POST {obj.affected_url} HTTP/1.1\nContent-Type: application/json\n\n{{\"username\": \"{obj.payload_used}\"}}"
    )
    response_data = Faker('text', max_nb_chars=800)

    discovered_by_tool = factory.Iterator([
        'nuclei', 'sqlmap', 'burp', 'zap', 'custom_scanner'
    ])
    discovery_method = Faker('sentence')
    confidence_level = factory.Faker('pyfloat', min_value=0.1, max_value=1.0)
    false_positive_likelihood = factory.Faker('pyfloat', min_value=0.0, max_value=0.5)

    screenshot_paths = factory.LazyFunction(
        lambda: ['/evidence/screenshots/vuln_001.png', '/evidence/screenshots/vuln_002.png']
    )
    additional_evidence = factory.LazyFunction(
        lambda: {
            'log_files': ['/evidence/logs/scan.log'],
            'network_traces': ['/evidence/pcap/traffic.pcap'],
            'source_code': '/evidence/source/vulnerable_code.php'
        }
    )

    is_exploitable = factory.Faker('boolean', chance_of_getting_true=30)
    exploitation_difficulty = factory.Iterator([choice[0] for choice in ExploitationDifficulty.choices])
    exploitation_notes = Faker('text', max_nb_chars=300)

    remediation_suggestion = factory.LazyAttribute(
        lambda obj: {
            'sql_injection': 'Use parameterized queries and input validation',
            'xss': 'Implement proper output encoding and Content Security Policy',
            'csrf': 'Implement CSRF tokens and SameSite cookie attributes',
            'command_injection': 'Use safe APIs and input validation'
        }.get(obj.vulnerability_type, 'Review and fix the identified security issue')
    )
    remediation_priority = factory.Iterator([choice[0] for choice in RemediationPriority.choices])

    manually_verified = factory.Faker('boolean', chance_of_getting_true=20)
    verification_notes = factory.Maybe(
        'manually_verified',
        yes_declaration=Faker('text', max_nb_chars=200),
        no_declaration=''
    )


class ExploitationSessionFactory(DjangoModelFactory):
    """Factory for creating test exploitation sessions"""

    class Meta:
        model = ExploitationSession

    vulnerability = SubFactory(VulnerabilityFactory)
    target = factory.LazyAttribute(lambda obj: obj.vulnerability.scan_session.target)
    exploitation_type = factory.Iterator([choice[0] for choice in ExploitationType.choices])
    status = factory.Iterator([choice[0] for choice in ExploitationStatus.choices])
    severity = factory.Iterator([choice[0] for choice in ExploitationSeverity.choices])

    exploit_chain_data = factory.LazyFunction(
        lambda: {
            'steps': [
                {'step': 1, 'action': 'reconnaissance', 'status': 'completed'},
                {'step': 2, 'action': 'exploitation', 'status': 'in_progress'},
                {'step': 3, 'action': 'post_exploitation', 'status': 'pending'}
            ],
            'current_step': 2
        }
    )

    payloads_used = factory.LazyFunction(
        lambda: [
            "admin' OR '1'='1' --",
            "' UNION SELECT 1,2,3,4,5 --",
            "<script>alert('XSS')</script>"
        ]
    )

    notes = Faker('text', max_nb_chars=500)
    automated = factory.Faker('boolean', chance_of_getting_true=80)


class ExploitResultFactory(DjangoModelFactory):
    """Factory for creating test exploit results"""

    class Meta:
        model = ExploitResult

    session = SubFactory(ExploitationSessionFactory)
    payload = factory.LazyAttribute(lambda obj: obj.session.payloads_used[0] if obj.session.payloads_used else 'test_payload')

    response_data = factory.LazyFunction(
        lambda: {
            'status_code': 200,
            'response_time': 0.234,
            'content_length': 1024,
            'headers': {'Content-Type': 'text/html'},
            'body_excerpt': '<html>Database error: syntax error...'
        }
    )

    success = factory.Faker('boolean', chance_of_getting_true=40)
    impact_level = factory.Iterator([choice[0] for choice in ExploitationSeverity.choices])

    evidence_files = factory.LazyFunction(
        lambda: [
            '/evidence/exploits/screenshot_001.png',
            '/evidence/exploits/response_log.txt',
            '/evidence/exploits/proof_of_concept.py'
        ]
    )

    proof_of_concept = Faker('text', max_nb_chars=800)


class ExploitChainFactory(DjangoModelFactory):
    """Factory for creating test exploit chains"""

    class Meta:
        model = ExploitChain

    name = Faker('sentence', nb_words=3)
    description = Faker('text', max_nb_chars=300)

    chain_steps = factory.LazyFunction(
        lambda: [
            {
                'step': 1,
                'name': 'Information Gathering',
                'description': 'Gather target information',
                'payload': 'nmap -sV target.com',
                'expected_result': 'Port scan results'
            },
            {
                'step': 2,
                'name': 'Vulnerability Discovery',
                'description': 'Find SQL injection',
                'payload': "admin' OR '1'='1' --",
                'expected_result': 'Authentication bypass'
            },
            {
                'step': 3,
                'name': 'Data Extraction',
                'description': 'Extract sensitive data',
                'payload': "' UNION SELECT username,password FROM users --",
                'expected_result': 'User credentials'
            }
        ]
    )

    success_rate = factory.Faker('pyfloat', min_value=0.0, max_value=1.0)


class ExploitTemplateFactory(DjangoModelFactory):
    """Factory for creating test exploit templates"""

    class Meta:
        model = ExploitTemplate

    name = Faker('sentence', nb_words=3)
    exploitation_type = factory.Iterator([choice[0] for choice in ExploitationType.choices])

    payload_template = factory.LazyAttribute(
        lambda obj: {
            'sql_injection': "{username}' OR '1'='1' --",
            'xss': '<script>alert("{xss_payload}")</script>',
            'command_injection': '; {command}',
            'ssrf': 'http://{target_host}:{port}{path}'
        }.get(obj.exploitation_type, '{payload}')
    )

    configuration = factory.LazyFunction(
        lambda: {
            'timeout': 30,
            'retries': 3,
            'delay_between_requests': 1.0,
            'user_agent': 'BugBountyBot/1.0',
            'follow_redirects': True
        }
    )

    prerequisites = factory.LazyFunction(
        lambda: [
            'Target must be accessible',
            'Authentication may be required',
            'Rate limiting should be considered'
        ]
    )


class ReconSessionFactory(DjangoModelFactory):
    """Factory for creating test reconnaissance sessions"""

    class Meta:
        model = ReconSession

    target = SubFactory(TargetFactory)
    session_name = factory.LazyAttribute(
        lambda obj: f"Recon - {obj.target.target_name}"
    )
    status = 'completed'

    recon_config = factory.LazyFunction(
        lambda: {
            'passive_recon': True,
            'active_recon': False,
            'tools': ['amass', 'subfinder', 'crt.sh'],
            'depth': 3
        }
    )

    subdomains_found = factory.Faker('pyint', min_value=5, max_value=100)
    endpoints_discovered = factory.Faker('pyint', min_value=10, max_value=500)
    technologies_identified = factory.LazyFunction(
        lambda: [
            'nginx/1.18.0',
            'PHP/7.4.3',
            'WordPress 5.8',
            'MySQL',
            'jQuery 3.6.0'
        ]
    )


class ReportFactory(DjangoModelFactory):
    """Factory for creating test reports"""

    class Meta:
        model = Report

    scan_session = SubFactory(ScanSessionFactory)
    report_name = factory.LazyAttribute(
        lambda obj: f"Security Assessment Report - {obj.scan_session.target.target_name}"
    )

    report_format = factory.Iterator([choice[0] for choice in ReportFormat.choices])
    status = factory.Iterator([choice[0] for choice in ReportStatus.choices])

    template_used = factory.Iterator([
        'executive_summary', 'technical_detail', 'compliance_audit', 'penetration_test'
    ])

    report_config = factory.LazyFunction(
        lambda: {
            'include_screenshots': True,
            'include_recommendations': True,
            'risk_matrix': True,
            'executive_summary': True,
            'technical_details': True,
            'appendices': True
        }
    )

    file_path = factory.LazyAttribute(
        lambda obj: f"/reports/{obj.scan_session.id}_{obj.report_format}_report.{obj.report_format}"
    )
    file_size_bytes = factory.Faker('pyint', min_value=1024, max_value=10485760)  # 1KB to 10MB

    executive_summary = Faker('text', max_nb_chars=1000)

    vulnerability_stats = factory.LazyFunction(
        lambda: {
            'total': 15,
            'critical': 2,
            'high': 5,
            'medium': 6,
            'low': 2,
            'info': 0,
            'verified': 8,
            'false_positives': 1
        }
    )


# Trait classes for specific test scenarios
class CriticalVulnerabilityFactory(VulnerabilityFactory):
    """Factory for critical vulnerabilities"""
    severity = VulnSeverity.CRITICAL
    cvss_score = factory.Faker('pyfloat', min_value=9.0, max_value=10.0)
    is_exploitable = True
    manually_verified = True


class CompletedScanSessionFactory(ScanSessionFactory):
    """Factory for completed scan sessions"""
    status = ScanStatus.COMPLETED
    total_progress = 100.0
    phase_progress = factory.LazyFunction(
        lambda: {phase: 100 for phase in [
            'reconnaissance', 'enumeration', 'vulnerability_scanning',
            'exploitation', 'post_exploitation', 'reporting'
        ]}
    )


class SuccessfulExploitationFactory(ExploitationSessionFactory):
    """Factory for successful exploitation sessions"""
    status = ExploitationStatus.SUCCESSFUL
    severity = ExploitationSeverity.HIGH

    exploit_chain_data = factory.LazyFunction(
        lambda: {
            'steps': [
                {'step': 1, 'action': 'reconnaissance', 'status': 'completed'},
                {'step': 2, 'action': 'exploitation', 'status': 'completed'},
                {'step': 3, 'action': 'post_exploitation', 'status': 'completed'}
            ],
            'current_step': 3,
            'completion_time': '2023-10-01T12:00:00Z'
        }
    )


# Factory sequences for creating related objects
class TargetWithScansFactory(TargetFactory):
    """Target with multiple scan sessions"""

    @factory.post_generation
    def scan_sessions(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for session in extracted:
                ScanSessionFactory.create(target=self, **session)
        else:
            # Create 3 scan sessions by default
            ScanSessionFactory.create_batch(3, target=self)


class ScanWithVulnerabilitiesFactory(ScanSessionFactory):
    """Scan session with vulnerabilities"""

    @factory.post_generation
    def vulnerabilities(self, create, extracted, **kwargs):
        if not create:
            return

        if extracted:
            for vuln in extracted:
                VulnerabilityFactory.create(scan_session=self, **vuln)
        else:
            # Create vulnerabilities with different severities
            CriticalVulnerabilityFactory.create(scan_session=self)
            VulnerabilityFactory.create_batch(3, scan_session=self, severity=VulnSeverity.HIGH)
            VulnerabilityFactory.create_batch(5, scan_session=self, severity=VulnSeverity.MEDIUM)
            VulnerabilityFactory.create_batch(2, scan_session=self, severity=VulnSeverity.LOW)