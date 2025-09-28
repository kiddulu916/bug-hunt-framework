"""
Large Dataset Generators for Performance Testing

Provides standardized large-scale test data for performance benchmarking
and stress testing of the bug bounty automation platform.
"""

import pytest
import random
import string
from datetime import datetime, timedelta
from typing import List, Dict, Any
from django.utils import timezone
from faker import Faker

from tests.factories import (
    TargetFactory, ScanSessionFactory, VulnerabilityFactory,
    ExploitationSessionFactory, ToolExecutionFactory, ReportFactory
)
from apps.targets.models import BugBountyPlatform
from apps.vulnerabilities.models import VulnSeverity
from apps.scanning.models import ScanStatus


fake = Faker()


class LargeDatasetGenerator:
    """Generator for large-scale test datasets"""

    def __init__(self, seed=42):
        """Initialize with reproducible seed for consistent data generation"""
        random.seed(seed)
        fake.seed_instance(seed)
        self.seed = seed

    @pytest.fixture(scope='session')
    def large_target_dataset(self):
        """Generate 1000+ targets for load testing"""
        print("Generating large target dataset (1000 targets)...")

        platforms = [choice[0] for choice in BugBountyPlatform.choices]
        domains = [
            'example.com', 'testcorp.com', 'democorp.net', 'samplebiz.org',
            'techstartup.io', 'webapp.dev', 'apiservice.co', 'cloudapp.net'
        ]

        targets = []
        for i in range(1000):
            base_domain = random.choice(domains)
            subdomain = fake.word() if i % 3 == 0 else None
            url = f"https://{subdomain + '.' if subdomain else ''}{base_domain}"

            target_data = {
                'target_name': f"{fake.company()} {i}",
                'platform': random.choice(platforms),
                'researcher_username': fake.user_name(),
                'main_url': url,
                'in_scope_urls': self._generate_scope_urls(base_domain, 3, 8),
                'out_of_scope_urls': self._generate_scope_urls(base_domain, 1, 3),
                'requests_per_second': round(random.uniform(1.0, 20.0), 1),
                'concurrent_requests': random.randint(5, 50),
                'program_notes': fake.text(max_nb_chars=random.randint(100, 1000))
            }

            targets.append(TargetFactory.create(**target_data))

            if (i + 1) % 100 == 0:
                print(f"Generated {i + 1} targets...")

        print(f"✅ Generated {len(targets)} targets")
        return targets

    @pytest.fixture(scope='session')
    def large_vulnerability_dataset(self, large_target_dataset):
        """Generate 10,000+ vulnerabilities across targets"""
        print("Generating large vulnerability dataset (10,000 vulnerabilities)...")

        # Create scan sessions for targets
        scan_sessions = []
        for i, target in enumerate(large_target_dataset[:100]):  # Use subset for scan sessions
            scan_session = ScanSessionFactory.create(
                target=target,
                session_name=f"Large Dataset Scan {i}",
                status=random.choice([ScanStatus.COMPLETED, ScanStatus.RUNNING])
            )
            scan_sessions.append(scan_session)

        vulnerabilities = []
        vuln_types = [
            'sql_injection', 'xss_reflected', 'xss_stored', 'csrf', 'lfi', 'rfi',
            'command_injection', 'ssrf', 'xxe', 'idor', 'security_misconfiguration',
            'sensitive_data_exposure', 'broken_authentication', 'broken_access_control'
        ]

        severities = [choice[0] for choice in VulnSeverity.choices]

        for i in range(10000):
            scan_session = random.choice(scan_sessions)
            vuln_type = random.choice(vuln_types)
            severity = random.choice(severities)

            # Generate realistic vulnerability data
            vuln_data = {
                'scan_session': scan_session,
                'vulnerability_name': self._generate_vuln_name(vuln_type),
                'vulnerability_type': vuln_type,
                'owasp_category': self._map_to_owasp(vuln_type),
                'cwe_id': self._map_to_cwe(vuln_type),
                'severity': severity,
                'cvss_score': self._generate_cvss_score(severity),
                'impact_description': fake.text(max_nb_chars=500),
                'affected_url': f"{scan_session.target.main_url}/{fake.uri_path()}",
                'affected_parameter': random.choice(['id', 'username', 'search', 'file', 'url', 'data']),
                'http_method': random.choice(['GET', 'POST', 'PUT', 'DELETE']),
                'payload_used': self._generate_payload(vuln_type),
                'discovered_by_tool': random.choice(['nuclei', 'custom_web', 'custom_api', 'burp']),
                'confidence_level': round(random.uniform(0.1, 1.0), 2),
                'manually_verified': random.choice([True, False]),
                'false_positive_likelihood': round(random.uniform(0.0, 0.3), 2)
            }

            vulnerabilities.append(VulnerabilityFactory.create(**vuln_data))

            if (i + 1) % 1000 == 0:
                print(f"Generated {i + 1} vulnerabilities...")

        print(f"✅ Generated {len(vulnerabilities)} vulnerabilities")
        return vulnerabilities

    @pytest.fixture(scope='session')
    def large_scan_history_dataset(self, large_target_dataset):
        """Generate extensive scan history for trend analysis testing"""
        print("Generating large scan history dataset...")

        scan_sessions = []
        start_date = timezone.now() - timedelta(days=365)  # 1 year of history

        for i in range(2000):  # 2000 scan sessions over the year
            target = random.choice(large_target_dataset[:200])  # Use subset of targets

            # Distribute scans over time
            scan_date = start_date + timedelta(
                days=random.randint(0, 365),
                hours=random.randint(0, 23),
                minutes=random.randint(0, 59)
            )

            scan_data = {
                'target': target,
                'session_name': f"Historical Scan {i} - {fake.word().title()}",
                'status': random.choice([
                    ScanStatus.COMPLETED, ScanStatus.COMPLETED, ScanStatus.COMPLETED,  # Weight towards completed
                    ScanStatus.FAILED, ScanStatus.CANCELLED
                ]),
                'total_progress': 100.0 if random.random() > 0.1 else random.uniform(10.0, 99.0),
                'total_subdomains_found': random.randint(5, 200),
                'total_endpoints_found': random.randint(20, 1000),
                'total_vulnerabilities': random.randint(0, 50),
                'critical_vulnerabilities': random.randint(0, 5),
                'high_vulnerabilities': random.randint(0, 15),
                'methodology_phases': [
                    'reconnaissance', 'enumeration', 'vulnerability_scanning', 'exploitation'
                ],
                'scan_config': {
                    'tools': random.sample(['nuclei', 'nmap', 'amass', 'subfinder', 'httpx'],
                                         random.randint(2, 5)),
                    'intensity': random.choice(['low', 'medium', 'high', 'aggressive']),
                    'concurrent_scans': random.randint(1, 10)
                }
            }

            with timezone.override(scan_date):
                scan_session = ScanSessionFactory.create(**scan_data)
                scan_sessions.append(scan_session)

            if (i + 1) % 200 == 0:
                print(f"Generated {i + 1} scan sessions...")

        print(f"✅ Generated {len(scan_sessions)} scan sessions")
        return scan_sessions

    @pytest.fixture(scope='session')
    def large_tool_execution_dataset(self, large_scan_history_dataset):
        """Generate tool execution data for performance analysis"""
        print("Generating large tool execution dataset...")

        tools = [
            'nuclei', 'nmap', 'amass', 'subfinder', 'httpx', 'gobuster',
            'ffuf', 'sqlmap', 'nikto', 'masscan', 'zap', 'burp'
        ]

        tool_executions = []

        for scan_session in large_scan_history_dataset:
            # Generate 3-8 tool executions per scan session
            num_executions = random.randint(3, 8)

            for i in range(num_executions):
                tool_name = random.choice(tools)

                execution_data = {
                    'scan_session': scan_session,
                    'tool_name': tool_name,
                    'tool_category': self._map_tool_category(tool_name),
                    'command_executed': self._generate_tool_command(tool_name, scan_session.target.main_url),
                    'status': random.choice(['completed', 'completed', 'completed', 'failed']),  # Weight towards completed
                    'execution_time_seconds': round(random.uniform(5.0, 3600.0), 2),
                    'parsed_results_count': random.randint(0, 100),
                    'tool_parameters': self._generate_tool_parameters(tool_name),
                    'raw_output': fake.text(max_nb_chars=random.randint(100, 2000))
                }

                tool_executions.append(ToolExecutionFactory.create(**execution_data))

        print(f"✅ Generated {len(tool_executions)} tool executions")
        return tool_executions

    @pytest.fixture(scope='session')
    def performance_benchmark_dataset(self):
        """Generate standardized dataset for performance benchmarking"""
        print("Generating performance benchmark dataset...")

        # Create standardized dataset sizes for benchmarking
        benchmark_data = {
            'small': {
                'targets': 10,
                'scan_sessions_per_target': 2,
                'vulnerabilities_per_scan': 5
            },
            'medium': {
                'targets': 100,
                'scan_sessions_per_target': 5,
                'vulnerabilities_per_scan': 20
            },
            'large': {
                'targets': 1000,
                'scan_sessions_per_target': 10,
                'vulnerabilities_per_scan': 50
            },
            'xlarge': {
                'targets': 5000,
                'scan_sessions_per_target': 20,
                'vulnerabilities_per_scan': 100
            }
        }

        datasets = {}

        for size_name, config in benchmark_data.items():
            print(f"Generating {size_name} benchmark dataset...")

            # Generate targets
            targets = []
            for i in range(config['targets']):
                target = TargetFactory.create(
                    target_name=f"{size_name.title()} Benchmark Target {i}",
                    main_url=f"https://benchmark-{size_name}-{i}.example.com"
                )
                targets.append(target)

            # Generate scan sessions and vulnerabilities
            scan_sessions = []
            vulnerabilities = []

            for target in targets:
                for j in range(config['scan_sessions_per_target']):
                    scan_session = ScanSessionFactory.create(
                        target=target,
                        session_name=f"{size_name.title()} Benchmark Scan {j}",
                        status=ScanStatus.COMPLETED
                    )
                    scan_sessions.append(scan_session)

                    # Generate vulnerabilities for this scan session
                    for k in range(config['vulnerabilities_per_scan']):
                        vulnerability = VulnerabilityFactory.create(
                            scan_session=scan_session,
                            vulnerability_name=f"Benchmark Vulnerability {k}",
                            severity=random.choice(['low', 'medium', 'high', 'critical'])
                        )
                        vulnerabilities.append(vulnerability)

            datasets[size_name] = {
                'targets': targets,
                'scan_sessions': scan_sessions,
                'vulnerabilities': vulnerabilities,
                'expected_counts': {
                    'targets': len(targets),
                    'scan_sessions': len(scan_sessions),
                    'vulnerabilities': len(vulnerabilities)
                }
            }

            print(f"✅ {size_name}: {len(targets)} targets, {len(scan_sessions)} scans, {len(vulnerabilities)} vulns")

        return datasets

    def _generate_scope_urls(self, base_domain: str, min_count: int, max_count: int) -> List[str]:
        """Generate realistic in-scope/out-of-scope URLs"""
        count = random.randint(min_count, max_count)
        urls = []

        subdomains = ['api', 'admin', 'dev', 'staging', 'test', 'www', 'app', 'portal']
        paths = ['', '/api', '/admin', '/login', '/dashboard', '/upload', '/search']

        for _ in range(count):
            subdomain = random.choice(subdomains) if random.random() > 0.3 else None
            path = random.choice(paths)

            url = f"https://{subdomain + '.' if subdomain else ''}{base_domain}{path}"
            if url not in urls:
                urls.append(url)

        return urls

    def _generate_vuln_name(self, vuln_type: str) -> str:
        """Generate realistic vulnerability names based on type"""
        vuln_templates = {
            'sql_injection': [
                'SQL Injection in {} Form',
                'Blind SQL Injection in {} Parameter',
                'Time-based SQL Injection in {}'
            ],
            'xss_reflected': [
                'Reflected XSS in {} Parameter',
                'DOM-based XSS in {} Function',
                'Reflected Cross-Site Scripting in {}'
            ],
            'xss_stored': [
                'Stored XSS in {} Field',
                'Persistent Cross-Site Scripting in {}',
                'Stored XSS via {} Upload'
            ],
            'csrf': [
                'CSRF in {} Functionality',
                'Cross-Site Request Forgery in {}',
                'Missing CSRF Protection in {}'
            ]
        }

        templates = vuln_templates.get(vuln_type, ['Security Vulnerability in {}'])
        template = random.choice(templates)

        locations = ['Login', 'Search', 'Upload', 'Profile', 'Admin Panel', 'Contact Form', 'Comment Section']
        location = random.choice(locations)

        return template.format(location)

    def _map_to_owasp(self, vuln_type: str) -> str:
        """Map vulnerability type to OWASP Top 10 category"""
        owasp_mapping = {
            'sql_injection': 'A03',
            'xss_reflected': 'A03',
            'xss_stored': 'A03',
            'csrf': 'A01',
            'broken_authentication': 'A07',
            'sensitive_data_exposure': 'A02',
            'idor': 'A01',
            'security_misconfiguration': 'A05',
            'xxe': 'A04',
            'ssrf': 'A10'
        }
        return owasp_mapping.get(vuln_type, 'A10')

    def _map_to_cwe(self, vuln_type: str) -> str:
        """Map vulnerability type to CWE ID"""
        cwe_mapping = {
            'sql_injection': 'CWE-89',
            'xss_reflected': 'CWE-79',
            'xss_stored': 'CWE-79',
            'csrf': 'CWE-352',
            'command_injection': 'CWE-78',
            'lfi': 'CWE-22',
            'rfi': 'CWE-98',
            'ssrf': 'CWE-918',
            'xxe': 'CWE-611'
        }
        return cwe_mapping.get(vuln_type, 'CWE-20')

    def _generate_cvss_score(self, severity: str) -> float:
        """Generate realistic CVSS score based on severity"""
        score_ranges = {
            'critical': (9.0, 10.0),
            'high': (7.0, 8.9),
            'medium': (4.0, 6.9),
            'low': (0.1, 3.9),
            'info': (0.0, 0.0)
        }

        min_score, max_score = score_ranges.get(severity, (0.0, 5.0))
        return round(random.uniform(min_score, max_score), 1)

    def _generate_payload(self, vuln_type: str) -> str:
        """Generate realistic payloads based on vulnerability type"""
        payloads = {
            'sql_injection': [
                "admin' OR '1'='1' --",
                "' UNION SELECT 1,2,3,4,5 --",
                "'; DROP TABLE users; --",
                "' AND 1=1 --"
            ],
            'xss_reflected': [
                '<script>alert("XSS")</script>',
                '<img src=x onerror=alert("XSS")>',
                '<svg onload=alert("XSS")>',
                'javascript:alert("XSS")'
            ],
            'command_injection': [
                '; cat /etc/passwd',
                '| whoami',
                '&& id',
                '`ls -la`'
            ]
        }

        payload_list = payloads.get(vuln_type, ['test_payload'])
        return random.choice(payload_list)

    def _map_tool_category(self, tool_name: str) -> str:
        """Map tool name to category"""
        categories = {
            'nuclei': 'vulnerability_scanning',
            'nmap': 'port_scanning',
            'amass': 'reconnaissance',
            'subfinder': 'reconnaissance',
            'httpx': 'reconnaissance',
            'gobuster': 'enumeration',
            'ffuf': 'enumeration',
            'sqlmap': 'exploitation',
            'nikto': 'vulnerability_scanning',
            'masscan': 'port_scanning'
        }
        return categories.get(tool_name, 'vulnerability_scanning')

    def _generate_tool_command(self, tool_name: str, target_url: str) -> str:
        """Generate realistic tool commands"""
        commands = {
            'nuclei': f'nuclei -u {target_url} -t /templates/ -o output.json',
            'nmap': f'nmap -sV -sC {target_url.split("://")[1]}',
            'amass': f'amass enum -d {target_url.split("://")[1]}',
            'subfinder': f'subfinder -d {target_url.split("://")[1]}',
            'sqlmap': f'sqlmap -u {target_url}/login --batch'
        }
        return commands.get(tool_name, f'{tool_name} {target_url}')

    def _generate_tool_parameters(self, tool_name: str) -> Dict[str, Any]:
        """Generate realistic tool parameters"""
        base_params = {
            'timeout': random.randint(30, 300),
            'retries': random.randint(1, 3),
            'user_agent': 'BugBountyBot/1.0'
        }

        tool_specific = {
            'nuclei': {
                'concurrency': random.randint(10, 50),
                'rate_limit': random.randint(50, 200),
                'severity': random.choice(['low', 'medium', 'high', 'critical'])
            },
            'nmap': {
                'scan_type': random.choice(['-sS', '-sT', '-sU']),
                'timing': random.choice(['-T2', '-T3', '-T4'])
            }
        }

        base_params.update(tool_specific.get(tool_name, {}))
        return base_params


# Global instance for use in fixtures
large_dataset_generator = LargeDatasetGenerator()


# Export fixtures for use in tests
@pytest.fixture(scope='session')
def large_target_dataset():
    return large_dataset_generator.large_target_dataset()


@pytest.fixture(scope='session')
def large_vulnerability_dataset():
    return large_dataset_generator.large_vulnerability_dataset()


@pytest.fixture(scope='session')
def large_scan_history_dataset():
    return large_dataset_generator.large_scan_history_dataset()


@pytest.fixture(scope='session')
def performance_benchmark_dataset():
    return large_dataset_generator.performance_benchmark_dataset()


@pytest.fixture(scope='session')
def large_tool_execution_dataset():
    return large_dataset_generator.large_tool_execution_dataset()