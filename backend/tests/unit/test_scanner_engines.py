"""
Unit tests for vulnerability scanner engines
"""

import pytest
import json
import tempfile
from unittest.mock import Mock, patch, mock_open
from pathlib import Path

from services.scanner_engines.nuclei_engine import NucleiEngine
from services.scanner_engines.custom_web_engine import CustomWebEngine
from services.scanner_engines.custom_infra_engine import CustomInfraEngine
from services.scanner_engines.custom_api_engine import CustomAPIEngine
from services.scanner_engines.recon_engine import ReconEngine
from services.scanner_engines.scan_orchestrator import ScanOrchestrator

from tests.factories import TargetFactory, ScanSessionFactory


@pytest.mark.django_db
class TestNucleiEngine:
    """Test Nuclei vulnerability scanner engine"""

    def setUp(self):
        self.target = TargetFactory()
        self.scan_session = ScanSessionFactory(target=self.target)
        self.nuclei_engine = NucleiEngine()

    @patch('subprocess.run')
    def test_nuclei_basic_scan(self, mock_subprocess):
        """Test basic Nuclei scan execution"""

        # Mock Nuclei output
        nuclei_output = """
        {"template":"ssl-issuer","template-url":"file:///nuclei-templates/ssl/ssl-issuer.yaml","template-id":"ssl-issuer","info":{"name":"SSL Certificate Issuer","author":"pdteam","tags":"ssl","reference":"","severity":"info"},"type":"ssl","host":"example.com","matched-at":"example.com:443","ip":"93.184.216.34","timestamp":"2024-01-15T10:30:00Z"}
        {"template":"xss-reflected","template-url":"file:///nuclei-templates/vulnerabilities/xss/reflected-xss.yaml","template-id":"xss-reflected","info":{"name":"Reflected XSS","author":"pdteam","tags":"xss,web","severity":"medium"},"type":"http","host":"https://example.com","matched-at":"https://example.com/search?q=test","request":"GET /search?q=%3Cscript%3Ealert%281%29%3C%2Fscript%3E HTTP/1.1","response":"200 OK","timestamp":"2024-01-15T10:31:00Z"}
        """

        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = nuclei_output
        mock_subprocess.return_value.stderr = ""

        # Execute scan
        result = self.nuclei_engine.execute_scan(
            target_url="https://example.com",
            scan_session_id=self.scan_session.id
        )

        # Verify command execution
        mock_subprocess.assert_called_once()
        args = mock_subprocess.call_args[0][0]
        self.assertIn('nuclei', args)
        self.assertIn('-u', args)
        self.assertIn('https://example.com', args)
        self.assertIn('-json', args)

        # Verify results
        self.assertEqual(result['status'], 'completed')
        self.assertIn('vulnerabilities', result)
        self.assertEqual(len(result['vulnerabilities']), 2)

    @patch('subprocess.run')
    def test_nuclei_with_custom_templates(self, mock_subprocess):
        """Test Nuclei scan with custom templates"""

        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = ""
        mock_subprocess.return_value.stderr = ""

        # Execute scan with custom templates
        result = self.nuclei_engine.execute_scan(
            target_url="https://example.com",
            scan_session_id=self.scan_session.id,
            template_paths=["/custom/templates/", "/specific-template.yaml"]
        )

        # Verify custom templates were used
        args = mock_subprocess.call_args[0][0]
        self.assertIn('-t', args)

    @patch('subprocess.run')
    def test_nuclei_rate_limiting(self, mock_subprocess):
        """Test Nuclei rate limiting configuration"""

        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = ""
        mock_subprocess.return_value.stderr = ""

        # Execute scan with rate limiting
        result = self.nuclei_engine.execute_scan(
            target_url="https://example.com",
            scan_session_id=self.scan_session.id,
            rate_limit=50,
            concurrency=10
        )

        # Verify rate limiting parameters
        args = mock_subprocess.call_args[0][0]
        self.assertIn('-rl', args)
        self.assertIn('50', args)
        self.assertIn('-c', args)
        self.assertIn('10', args)

    def test_nuclei_result_parsing(self):
        """Test Nuclei JSON result parsing"""

        nuclei_json = {
            "template": "sql-injection",
            "template-id": "sql-injection-login",
            "info": {
                "name": "SQL Injection - Login Form",
                "severity": "high",
                "tags": "sqli,web"
            },
            "type": "http",
            "host": "https://example.com",
            "matched-at": "https://example.com/login",
            "request": "POST /login HTTP/1.1",
            "response": "500 Internal Server Error"
        }

        # Parse result
        parsed = self.nuclei_engine.parse_nuclei_result(nuclei_json)

        # Verify parsing
        self.assertEqual(parsed['template_id'], 'sql-injection-login')
        self.assertEqual(parsed['severity'], 'high')
        self.assertEqual(parsed['vulnerability_type'], 'sql_injection')
        self.assertEqual(parsed['affected_url'], 'https://example.com/login')


@pytest.mark.django_db
class TestCustomWebEngine:
    """Test custom web application scanner engine"""

    def setUp(self):
        self.target = TargetFactory()
        self.scan_session = ScanSessionFactory(target=self.target)
        self.web_engine = CustomWebEngine()

    @patch('requests.get')
    @patch('requests.post')
    def test_web_directory_traversal_scan(self, mock_post, mock_get):
        """Test directory traversal vulnerability scanning"""

        # Mock vulnerable response
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = "root:x:0:0:root:/root:/bin/bash"
        mock_get.return_value.headers = {'Content-Type': 'text/plain'}

        # Execute directory traversal scan
        result = self.web_engine.scan_directory_traversal(
            target_url="https://example.com",
            scan_session_id=self.scan_session.id
        )

        # Verify scan execution
        mock_get.assert_called()

        # Verify results
        self.assertEqual(result['status'], 'completed')
        if result['vulnerabilities_found']:
            vuln = result['vulnerabilities'][0]
            self.assertEqual(vuln['type'], 'directory_traversal')
            self.assertIn('payload', vuln)

    @patch('requests.post')
    def test_sql_injection_scan(self, mock_post):
        """Test SQL injection vulnerability scanning"""

        # Mock SQL error response
        mock_post.return_value.status_code = 500
        mock_post.return_value.text = "MySQL syntax error near 'OR 1=1'"
        mock_post.return_value.headers = {'Content-Type': 'text/html'}

        # Execute SQL injection scan
        result = self.web_engine.scan_sql_injection(
            target_url="https://example.com/login",
            scan_session_id=self.scan_session.id,
            parameters=['username', 'password']
        )

        # Verify scan execution
        mock_post.assert_called()

        # Verify results
        self.assertEqual(result['status'], 'completed')
        if result['vulnerabilities_found']:
            vuln = result['vulnerabilities'][0]
            self.assertEqual(vuln['type'], 'sql_injection')
            self.assertIn('affected_parameter', vuln)

    @patch('requests.get')
    def test_xss_scan(self, mock_get):
        """Test XSS vulnerability scanning"""

        # Mock reflected XSS response
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = '<html><body>Search results for <script>alert(1)</script></body></html>'

        # Execute XSS scan
        result = self.web_engine.scan_xss(
            target_url="https://example.com/search",
            scan_session_id=self.scan_session.id,
            parameters=['q', 'search', 'query']
        )

        # Verify scan execution
        mock_get.assert_called()

        # Verify results
        self.assertEqual(result['status'], 'completed')
        if result['vulnerabilities_found']:
            vuln = result['vulnerabilities'][0]
            self.assertEqual(vuln['type'], 'xss_reflected')

    def test_payload_generation(self):
        """Test vulnerability payload generation"""

        # Test SQL injection payloads
        sql_payloads = self.web_engine.generate_sql_payloads()
        self.assertIsInstance(sql_payloads, list)
        self.assertIn("' OR 1=1 --", sql_payloads)
        self.assertIn("' UNION SELECT 1,2,3 --", sql_payloads)

        # Test XSS payloads
        xss_payloads = self.web_engine.generate_xss_payloads()
        self.assertIsInstance(xss_payloads, list)
        self.assertIn('<script>alert(1)</script>', xss_payloads)
        self.assertIn('<img src=x onerror=alert(1)>', xss_payloads)


@pytest.mark.django_db
class TestCustomInfraEngine:
    """Test custom infrastructure scanner engine"""

    def setUp(self):
        self.target = TargetFactory()
        self.scan_session = ScanSessionFactory(target=self.target)
        self.infra_engine = CustomInfraEngine()

    @patch('subprocess.run')
    def test_nmap_port_scan(self, mock_subprocess):
        """Test Nmap port scanning"""

        # Mock Nmap XML output
        nmap_xml = """
        <?xml version="1.0" encoding="UTF-8"?>
        <nmaprun>
            <host>
                <address addr="93.184.216.34" addrtype="ipv4"/>
                <hostnames><hostname name="example.com" type="PTR"/></hostnames>
                <ports>
                    <port protocol="tcp" portid="80">
                        <state state="open" reason="syn-ack"/>
                        <service name="http" product="nginx" version="1.18.0"/>
                    </port>
                    <port protocol="tcp" portid="443">
                        <state state="open" reason="syn-ack"/>
                        <service name="https" product="nginx" version="1.18.0"/>
                    </port>
                </ports>
            </host>
        </nmaprun>
        """

        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = nmap_xml
        mock_subprocess.return_value.stderr = ""

        # Execute port scan
        result = self.infra_engine.execute_port_scan(
            target="example.com",
            scan_session_id=self.scan_session.id
        )

        # Verify scan execution
        mock_subprocess.assert_called_once()
        args = mock_subprocess.call_args[0][0]
        self.assertIn('nmap', args)
        self.assertIn('example.com', args)

        # Verify results
        self.assertEqual(result['status'], 'completed')
        self.assertIn('open_ports', result)
        self.assertIn(80, result['open_ports'])
        self.assertIn(443, result['open_ports'])

    @patch('subprocess.run')
    def test_ssl_scan(self, mock_subprocess):
        """Test SSL/TLS configuration scanning"""

        # Mock SSL scan output
        ssl_output = """
        Testing SSL/TLS on example.com:443
        TLS 1.2: OFFERED
        TLS 1.3: OFFERED
        Certificate expires: 2024-12-31
        Weak ciphers: NONE
        """

        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = ssl_output
        mock_subprocess.return_value.stderr = ""

        # Execute SSL scan
        result = self.infra_engine.execute_ssl_scan(
            target="example.com",
            scan_session_id=self.scan_session.id
        )

        # Verify results
        self.assertEqual(result['status'], 'completed')
        self.assertIn('ssl_config', result)

    def test_service_detection(self):
        """Test service fingerprinting"""

        # Mock service detection
        service_data = {
            'port': 80,
            'protocol': 'tcp',
            'service': 'http',
            'product': 'nginx',
            'version': '1.18.0'
        }

        detected_service = self.infra_engine.analyze_service(service_data)

        # Verify service analysis
        self.assertEqual(detected_service['service_name'], 'nginx')
        self.assertEqual(detected_service['version'], '1.18.0')
        self.assertIn('potential_vulnerabilities', detected_service)


@pytest.mark.django_db
class TestCustomAPIEngine:
    """Test custom API scanner engine"""

    def setUp(self):
        self.target = TargetFactory()
        self.scan_session = ScanSessionFactory(target=self.target)
        self.api_engine = CustomAPIEngine()

    @patch('requests.get')
    def test_api_endpoint_discovery(self, mock_get):
        """Test API endpoint discovery"""

        # Mock API documentation response
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {
            "swagger": "2.0",
            "paths": {
                "/api/v1/users": {"get": {}, "post": {}},
                "/api/v1/admin": {"get": {}, "delete": {}},
                "/api/v1/files": {"get": {}, "post": {}}
            }
        }

        # Execute endpoint discovery
        result = self.api_engine.discover_api_endpoints(
            target_url="https://api.example.com",
            scan_session_id=self.scan_session.id
        )

        # Verify discovery
        self.assertEqual(result['status'], 'completed')
        self.assertIn('endpoints', result)
        self.assertGreater(len(result['endpoints']), 0)

    @patch('requests.get')
    @patch('requests.post')
    def test_api_authentication_bypass(self, mock_post, mock_get):
        """Test API authentication bypass scanning"""

        # Mock responses
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {"data": "sensitive_info"}

        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {"token": "fake_token"}

        # Execute auth bypass scan
        result = self.api_engine.scan_authentication_bypass(
            api_endpoints=["https://api.example.com/admin", "https://api.example.com/users"],
            scan_session_id=self.scan_session.id
        )

        # Verify scan
        self.assertEqual(result['status'], 'completed')
        if result['vulnerabilities_found']:
            vuln = result['vulnerabilities'][0]
            self.assertEqual(vuln['type'], 'authentication_bypass')

    def test_api_payload_generation(self):
        """Test API-specific payload generation"""

        # Test JWT manipulation payloads
        jwt_payloads = self.api_engine.generate_jwt_payloads()
        self.assertIsInstance(jwt_payloads, list)
        self.assertTrue(any('alg":"none"' in payload for payload in jwt_payloads))

        # Test API injection payloads
        injection_payloads = self.api_engine.generate_api_injection_payloads()
        self.assertIsInstance(injection_payloads, list)


@pytest.mark.django_db
class TestReconEngine:
    """Test reconnaissance engine"""

    def setUp(self):
        self.target = TargetFactory()
        self.recon_engine = ReconEngine()

    @patch('subprocess.run')
    def test_subdomain_enumeration(self, mock_subprocess):
        """Test subdomain enumeration"""

        # Mock subfinder output
        subfinder_output = """
        api.example.com
        admin.example.com
        mail.example.com
        dev.example.com
        """

        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = subfinder_output
        mock_subprocess.return_value.stderr = ""

        # Execute subdomain enumeration
        result = self.recon_engine.enumerate_subdomains(
            target_domain="example.com"
        )

        # Verify enumeration
        self.assertEqual(result['status'], 'completed')
        self.assertIn('subdomains', result)
        self.assertIn('api.example.com', result['subdomains'])
        self.assertIn('admin.example.com', result['subdomains'])

    @patch('requests.get')
    def test_technology_detection(self, mock_get):
        """Test web technology detection"""

        # Mock response with technology indicators
        mock_get.return_value.status_code = 200
        mock_get.return_value.headers = {
            'Server': 'nginx/1.18.0',
            'X-Powered-By': 'PHP/7.4.0'
        }
        mock_get.return_value.text = """
        <html>
        <head>
            <meta name="generator" content="WordPress 5.8">
            <script src="/wp-content/themes/theme/js/jquery.min.js"></script>
        </head>
        </html>
        """

        # Execute technology detection
        result = self.recon_engine.detect_technologies(
            target_url="https://example.com"
        )

        # Verify detection
        self.assertEqual(result['status'], 'completed')
        self.assertIn('technologies', result)
        self.assertIn('nginx', [tech['name'] for tech in result['technologies']])
        self.assertIn('WordPress', [tech['name'] for tech in result['technologies']])

    @patch('subprocess.run')
    def test_dns_enumeration(self, mock_subprocess):
        """Test DNS record enumeration"""

        # Mock dig output
        dig_output = """
        example.com.		300	IN	A	93.184.216.34
        example.com.		300	IN	MX	10 mail.example.com.
        example.com.		300	IN	TXT	"v=spf1 include:_spf.google.com ~all"
        """

        mock_subprocess.return_value.returncode = 0
        mock_subprocess.return_value.stdout = dig_output
        mock_subprocess.return_value.stderr = ""

        # Execute DNS enumeration
        result = self.recon_engine.enumerate_dns_records(
            target_domain="example.com"
        )

        # Verify enumeration
        self.assertEqual(result['status'], 'completed')
        self.assertIn('dns_records', result)


@pytest.mark.django_db
class TestScanOrchestrator:
    """Test scan orchestration and coordination"""

    def setUp(self):
        self.target = TargetFactory()
        self.scan_session = ScanSessionFactory(target=self.target)
        self.orchestrator = ScanOrchestrator()

    @patch.multiple(
        'services.scanner_engines',
        NucleiEngine=Mock(),
        CustomWebEngine=Mock(),
        CustomInfraEngine=Mock()
    )
    def test_coordinated_scan_execution(self):
        """Test coordinated execution of multiple scan engines"""

        # Mock engine results
        nuclei_results = {'status': 'completed', 'vulnerabilities': 2}
        web_results = {'status': 'completed', 'vulnerabilities': 1}
        infra_results = {'status': 'completed', 'open_ports': [80, 443]}

        # Execute coordinated scan
        result = self.orchestrator.execute_coordinated_scan(
            scan_session_id=self.scan_session.id,
            scan_engines=['nuclei', 'custom_web', 'custom_infra']
        )

        # Verify orchestration
        self.assertEqual(result['status'], 'completed')
        self.assertIn('engine_results', result)

    def test_scan_priority_management(self):
        """Test scan priority and resource management"""

        # Define scan priorities
        scan_priorities = {
            'nuclei': 'high',
            'custom_web': 'medium',
            'custom_infra': 'low'
        }

        # Execute priority-based scanning
        execution_order = self.orchestrator.determine_execution_order(
            scan_engines=list(scan_priorities.keys()),
            priorities=scan_priorities
        )

        # Verify priority ordering
        self.assertEqual(execution_order[0], 'nuclei')  # highest priority first
        self.assertEqual(execution_order[-1], 'custom_infra')  # lowest priority last

    @patch('asyncio.gather')
    async def test_parallel_scan_execution(self, mock_gather):
        """Test parallel scan engine execution"""

        # Mock async scan results
        mock_gather.return_value = [
            {'engine': 'nuclei', 'status': 'completed'},
            {'engine': 'custom_web', 'status': 'completed'},
            {'engine': 'custom_infra', 'status': 'completed'}
        ]

        # Execute parallel scans
        result = await self.orchestrator.execute_parallel_scans(
            scan_session_id=self.scan_session.id,
            scan_engines=['nuclei', 'custom_web', 'custom_infra']
        )

        # Verify parallel execution
        mock_gather.assert_called_once()
        self.assertEqual(len(result), 3)