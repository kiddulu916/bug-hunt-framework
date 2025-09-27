"""
Custom API Security Scanner Engine
Specialized vulnerability detection for REST APIs, GraphQL, and other API endpoints
"""

import asyncio
import json
import logging
from typing import Dict, List, Any
from urllib.parse import urlparse, parse_qs
import aiohttp
import re

from services.vulnerability_scanner import VulnerabilityFinding, ScanEngineType, VulnSeverity


class CustomAPIEngine:
    """Custom API security scanner engine"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.engine_type = ScanEngineType.CUSTOM_API
        
        # API-specific test payloads
        self.graphql_introspection_query = """
        {
            __schema {
                types {
                    name
                    fields {
                        name
                        type {
                            name
                        }
                    }
                }
            }
        }
        """
        
        self.rest_api_tests = [
            {"method": "OPTIONS", "check": "cors_misconfiguration"},
            {"method": "TRACE", "check": "trace_method_enabled"},
            {"method": "PUT", "check": "http_method_override"},
            {"method": "DELETE", "check": "unsafe_methods"}
        ]
        
        self.api_injection_payloads = [
            # JSON injection
            '{"test": "value\\"injection"}',
            '{"$ne": null}',  # NoSQL injection
            '{"$where": "this.name == this.password"}',
            
            # XML injection for SOAP APIs
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test "injection">]><root>&test;</root>',
            
            # Parameter pollution
            'param=value1&param=value2',
            
            # Mass assignment
            '{"admin": true, "role": "administrator"}'
        ]
    
    async def scan_targets(self, targets: List[Dict[str, Any]], scan_config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Scan API targets for vulnerabilities"""
        findings = []
        
        # Filter for API endpoints
        api_targets = [t for t in targets if self._is_api_endpoint(t["url"])]
        
        if not api_targets:
            return findings
        
        rate_limit = scan_config.get("rate_limit", 5.0)
        timeout = aiohttp.ClientTimeout(total=scan_config.get("timeout", 30))
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            semaphore = asyncio.Semaphore(int(rate_limit))
            
            scan_tasks = []
            for target in api_targets:
                task = self._scan_api_target(session, semaphore, target, scan_config)
                scan_tasks.append(task)
            
            target_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
            
            for result in target_results:
                if isinstance(result, list):
                    findings.extend(result)
                elif isinstance(result, Exception):
                    self.logger.error(f"API scan error: {result}")
        
        return findings
    
    async def _scan_api_target(self, session: aiohttp.ClientSession,
                              semaphore: asyncio.Semaphore,
                              target: Dict[str, Any],
                              config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Scan a single API target"""
        findings = []
        url = target["url"]
        
        try:
            async with semaphore:
                # Determine API type
                api_type = await self._detect_api_type(session, url)
                
                # API-specific scans
                if api_type == "graphql":
                    findings.extend(await self._scan_graphql_api(session, url, target))
                elif api_type == "rest":
                    findings.extend(await self._scan_rest_api(session, url, target))
                elif api_type == "soap":
                    findings.extend(await self._scan_soap_api(session, url, target))
                
                # General API security checks
                findings.extend(await self._check_api_authentication(session, url, target))
                findings.extend(await self._check_api_authorization(session, url, target))
                findings.extend(await self._check_api_rate_limiting(session, url, target))
                findings.extend(await self._check_api_cors(session, url, target))
                findings.extend(await self._check_api_versioning(session, url, target))
                findings.extend(await self._check_api_documentation_exposure(session, url, target))
                
                # Rate limiting delay
                await asyncio.sleep(1.0 / config.get("rate_limit", 5.0))
                
        except Exception as e:
            self.logger.error(f"API scan error for {url}: {str(e)}")
        
        return findings
    
    def _is_api_endpoint(self, url: str) -> bool:
        """Check if URL looks like an API endpoint"""
        api_indicators = [
            "/api/", "/v1/", "/v2/", "/v3/", "/rest/", "/graphql",
            ".json", ".xml", "/soap", "/wsdl"
        ]
        return any(indicator in url.lower() for indicator in api_indicators)
    
    async def _detect_api_type(self, session: aiohttp.ClientSession, url: str) -> str:
        """Detect the type of API"""
        try:
            async with session.get(url) as response:
                content_type = response.headers.get('content-type', '').lower()
                response_text = await response.text()
                
                # GraphQL detection
                if 'graphql' in url.lower() or 'graphql' in content_type:
                    return "graphql"
                
                # SOAP detection
                if 'soap' in content_type or 'wsdl' in url.lower() or 'soap:envelope' in response_text:
                    return "soap"
                
                # Default to REST
                return "rest"
                
        except Exception:
            return "rest"  # Default assumption
    
    async def _scan_graphql_api(self, session: aiohttp.ClientSession, url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Scan GraphQL API for vulnerabilities"""
        findings = []
        
        try:
            # Test introspection query
            introspection_payload = {
                "query": self.graphql_introspection_query
            }
            
            async with session.post(url, json=introspection_payload) as response:
                if response.status == 200:
                    response_data = await response.json()
                    
                    # Check if introspection is enabled
                    if 'data' in response_data and '__schema' in response_data['data']:
                        finding = VulnerabilityFinding(
                            vulnerability_id="graphql_introspection_enabled",
                            name="GraphQL Introspection Enabled",
                            description="GraphQL introspection is enabled, exposing schema information",
                            severity=VulnSeverity.MEDIUM,
                            confidence=0.9,
                            affected_url=url,
                            affected_parameter="query",
                            http_method="POST",
                            payload=self.graphql_introspection_query,
                            evidence={"response": response_data},
                            remediation="Disable GraphQL introspection in production",
                            references=["https://graphql.org/learn/introspection/"],
                            tags=["graphql", "information_disclosure"],
                            discovered_by=self.engine_type.value,
                            scan_engine=self.engine_type,
                            template_id="graphql_introspection"
                        )
                        findings.append(finding)
            
            # Test for depth-based DoS
            deep_query = self._generate_deep_graphql_query()
            deep_payload = {"query": deep_query}
            
            async with session.post(url, json=deep_payload) as response:
                if response.status == 200:
                    finding = VulnerabilityFinding(
                        vulnerability_id="graphql_depth_dos",
                        name="GraphQL Depth-based DoS",
                        description="GraphQL endpoint vulnerable to depth-based DoS attacks",
                        severity=VulnSeverity.HIGH,
                        confidence=0.7,
                        affected_url=url,
                        affected_parameter="query",
                        http_method="POST",
                        payload=deep_query,
                        evidence={"response_status": response.status},
                        remediation="Implement query depth limiting",
                        references=["https://owasp.org/www-project-graphql-security-cheat-sheet/"],
                        tags=["graphql", "dos"],
                        discovered_by=self.engine_type.value,
                        scan_engine=self.engine_type,
                        template_id="graphql_depth_dos"
                    )
                    findings.append(finding)
                    
        except Exception as e:
            self.logger.error(f"GraphQL scan error: {str(e)}")
        
        return findings
    
    async def _scan_rest_api(self, session: aiohttp.ClientSession, url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Scan REST API for vulnerabilities"""
        findings = []
        
        try:
            # Test HTTP methods
            for test in self.rest_api_tests:
                method = test["method"]
                check = test["check"]
                
                async with session.request(method, url) as response:
                    if method == "OPTIONS" and response.status == 200:
                        # Check CORS configuration
                        allowed_methods = response.headers.get('allow', '')
                        if 'DELETE' in allowed_methods or 'PUT' in allowed_methods:
                            finding = VulnerabilityFinding(
                                vulnerability_id="dangerous_http_methods",
                                name="Dangerous HTTP Methods Allowed",
                                description=f"Dangerous HTTP methods are allowed: {allowed_methods}",
                                severity=VulnSeverity.MEDIUM,
                                confidence=0.8,
                                affected_url=url,
                                affected_parameter="HTTP_METHOD",
                                http_method=method,
                                payload=None,
                                evidence={"allowed_methods": allowed_methods},
                                remediation="Restrict HTTP methods to only those required",
                                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                                tags=["rest_api", "http_methods"],
                                discovered_by=self.engine_type.value,
                                scan_engine=self.engine_type,
                                template_id="dangerous_http_methods"
                            )
                            findings.append(finding)
                    
                    elif method == "TRACE" and response.status == 200:
                        finding = VulnerabilityFinding(
                            vulnerability_id="trace_method_enabled",
                            name="HTTP TRACE Method Enabled",
                            description="HTTP TRACE method is enabled, potential for XST attacks",
                            severity=VulnSeverity.MEDIUM,
                            confidence=0.9,
                            affected_url=url,
                            affected_parameter="HTTP_METHOD",
                            http_method=method,
                            payload=None,
                            evidence={"response_status": response.status},
                            remediation="Disable HTTP TRACE method",
                            references=["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                            tags=["rest_api", "xst"],
                            discovered_by=self.engine_type.value,
                            scan_engine=self.engine_type,
                            template_id="trace_method_enabled"
                        )
                        findings.append(finding)
            
            # Test for injection vulnerabilities
            findings.extend(await self._test_api_injections(session, url, target))
            
        except Exception as e:
            self.logger.error(f"REST API scan error: {str(e)}")
        
        return findings
    
    async def _scan_soap_api(self, session: aiohttp.ClientSession, url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Scan SOAP API for vulnerabilities"""
        findings = []
        
        try:
            # Test for WSDL exposure
            wsdl_url = url.replace('soap', 'wsdl') if 'soap' in url else f"{url}?wsdl"
            
            async with session.get(wsdl_url) as response:
                if response.status == 200:
                    content = await response.text()
                    if 'wsdl:definitions' in content or 'definitions' in content:
                        finding = VulnerabilityFinding(
                            vulnerability_id="wsdl_exposure",
                            name="WSDL File Exposed",
                            description="WSDL file is publicly accessible, exposing service structure",
                            severity=VulnSeverity.LOW,
                            confidence=0.9,
                            affected_url=wsdl_url,
                            affected_parameter=None,
                            http_method="GET",
                            payload=None,
                            evidence={"wsdl_content": content[:500]},
                            remediation="Restrict access to WSDL files",
                            references=["https://owasp.org/www-project-web-security-testing-guide/"],
                            tags=["soap", "information_disclosure"],
                            discovered_by=self.engine_type.value,
                            scan_engine=self.engine_type,
                            template_id="wsdl_exposure"
                        )
                        findings.append(finding)
            
            # Test for XML injection
            xml_payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test "injection">]><soap:Envelope><soap:Body>&test;</soap:Body></soap:Envelope>'
            
            async with session.post(url, data=xml_payload, headers={'Content-Type': 'text/xml'}) as response:
                response_text = await response.text()
                if 'injection' in response_text:
                    finding = VulnerabilityFinding(
                        vulnerability_id="soap_xml_injection",
                        name="SOAP XML Injection",
                        description="SOAP endpoint vulnerable to XML injection attacks",
                        severity=VulnSeverity.HIGH,
                        confidence=0.8,
                        affected_url=url,
                        affected_parameter="XML_BODY",
                        http_method="POST",
                        payload=xml_payload,
                        evidence={"response": response_text[:500]},
                        remediation="Implement proper XML parsing and validation",
                        references=["https://owasp.org/www-community/vulnerabilities/XML_Injection"],
                        tags=["soap", "xml_injection"],
                        discovered_by=self.engine_type.value,
                        scan_engine=self.engine_type,
                        template_id="soap_xml_injection"
                    )
                    findings.append(finding)
                    
        except Exception as e:
            self.logger.error(f"SOAP API scan error: {str(e)}")
        
        return findings
    
    async def _check_api_authentication(self, session: aiohttp.ClientSession, url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check API authentication mechanisms"""
        findings = []
        
        try:
            # Test access without authentication
            async with session.get(url) as response:
                if response.status == 200:
                    content = await response.text()
                    # Check if sensitive data is returned without auth
                    if any(keyword in content.lower() for keyword in ['password', 'token', 'secret', 'key']):
                        finding = VulnerabilityFinding(
                            vulnerability_id="unauthenticated_access",
                            name="Unauthenticated API Access",
                            description="API endpoint accessible without authentication",
                            severity=VulnSeverity.HIGH,
                            confidence=0.8,
                            affected_url=url,
                            affected_parameter=None,
                            http_method="GET",
                            payload=None,
                            evidence={"response_snippet": content[:200]},
                            remediation="Implement proper authentication",
                            references=["https://owasp.org/www-project-api-security/"],
                            tags=["api", "authentication"],
                            discovered_by=self.engine_type.value,
                            scan_engine=self.engine_type,
                            template_id="unauthenticated_access"
                        )
                        findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Authentication check error: {str(e)}")
        
        return findings
    
    async def _check_api_authorization(self, session: aiohttp.ClientSession, url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check API authorization mechanisms"""
        findings = []
        
        try:
            # Test with weak/default tokens
            weak_tokens = ["admin", "test", "123456", "bearer", "token"]
            
            for token in weak_tokens:
                headers = {"Authorization": f"Bearer {token}"}
                async with session.get(url, headers=headers) as response:
                    if response.status == 200:
                        finding = VulnerabilityFinding(
                            vulnerability_id="weak_api_token",
                            name="Weak API Token Accepted",
                            description=f"API accepts weak token: {token}",
                            severity=VulnSeverity.CRITICAL,
                            confidence=0.9,
                            affected_url=url,
                            affected_parameter="Authorization",
                            http_method="GET",
                            payload=token,
                            evidence={"token": token, "response_status": response.status},
                            remediation="Implement strong token validation",
                            references=["https://owasp.org/www-project-api-security/"],
                            tags=["api", "authorization", "weak_token"],
                            discovered_by=self.engine_type.value,
                            scan_engine=self.engine_type,
                            template_id="weak_api_token"
                        )
                        findings.append(finding)
                        break  # Found one, don't test others
        
        except Exception as e:
            self.logger.error(f"Authorization check error: {str(e)}")
        
        return findings
    
    async def _check_api_rate_limiting(self, session: aiohttp.ClientSession, url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check API rate limiting"""
        findings = []
        
        try:
            # Send multiple rapid requests
            rapid_requests = 10
            success_count = 0
            
            for _ in range(rapid_requests):
                async with session.get(url) as response:
                    if response.status == 200:
                        success_count += 1
            
            # If most requests succeed, rate limiting might be weak
            if success_count >= rapid_requests * 0.8:
                finding = VulnerabilityFinding(
                    vulnerability_id="weak_rate_limiting",
                    name="Weak API Rate Limiting",
                    description="API lacks proper rate limiting protection",
                    severity=VulnSeverity.MEDIUM,
                    confidence=0.7,
                    affected_url=url,
                    affected_parameter=None,
                    http_method="GET",
                    payload=None,
                    evidence={"successful_requests": success_count, "total_requests": rapid_requests},
                    remediation="Implement proper rate limiting",
                    references=["https://owasp.org/www-project-api-security/"],
                    tags=["api", "rate_limiting"],
                    discovered_by=self.engine_type.value,
                    scan_engine=self.engine_type,
                    template_id="weak_rate_limiting"
                )
                findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Rate limiting check error: {str(e)}")
        
        return findings
    
    async def _check_api_cors(self, session: aiohttp.ClientSession, url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check API CORS configuration"""
        findings = []
        
        try:
            headers = {"Origin": "https://evil.com"}
            async with session.options(url, headers=headers) as response:
                cors_origin = response.headers.get('access-control-allow-origin', '')
                
                if cors_origin == '*':
                    finding = VulnerabilityFinding(
                        vulnerability_id="cors_wildcard",
                        name="CORS Wildcard Origin",
                        description="API allows all origins via CORS wildcard",
                        severity=VulnSeverity.MEDIUM,
                        confidence=0.9,
                        affected_url=url,
                        affected_parameter="Origin",
                        http_method="OPTIONS",
                        payload="*",
                        evidence={"cors_header": cors_origin},
                        remediation="Restrict CORS to specific origins",
                        references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                        tags=["api", "cors"],
                        discovered_by=self.engine_type.value,
                        scan_engine=self.engine_type,
                        template_id="cors_wildcard"
                    )
                    findings.append(finding)
                
                elif 'evil.com' in cors_origin:
                    finding = VulnerabilityFinding(
                        vulnerability_id="cors_reflected_origin",
                        name="CORS Reflected Origin",
                        description="API reflects arbitrary origins in CORS headers",
                        severity=VulnSeverity.HIGH,
                        confidence=0.9,
                        affected_url=url,
                        affected_parameter="Origin",
                        http_method="OPTIONS",
                        payload="https://evil.com",
                        evidence={"cors_header": cors_origin},
                        remediation="Validate CORS origins against whitelist",
                        references=["https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"],
                        tags=["api", "cors"],
                        discovered_by=self.engine_type.value,
                        scan_engine=self.engine_type,
                        template_id="cors_reflected_origin"
                    )
                    findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"CORS check error: {str(e)}")
        
        return findings
    
    async def _check_api_versioning(self, session: aiohttp.ClientSession, url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check API versioning issues"""
        findings = []
        
        try:
            # Test for old API versions
            version_patterns = ['/v1/', '/v2/', '/api/v1/', '/api/v2/']
            
            for pattern in version_patterns:
                if pattern not in url:
                    test_url = url.replace('/api/', pattern).replace('/v3/', pattern).replace('/v4/', pattern)
                    
                    async with session.get(test_url) as response:
                        if response.status == 200:
                            finding = VulnerabilityFinding(
                                vulnerability_id="old_api_version",
                                name="Old API Version Accessible",
                                description=f"Old API version accessible at {test_url}",
                                severity=VulnSeverity.LOW,
                                confidence=0.8,
                                affected_url=test_url,
                                affected_parameter=None,
                                http_method="GET",
                                payload=None,
                                evidence={"version_url": test_url},
                                remediation="Deprecate and remove old API versions",
                                references=["https://owasp.org/www-project-api-security/"],
                                tags=["api", "versioning"],
                                discovered_by=self.engine_type.value,
                                scan_engine=self.engine_type,
                                template_id="old_api_version"
                            )
                            findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Versioning check error: {str(e)}")
        
        return findings
    
    async def _check_api_documentation_exposure(self, session: aiohttp.ClientSession, url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for exposed API documentation"""
        findings = []
        
        try:
            # Common documentation endpoints
            doc_endpoints = ['/docs', '/swagger', '/api-docs', '/openapi.json', '/swagger.json']
            base_url = '/'.join(url.split('/')[:3])
            
            for endpoint in doc_endpoints:
                doc_url = f"{base_url}{endpoint}"
                
                async with session.get(doc_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        if any(keyword in content.lower() for keyword in ['swagger', 'openapi', 'api documentation']):
                            finding = VulnerabilityFinding(
                                vulnerability_id="api_docs_exposed",
                                name="API Documentation Exposed",
                                description=f"API documentation exposed at {doc_url}",
                                severity=VulnSeverity.LOW,
                                confidence=0.9,
                                affected_url=doc_url,
                                affected_parameter=None,
                                http_method="GET",
                                payload=None,
                                evidence={"documentation_url": doc_url},
                                remediation="Restrict access to API documentation in production",
                                references=["https://owasp.org/www-project-api-security/"],
                                tags=["api", "documentation", "information_disclosure"],
                                discovered_by=self.engine_type.value,
                                scan_engine=self.engine_type,
                                template_id="api_docs_exposed"
                            )
                            findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Documentation check error: {str(e)}")
        
        return findings
    
    async def _test_api_injections(self, session: aiohttp.ClientSession, url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Test API for injection vulnerabilities"""
        findings = []
        
        try:
            for payload in self.api_injection_payloads:
                # Test JSON injection
                if payload.startswith('{'):
                    headers = {'Content-Type': 'application/json'}
                    async with session.post(url, data=payload, headers=headers) as response:
                        response_text = await response.text()
                        
                        # Check for error messages indicating injection
                        if any(error in response_text.lower() for error in ['error', 'exception', 'syntax']):
                            finding = VulnerabilityFinding(
                                vulnerability_id="api_json_injection",
                                name="API JSON Injection",
                                description="API vulnerable to JSON injection attacks",
                                severity=VulnSeverity.HIGH,
                                confidence=0.7,
                                affected_url=url,
                                affected_parameter="JSON_BODY",
                                http_method="POST",
                                payload=payload,
                                evidence={"response": response_text[:200]},
                                remediation="Implement proper input validation and sanitization",
                                references=["https://owasp.org/www-project-api-security/"],
                                tags=["api", "injection", "json"],
                                discovered_by=self.engine_type.value,
                                scan_engine=self.engine_type,
                                template_id="api_json_injection"
                            )
                            findings.append(finding)
        
        except Exception as e:
            self.logger.error(f"Injection test error: {str(e)}")
        
        return findings
    
    def _generate_deep_graphql_query(self, depth: int = 10) -> str:
        """Generate deeply nested GraphQL query for DoS testing"""
        query = "{ user { "
        for i in range(depth):
            query += "friends { "
        query += "name "
        for i in range(depth):
            query += "} "
        query += "} }"
        return query