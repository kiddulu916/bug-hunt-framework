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

from backend.services.vulnerability_scanner import VulnerabilityFinding, ScanEngineType, VulnSeverity


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
    
    async def _check_api_authorization(self, session: aiohttp.ClientSession,
                                      url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check API authorization mechanisms"""
        findings = []
        
        # Test privilege escalation through parameter manipulation
        privilege_escalation_tests = [
            {"admin": "true"},
            {"role": "administrator"},
            {"user_id": "1"},  # Try accessing admin user
            {"is_admin": True},
            {"privileges": ["admin", "read", "write"]},
            {"scope": "admin"}
        ]
        
        for test_params in privilege_escalation_tests:
            try:
                # Test with GET parameters
                async with session.get(url, params=test_params) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check for admin/privileged content
                        admin_indicators = [
                            "admin", "administrator", "dashboard", "management",
                            "users", "system", "config", "settings"
                        ]
                        
                        if any(indicator in content.lower() for indicator in admin_indicators):
                            finding = VulnerabilityFinding(
                                vulnerability_id="",
                                name="Potential Privilege Escalation",
                                description="API may allow privilege escalation through parameter manipulation",
                                severity=VulnSeverity.HIGH,
                                confidence=0.6,
                                affected_url=url,
                                affected_parameter=list(test_params.keys())[0],
                                http_method="GET",
                                payload=str(test_params),
                                evidence={
                                    "test_parameters": test_params,
                                    "admin_indicators_found": [
                                        ind for ind in admin_indicators 
                                        if ind in content.lower()
                                    ],
                                    "response_length": len(content)
                                },
                                remediation="Implement proper authorization checks and avoid client-side privilege controls",
                                references=[
                                    "https://owasp.org/www-project-api-security/"
                                ],
                                tags=["authorization", "privilege-escalation", "idor"],
                                discovered_by="custom_api_scanner",
                                scan_engine=self.engine_type,
                                template_id="privilege_escalation"
                            )
                            findings.append(finding)
                            break  # Don't test more parameters if one succeeds
                
                # Test with POST body
                headers = {"Content-Type": "application/json"}
                async with session.post(url, json=test_params, headers=headers) as response:
                    if response.status in [200, 201]:
                        content = await response.text()
                        
                        if "created" in content.lower() or "success" in content.lower():
                            finding = VulnerabilityFinding(
                                vulnerability_id="",
                                name="Mass Assignment Vulnerability",
                                description="API accepts additional parameters that may lead to privilege escalation",
                                severity=VulnSeverity.MEDIUM,
                                confidence=0.7,
                                affected_url=url,
                                affected_parameter="request_body",
                                http_method="POST",
                                payload=json.dumps(test_params),
                                evidence={
                                    "mass_assignment_parameters": test_params,
                                    "response_indicates_success": True,
                                    "response_content": content[:500]
                                },
                                remediation="Use explicit parameter whitelisting and avoid mass assignment",
                                references=[
                                    "https://owasp.org/www-community/vulnerabilities/Mass_Assignment_Cheat_Sheet"
                                ],
                                tags=["mass-assignment", "parameter-pollution", "authorization"],
                                discovered_by="custom_api_scanner",
                                scan_engine=self.engine_type,
                                template_id="mass_assignment"
                            )
                            findings.append(finding)
                            break
            
            except Exception as e:
                self.logger.debug(f"Authorization test failed: {e}")
        
        return findings
    
    async def _check_api_rate_limiting(self, session: aiohttp.ClientSession,
                                      url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check API rate limiting"""
        findings = []
        
        try:
            # Send multiple requests rapidly
            rapid_requests = 20
            responses = []
            
            tasks = []
            for _ in range(rapid_requests):
                task = session.get(url)
                tasks.append(task)
            
            # Execute requests concurrently
            async_responses = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Analyze responses
            status_codes = []
            rate_limit_headers = []
            
            for resp in async_responses:
                if isinstance(resp, Exception):
                    continue
                
                try:
                    status_codes.append(resp.status)
                    
                    # Check for rate limiting headers
                    headers = dict(resp.headers)
                    rate_headers = {
                        k: v for k, v in headers.items()
                        if any(rate_term in k.lower() 
                              for rate_term in ['rate', 'limit', 'quota', 'throttle'])
                    }
                    
                    if rate_headers:
                        rate_limit_headers.append(rate_headers)
                    
                    resp.close()
                except Exception as e:
                    self.logger.debug(f"Error processing response: {e}")
            
            # Check if all requests succeeded (potential lack of rate limiting)
            successful_requests = len([s for s in status_codes if s == 200])
            
            if successful_requests >= rapid_requests * 0.9:  # 90% success rate
                finding = VulnerabilityFinding(
                    vulnerability_id="",
                    name="Missing API Rate Limiting",
                    description="API does not implement rate limiting, allowing potential abuse",
                    severity=VulnSeverity.MEDIUM,
                    confidence=0.7,
                    affected_url=url,
                    affected_parameter=None,
                    http_method="GET",
                    payload=None,
                    evidence={
                        "rapid_requests_sent": rapid_requests,
                        "successful_responses": successful_requests,
                        "success_rate": successful_requests / rapid_requests,
                        "rate_limit_headers_found": len(rate_limit_headers) > 0,
                        "status_codes": status_codes
                    },
                    remediation="Implement API rate limiting to prevent abuse and DoS attacks",
                    references=[
                        "https://owasp.org/www-project-api-security/"
                    ],
                    tags=["rate-limiting", "dos", "api-abuse"],
                    discovered_by="custom_api_scanner",
                    scan_engine=self.engine_type,
                    template_id="missing_rate_limiting"
                )
                findings.append(finding)
        
        except Exception as e:
            self.logger.debug(f"Rate limiting check failed: {e}")
        
        return findings
    
    async def _check_api_cors(self, session: aiohttp.ClientSession,
                             url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check API CORS configuration"""
        findings = []
        
        # Test CORS with malicious origin
        malicious_origins = [
            "https://evil.com",
            "https://attacker.example.com",
            "null",
            "file://",
            "data:text/html,<script>alert('XSS')</script>"
        ]
        
        for origin in malicious_origins:
            try:
                headers = {"Origin": origin}
                
                async with session.options(url, headers=headers) as response:
                    allow_origin = response.headers.get("access-control-allow-origin")
                    allow_credentials = response.headers.get("access-control-allow-credentials")
                    
                    if allow_origin == origin or allow_origin == "*":
                        severity = VulnSeverity.HIGH if allow_credentials == "true" else VulnSeverity.MEDIUM
                        
                        finding = VulnerabilityFinding(
                            vulnerability_id="",
                            name="CORS Misconfiguration",
                            description=f"API accepts requests from potentially malicious origin: {origin}",
                            severity=severity,
                            confidence=0.8,
                            affected_url=url,
                            affected_parameter=None,
                            http_method="OPTIONS",
                            payload=origin,
                            evidence={
                                "malicious_origin": origin,
                                "access_control_allow_origin": allow_origin,
                                "access_control_allow_credentials": allow_credentials,
                                "cors_headers": dict(response.headers)
                            },
                            remediation="Configure CORS to only allow trusted origins and avoid wildcard with credentials",
                            references=[
                                "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
                            ],
                            tags=["cors", "origin-validation", "cross-domain"],
                            discovered_by="custom_api_scanner",
                            scan_engine=self.engine_type,
                            template_id="cors_misconfiguration"
                        )
                        findings.append(finding)
                        break  # Found misconfiguration, no need to test more origins
            
            except Exception as e:
                self.logger.debug(f"CORS test failed for origin {origin}: {e}")
        
        return findings
    
    async def _check_api_versioning(self, session: aiohttp.ClientSession,
                                   url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check API versioning security"""
        findings = []
        
        # Test for version disclosure and older version access
        version_patterns = [
            "/v1/", "/v2/", "/v3/", "/api/v1/", "/api/v2/",
            "?version=1", "?version=2", "?v=1", "?v=2"
        ]
        
        base_url = url.rstrip('/')
        
        for pattern in version_patterns:
            try:
                if pattern.startswith('?'):
                    test_url = f"{base_url}{pattern}"
                else:
                    test_url = f"{base_url}{pattern}"
                
                async with session.get(test_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        # Check if this reveals different/older API functionality
                        version_indicators = [
                            "deprecated", "legacy", "old", "version", "v1", "v2",
                            "api_version", "build", "release"
                        ]
                        
                        if any(indicator in content.lower() for indicator in version_indicators):
                            finding = VulnerabilityFinding(
                                vulnerability_id="",
                                name="API Version Information Disclosure",
                                description="API exposes version information that may help attackers",
                                severity=VulnSeverity.LOW,
                                confidence=0.6,
                                affected_url=test_url,
                                affected_parameter=None,
                                http_method="GET",
                                payload=None,
                                evidence={
                                    "version_pattern": pattern,
                                    "version_indicators": [
                                        ind for ind in version_indicators 
                                        if ind in content.lower()
                                    ],
                                    "response_content": content[:500]
                                },
                                remediation="Remove version information from API responses and disable access to old versions",
                                references=[
                                    "https://owasp.org/www-project-api-security/"
                                ],
                                tags=["version-disclosure", "information-leak", "api-versioning"],
                                discovered_by="custom_api_scanner",
                                scan_engine=self.engine_type,
                                template_id="api_version_disclosure"
                            )
                            findings.append(finding)
            
            except Exception as e:
                self.logger.debug(f"Version test failed for {pattern}: {e}")
        
        return findings
    
    async def _check_api_documentation_exposure(self, session: aiohttp.ClientSession,
                                               url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check for exposed API documentation"""
        findings = []
        
        # Common API documentation endpoints
        doc_endpoints = [
            "/docs", "/documentation", "/api-docs", "/api/docs",
            "/swagger", "/swagger-ui", "/swagger.json", "/swagger.yaml",
            "/openapi.json", "/openapi.yaml", "/redoc", "/rapidoc",
            "/graphiql", "/playground", "/postman", "/insomnia"
        ]
        
        base_url = url.split('/api')[0] if '/api' in url else '/'.join(url.split('/')[:3])
        
        for endpoint in doc_endpoints:
            try:
                doc_url = f"{base_url}{endpoint}"
                
                async with session.get(doc_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        content_type = response.headers.get("content-type", "")
                        
                        # Check if this is actually API documentation
                        doc_indicators = [
                            "swagger", "openapi", "api documentation", "endpoints",
                            "postman", "insomnia", "graphiql", "playground",
                            "redoc", "rapidoc", "api reference"
                        ]
                        
                        if (any(indicator in content.lower() for indicator in doc_indicators) or
                            "application/json" in content_type and ("paths" in content or "definitions" in content)):
                            
                            # Check for sensitive information in documentation
                            sensitive_in_docs = [
                                "password", "secret", "key", "token", "admin",
                                "internal", "private", "test", "staging"
                            ]
                            
                            sensitive_found = [
                                term for term in sensitive_in_docs 
                                if term in content.lower()
                            ]
                            
                            severity = VulnSeverity.MEDIUM if sensitive_found else VulnSeverity.LOW
                            
                            finding = VulnerabilityFinding(
                                vulnerability_id="",
                                name="API Documentation Exposed",
                                description="API documentation is publicly accessible",
                                severity=severity,
                                confidence=0.9,
                                affected_url=doc_url,
                                affected_parameter=None,
                                http_method="GET",
                                payload=None,
                                evidence={
                                    "documentation_type": endpoint,
                                    "sensitive_terms_found": sensitive_found,
                                    "content_length": len(content),
                                    "content_type": content_type
                                },
                                remediation="Restrict access to API documentation in production environments",
                                references=[
                                    "https://owasp.org/www-project-api-security/"
                                ],
                                tags=["documentation", "information-disclosure", "api-exposure"],
                                discovered_by="custom_api_scanner",
                                scan_engine=self.engine_type,
                                template_id="api_documentation_exposure"
                            )
                            findings.append(finding)
            
            except Exception as e:
                self.logger.debug(f"Documentation check failed for {endpoint}: {e}")
        
        return findings
    
    def _is_api_endpoint(self, url: str) -> bool:
        """Determine if URL is likely an API endpoint"""
        
        api_indicators = [
            "/api/", "/rest/", "/graphql", "/soap",
            "/service/", "/webservice/", "/ws/"
        ]
        
        # Check URL path
        url_lower = url.lower()
        if any(indicator in url_lower for indicator in api_indicators):
            return True
        
        # Check for API-like patterns
        if re.search(r'/v\d+/', url_lower):  # Version pattern like /v1/
            return True
        
        # Check file extensions that suggest API
        api_extensions = ['.json', '.xml', '.wsdl']
        if any(url_lower.endswith(ext) for ext in api_extensions):
            return True
        
        return False
    
    def get_engine_info(self) -> Dict[str, Any]:
        """Get engine information"""
        return {
            "name": "Custom API Security Scanner",
            "type": self.engine_type.value,
            "version": "1.0.0",
            "description": "Specialized security scanner for REST APIs, GraphQL, and SOAP services",
            "supported_protocols": ["HTTP", "HTTPS"],
            "api_types": ["REST", "GraphQL", "SOAP"],
            "capabilities": [
                "GraphQL introspection testing",
                "GraphQL query depth analysis", 
                "REST API security testing",
                "SOAP/WSDL security testing",
                "API authentication testing",
                "API authorization testing",
                "CORS misconfiguration detection",
                "Rate limiting analysis",
                "API versioning security",
                "Documentation exposure detection",
                "Mass assignment testing",
                "Privilege escalation testing"
            ],
            "test_categories": [
                "Authentication bypass",
                "Authorization flaws",
                "Information disclosure",
                "Input validation",
                "Rate limiting",
                "CORS policy",
                "API documentation exposure",
                "Version information leakage"
            ]
        } def scan_targets(self, targets: List[Dict[str, Any]], 
                          config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Scan API targets for vulnerabilities"""
        findings = []
        
        # Filter for API endpoints
        api_targets = [t for t in targets if self._is_api_endpoint(t["url"])]
        
        if not api_targets:
            return findings
        
        rate_limit = config.get("rate_limit", 5.0)
        timeout = aiohttp.ClientTimeout(total=config.get("timeout", 30))
        
        async with aiohttp.ClientSession(timeout=timeout) as session:
            semaphore = asyncio.Semaphore(int(rate_limit))
            
            scan_tasks = []
            for target in api_targets:
                task = self._scan_api_target(session, semaphore, target, config)
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
                
                # Rate limiting
                await asyncio.sleep(1 / config.get("rate_limit", 5.0))
                
        except Exception as e:
            self.logger.error(f"Error scanning API {url}: {e}")
        
        return findings
    
    async def _detect_api_type(self, session: aiohttp.ClientSession, url: str) -> str:
        """Detect the type of API"""
        
        try:
            # Check for GraphQL
            if "graphql" in url.lower():
                return "graphql"
            
            # Check content type and responses
            async with session.get(url) as response:
                content_type = response.headers.get("content-type", "").lower()
                
                if "application/json" in content_type:
                    return "rest"
                elif "text/xml" in content_type or "application/soap" in content_type:
                    return "soap"
                elif "application/graphql" in content_type:
                    return "graphql"
                
                # Check response content
                try:
                    content = await response.text()
                    if "graphql" in content.lower():
                        return "graphql"
                    elif "<soap:" in content.lower() or "<wsdl:" in content.lower():
                        return "soap"
                except:
                    pass
            
            return "rest"  # Default assumption
            
        except Exception:
            return "rest"
    
    async def _scan_graphql_api(self, session: aiohttp.ClientSession, 
                               url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Scan GraphQL API for vulnerabilities"""
        findings = []
        
        # Test GraphQL introspection
        try:
            headers = {"Content-Type": "application/json"}
            payload = {"query": self.graphql_introspection_query}
            
            async with session.post(url, json=payload, headers=headers) as response:
                if response.status == 200:
                    result = await response.json()
                    
                    if "data" in result and "__schema" in result["data"]:
                        finding = VulnerabilityFinding(
                            vulnerability_id="",
                            name="GraphQL Introspection Enabled",
                            description="GraphQL introspection is enabled, exposing schema information",
                            severity=VulnSeverity.MEDIUM,
                            confidence=0.9,
                            affected_url=url,
                            affected_parameter=None,
                            http_method="POST",
                            payload=self.graphql_introspection_query,
                            evidence={
                                "introspection_data": result["data"]["__schema"],
                                "exposed_types": len(result["data"]["__schema"].get("types", [])),
                                "response": str(result)[:1000]
                            },
                            remediation="Disable GraphQL introspection in production environments",
                            references=[
                                "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"
                            ],
                            tags=["graphql", "information-disclosure", "introspection"],
                            discovered_by="custom_api_scanner",
                            scan_engine=self.engine_type,
                            template_id="graphql_introspection"
                        )
                        findings.append(finding)
        
        except Exception as e:
            self.logger.debug(f"GraphQL introspection test failed: {e}")
        
        # Test GraphQL query depth
        depth_attack_query = """
        {
            user {
                posts {
                    comments {
                        user {
                            posts {
                                comments {
                                    user {
                                        posts {
                                            title
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        
        try:
            payload = {"query": depth_attack_query}
            async with session.post(url, json=payload, headers=headers) as response:
                if response.status == 200:
                    # If query succeeds, there might be no depth limiting
                    finding = VulnerabilityFinding(
                        vulnerability_id="",
                        name="GraphQL Query Depth Limiting Missing",
                        description="GraphQL API may be vulnerable to query depth attacks",
                        severity=VulnSeverity.MEDIUM,
                        confidence=0.7,
                        affected_url=url,
                        affected_parameter=None,
                        http_method="POST",
                        payload=depth_attack_query,
                        evidence={
                            "deep_query_accepted": True,
                            "response_status": response.status
                        },
                        remediation="Implement query depth limiting and complexity analysis",
                        references=[
                            "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/12-API_Testing/01-Testing_GraphQL"
                        ],
                        tags=["graphql", "dos", "query-depth"],
                        discovered_by="custom_api_scanner",
                        scan_engine=self.engine_type,
                        template_id="graphql_depth_limit"
                    )
                    findings.append(finding)
        
        except Exception as e:
            self.logger.debug(f"GraphQL depth test failed: {e}")
        
        return findings
    
    async def _scan_rest_api(self, session: aiohttp.ClientSession,
                            url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Scan REST API for vulnerabilities"""
        findings = []
        
        # Test HTTP methods
        for test in self.rest_api_tests:
            try:
                method = test["method"]
                check_type = test["check"]
                
                async with session.request(method, url) as response:
                    if method == "OPTIONS" and response.status in [200, 204]:
                        # Check CORS headers
                        access_control_headers = [
                            h for h in response.headers.keys() 
                            if h.lower().startswith("access-control-")
                        ]
                        
                        if access_control_headers:
                            allow_origin = response.headers.get("access-control-allow-origin", "")
                            
                            if allow_origin == "*":
                                finding = VulnerabilityFinding(
                                    vulnerability_id="",
                                    name="CORS Wildcard Origin",
                                    description="API allows requests from any origin (*)",
                                    severity=VulnSeverity.MEDIUM,
                                    confidence=0.9,
                                    affected_url=url,
                                    affected_parameter=None,
                                    http_method="OPTIONS",
                                    payload=None,
                                    evidence={
                                        "access_control_allow_origin": allow_origin,
                                        "cors_headers": access_control_headers
                                    },
                                    remediation="Configure CORS to allow only trusted origins",
                                    references=[
                                        "https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny"
                                    ],
                                    tags=["cors", "misconfiguration", "rest-api"],
                                    discovered_by="custom_api_scanner",
                                    scan_engine=self.engine_type,
                                    template_id="cors_wildcard"
                                )
                                findings.append(finding)
                    
                    elif method == "TRACE" and response.status == 200:
                        finding = VulnerabilityFinding(
                            vulnerability_id="",
                            name="HTTP TRACE Method Enabled",
                            description="HTTP TRACE method is enabled and may lead to XST attacks",
                            severity=VulnSeverity.LOW,
                            confidence=0.8,
                            affected_url=url,
                            affected_parameter=None,
                            http_method="TRACE",
                            payload=None,
                            evidence={
                                "trace_response": str(response.headers),
                                "status_code": response.status
                            },
                            remediation="Disable HTTP TRACE method on the web server",
                            references=[
                                "https://owasp.org/www-community/attacks/Cross_Site_Tracing"
                            ],
                            tags=["trace", "xst", "http-methods"],
                            discovered_by="custom_api_scanner",
                            scan_engine=self.engine_type,
                            template_id="http_trace_enabled"
                        )
                        findings.append(finding)
            
            except Exception as e:
                self.logger.debug(f"HTTP method test {method} failed: {e}")
        
        return findings
    
    async def _scan_soap_api(self, session: aiohttp.ClientSession,
                            url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Scan SOAP API for vulnerabilities"""
        findings = []
        
        # Test WSDL exposure
        wsdl_endpoints = [
            f"{url}?wsdl",
            f"{url}?WSDL",
            f"{url}/wsdl",
            f"{url.rstrip('/')}.wsdl"
        ]
        
        for wsdl_url in wsdl_endpoints:
            try:
                async with session.get(wsdl_url) as response:
                    if response.status == 200:
                        content = await response.text()
                        
                        if "wsdl:" in content.lower() or "soap:" in content.lower():
                            finding = VulnerabilityFinding(
                                vulnerability_id="",
                                name="WSDL File Exposed",
                                description="WSDL file is publicly accessible, revealing API structure",
                                severity=VulnSeverity.LOW,
                                confidence=0.9,
                                affected_url=wsdl_url,
                                affected_parameter=None,
                                http_method="GET",
                                payload=None,
                                evidence={
                                    "wsdl_content_sample": content[:500],
                                    "wsdl_url": wsdl_url,
                                    "content_length": len(content)
                                },
                                remediation="Restrict access to WSDL files or remove them from production",
                                references=[
                                    "https://owasp.org/www-community/vulnerabilities/Information_exposure_through_directory_listing"
                                ],
                                tags=["wsdl", "information-disclosure", "soap"],
                                discovered_by="custom_api_scanner",
                                scan_engine=self.engine_type,
                                template_id="wsdl_exposure"
                            )
                            findings.append(finding)
                            break  # Found WSDL, no need to check other URLs
            
            except Exception as e:
                self.logger.debug(f"WSDL check failed for {wsdl_url}: {e}")
        
        return findings
    
    async def _check_api_authentication(self, session: aiohttp.ClientSession,
                                       url: str, target: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Check API authentication mechanisms"""
        findings = []
        
        # Test unauthenticated access
        try:
            async with session.get(url) as response:
                if response.status == 200:
                    # Check if sensitive data is exposed without authentication
                    content = await response.text()
                    
                    # Look for sensitive data patterns
                    sensitive_patterns = [
                        r'"password":', r'"token":', r'"secret":', r'"api_key":',
                        r'"email":', r'"user_id":', r'"admin":', r'"role":'
                    ]
                    
                    sensitive_data_found = any(
                        re.search(pattern, content, re.IGNORECASE) 
                        for pattern in sensitive_patterns
                    )
                    
                    if sensitive_data_found:
                        finding = VulnerabilityFinding(
                            vulnerability_id="",
                            name="Unauthenticated API Access",
                            description="API endpoint returns sensitive data without authentication",
                            severity=VulnSeverity.HIGH,
                            confidence=0.8,
                            affected_url=url,
                            affected_parameter=None,
                            http_method="GET",
                            payload=None,
                            evidence={
                                "response_contains_sensitive_data": True,
                                "response_length": len(content),
                                "status_code": response.status
                            },
                            remediation="Implement proper authentication and authorization controls",
                            references=[
                                "https://owasp.org/www-project-api-security/"
                            ],
                            tags=["authentication", "unauthorized-access", "api-security"],
                            discovered_by="custom_api_scanner",
                            scan_engine=self.engine_type,
                            template_id="unauthenticated_access"
                        )
                        findings.append(finding)
        
        except Exception as e:
            self.logger.debug(f"Authentication check failed: {e}")
        
        return findings
    
    async