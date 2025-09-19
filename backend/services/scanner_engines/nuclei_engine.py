"""
Nuclei Scanner Engine for Bug Bounty Automation Platform
Integration with Nuclei vulnerability scanner
"""

import asyncio
import json
import logging
import subprocess
import tempfile
import os
from typing import Dict, List, Any
from dataclasses import dataclass

from backend.services.vulnerability_scanner import VulnerabilityFinding, ScanEngineType, VulnSeverity


class NucleiEngine:
    """Nuclei vulnerability scanner engine"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.engine_type = ScanEngineType.NUCLEI
        self.nuclei_path = "nuclei"  # Assuming nuclei is in PATH
        
    async def scan_targets(self, targets: List[Dict[str, Any]], 
                          config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Scan targets using Nuclei"""
        findings = []
        
        # Prepare target URLs
        target_urls = [target["url"] for target in targets]
        
        if not target_urls:
            return findings
        
        try:
            # Create temporary file for URLs
            with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
                for url in target_urls:
                    f.write(f"{url}\n")
                urls_file = f.name
            
            # Build Nuclei command
            cmd = await self._build_nuclei_command(urls_file, config)
            
            # Execute Nuclei
            self.logger.info(f"Running Nuclei on {len(target_urls)} targets")
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Parse results
            if process.returncode == 0 or stdout:
                findings = await self._parse_nuclei_output(stdout.decode(), targets)
            else:
                self.logger.error(f"Nuclei failed: {stderr.decode()}")
            
        except Exception as e:
            self.logger.error(f"Nuclei execution error: {e}")
        finally:
            # Cleanup temporary file
            if 'urls_file' in locals():
                os.unlink(urls_file)
        
        return findings
    
    async def _build_nuclei_command(self, urls_file: str, config: Dict[str, Any]) -> List[str]:
        """Build Nuclei command with configuration"""
        cmd = [
            self.nuclei_path,
            "-list", urls_file,
            "-json",  # JSON output
            "-silent",  # Reduce noise
            "-no-color",
            "-timeout", "30",
            "-retries", "1"
        ]
        
        # Rate limiting
        rate_limit = config.get("rate_limit", 5.0)
        cmd.extend(["-rate-limit", str(int(rate_limit))])
        
        # Severity filtering
        severity_filter = config.get("nuclei_severity", ["critical", "high", "medium", "low"])
        if severity_filter:
            cmd.extend(["-severity", ",".join(severity_filter)])
        
        # Template selection based on scan depth
        scan_depth = config.get("scan_depth", 3)
        if scan_depth <= 2:
            # Quick scan - only critical/high templates
            cmd.extend(["-tags", "cve,oast,sqli,xss,rce"])
        elif scan_depth <= 3:
            # Medium scan - common vulnerability classes
            cmd.extend(["-tags", "cve,oast,sqli,xss,rce,ssrf,lfi,ssti"])
        elif scan_depth >= 4:
            # Deep scan - all templates except intrusive
            if not config.get("intrusive_checks", False):
                cmd.extend(["-exclude-tags", "intrusive,dos"])
        
        # Stealth mode
        if config.get("stealth_mode", False):
            cmd.extend(["-no-httpx", "-random-agent"])
        
        # Custom templates directory
        if config.get("custom_templates_dir"):
            cmd.extend(["-templates", config["custom_templates_dir"]])
        
        # Additional Nuclei options
        nuclei_options = config.get("nuclei_options", {})
        for option, value in nuclei_options.items():
            if value is True:
                cmd.append(f"-{option}")
            elif value is not False:
                cmd.extend([f"-{option}", str(value)])
        
        return cmd
    
    async def _parse_nuclei_output(self, output: str, targets: List[Dict[str, Any]]) -> List[VulnerabilityFinding]:
        """Parse Nuclei JSON output into vulnerability findings"""
        findings = []
        
        if not output.strip():
            return findings
        
        # Create target lookup for additional context
        target_lookup = {target["url"]: target for target in targets}
        
        for line in output.strip().split('\n'):
            try:
                if not line.strip():
                    continue
                
                result = json.loads(line)
                
                # Extract vulnerability information
                template_id = result.get("template-id", "")
                template_name = result.get("info", {}).get("name", template_id)
                description = result.get("info", {}).get("description", "")
                severity = result.get("info", {}).get("severity", "info")
                matched_at = result.get("matched-at", result.get("host", ""))
                
                # Get target context
                target_context = self._find_target_context(matched_at, target_lookup)
                
                # Parse request/response if available
                request_data = None
                response_data = None
                
                if "request" in result:
                    request_data = result["request"]
                if "response" in result:
                    response_data = result["response"]
                
                # Extract matcher information
                matcher_name = result.get("matcher-name", "")
                extracted_results = result.get("extracted-results", [])
                
                # Build evidence dictionary
                evidence = {
                    "template_id": template_id,
                    "matcher_name": matcher_name,
                    "extracted_results": extracted_results,
                    "nuclei_info": result.get("info", {}),
                    "timestamp": result.get("timestamp"),
                    "curl_command": result.get("curl-command", "")
                }
                
                if request_data:
                    evidence["request"] = request_data
                if response_data:
                    evidence["response"] = response_data
                
                # Create vulnerability finding
                finding = VulnerabilityFinding(
                    vulnerability_id="",  # Will be set by scanner service
                    name=template_name,
                    description=description or f"Nuclei template {template_id} matched",
                    severity=self._map_nuclei_severity(severity),
                    confidence=self._calculate_confidence(result),
                    affected_url=matched_at,
                    affected_parameter=self._extract_parameter(result),
                    http_method=self._extract_http_method(result),
                    payload=self._extract_payload(result),
                    evidence=evidence,
                    remediation=self._get_remediation_advice(template_id, result),
                    references=self._extract_references(result),
                    tags=result.get("info", {}).get("tags", []),
                    discovered_by="nuclei",
                    scan_engine=self.engine_type,
                    template_id=template_id
                )
                
                findings.append(finding)
                
            except json.JSONDecodeError as e:
                self.logger.debug(f"Failed to parse Nuclei output line: {e}")
                continue
            except Exception as e:
                self.logger.error(f"Error processing Nuclei result: {e}")
                continue
        
        return findings
    
    def _find_target_context(self, matched_url: str, target_lookup: Dict[str, Any]) -> Dict[str, Any]:
        """Find target context for matched URL"""
        # Try exact match first
        if matched_url in target_lookup:
            return target_lookup[matched_url]
        
        # Try to find best match by comparing base URLs
        from urllib.parse import urlparse
        matched_parsed = urlparse(matched_url)
        matched_base = f"{matched_parsed.scheme}://{matched_parsed.netloc}"
        
        for target_url, target_data in target_lookup.items():
            target_parsed = urlparse(target_url)
            target_base = f"{target_parsed.scheme}://{target_parsed.netloc}"
            
            if matched_base == target_base:
                return target_data
        
        return {}
    
    def _map_nuclei_severity(self, nuclei_severity: str) -> VulnSeverity:
        """Map Nuclei severity to VulnSeverity enum"""
        severity_mapping = {
            "critical": VulnSeverity.CRITICAL,
            "high": VulnSeverity.HIGH,
            "medium": VulnSeverity.MEDIUM,
            "low": VulnSeverity.LOW,
            "info": VulnSeverity.INFO,
            "unknown": VulnSeverity.LOW
        }
        
        return severity_mapping.get(nuclei_severity.lower(), VulnSeverity.LOW)
    
    def _calculate_confidence(self, result: Dict[str, Any]) -> float:
        """Calculate confidence score for Nuclei finding"""
        base_confidence = 0.8  # Nuclei templates are generally reliable
        
        # Boost confidence based on factors
        info = result.get("info", {})
        
        # CVE-based templates have higher confidence
        if "cve" in info.get("tags", []):
            base_confidence += 0.1
        
        # Verified templates have higher confidence
        if info.get("verified", False):
            base_confidence += 0.1
        
        # Templates with multiple matchers have higher confidence
        matcher_name = result.get("matcher-name", "")
        if "and" in matcher_name.lower() or len(matcher_name.split(",")) > 1:
            base_confidence += 0.05
        
        # Extracted results indicate successful exploitation
        if result.get("extracted-results"):
            base_confidence += 0.05
        
        return min(1.0, base_confidence)
    
    def _extract_parameter(self, result: Dict[str, Any]) -> str:
        """Extract affected parameter from Nuclei result"""
        # Try to extract parameter from request data
        request = result.get("request", "")
        if isinstance(request, str) and "?" in request:
            # Extract from query string
            from urllib.parse import urlparse, parse_qs
            try:
                parsed_url = urlparse(request.split('\n')[0].split(' ')[1])
                params = parse_qs(parsed_url.query)
                if params:
                    return list(params.keys())[0]
            except:
                pass
        
        # Check matcher name for parameter hints
        matcher_name = result.get("matcher-name", "")
        if "param" in matcher_name.lower():
            return matcher_name
        
        return None
    
    def _extract_http_method(self, result: Dict[str, Any]) -> str:
        """Extract HTTP method from Nuclei result"""
        request = result.get("request", "")
        if isinstance(request, str) and request:
            try:
                method = request.split('\n')[0].split(' ')[0]
                if method in ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]:
                    return method
            except:
                pass
        
        return "GET"  # Default
    
    def _extract_payload(self, result: Dict[str, Any]) -> str:
        """Extract payload from Nuclei result"""
        # Try to extract from matcher name
        matcher_name = result.get("matcher-name", "")
        if matcher_name:
            return matcher_name
        
        # Try to extract from extracted results
        extracted = result.get("extracted-results", [])
        if extracted:
            return str(extracted[0])
        
        # Fall back to template ID
        return result.get("template-id", "")
    
    def _get_remediation_advice(self, template_id: str, result: Dict[str, Any]) -> str:
        """Get remediation advice for vulnerability"""
        # Basic remediation mapping based on template ID patterns
        remediation_mapping = {
            "cve": "Apply the latest security patches and updates",
            "sqli": "Use parameterized queries and input validation",
            "xss": "Implement proper output encoding and input sanitization",
            "ssrf": "Validate and restrict server-side requests",
            "lfi": "Implement proper file path validation and access controls",
            "rce": "Validate and sanitize all user inputs, disable dangerous functions",
            "config": "Review and secure configuration settings",
            "exposure": "Remove or secure exposed sensitive information",
            "default": "Change default credentials and configurations"
        }
        
        template_lower = template_id.lower()
        
        for pattern, advice in remediation_mapping.items():
            if pattern in template_lower:
                return advice
        
        # Get remediation from template info
        info = result.get("info", {})
        if "remediation" in info:
            return info["remediation"]
        
        return "Review and address the identified security issue according to security best practices"
    
    def _extract_references(self, result: Dict[str, Any]) -> List[str]:
        """Extract references from Nuclei result"""
        references = []
        
        info = result.get("info", {})
        
        # Add template references
        if "reference" in info:
            refs = info["reference"]
            if isinstance(refs, list):
                references.extend(refs)
            elif isinstance(refs, str):
                references.append(refs)
        
        # Add CVE references
        if "classification" in info:
            classification = info["classification"]
            if "cve-id" in classification:
                cve_ids = classification["cve-id"]
                if isinstance(cve_ids, list):
                    for cve_id in cve_ids:
                        references.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}")
                elif isinstance(cve_ids, str):
                    references.append(f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_ids}")
        
        # Add CWE references
        if "classification" in info and "cwe-id" in info["classification"]:
            cwe_ids = info["classification"]["cwe-id"]
            if isinstance(cwe_ids, list):
                for cwe_id in cwe_ids:
                    references.append(f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html")
            elif isinstance(cwe_ids, str):
                references.append(f"https://cwe.mitre.org/data/definitions/{cwe_ids.replace('CWE-', '')}.html")
        
        # Add template ID as reference
        template_id = result.get("template-id", "")
        if template_id:
            references.append(f"Nuclei Template: {template_id}")
        
        return references
    
    async def update_templates(self) -> bool:
        """Update Nuclei templates"""
        try:
            cmd = [self.nuclei_path, "-update-templates"]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                self.logger.info("Nuclei templates updated successfully")
                return True
            else:
                self.logger.error(f"Failed to update Nuclei templates: {stderr.decode()}")
                return False
                
        except Exception as e:
            self.logger.error(f"Template update error: {e}")
            return False
    
    def get_engine_info(self) -> Dict[str, Any]:
        """Get engine information"""
        return {
            "name": "Nuclei",
            "type": self.engine_type.value,
            "version": self._get_nuclei_version(),
            "description": "Fast and customizable vulnerability scanner based on simple YAML templates",
            "supported_protocols": ["HTTP", "HTTPS"],
            "template_count": self._get_template_count(),
            "capabilities": [
                "CVE detection",
                "OWASP Top 10 testing",
                "Configuration issues",
                "Exposed panels/services",
                "Technology detection",
                "Custom template support"
            ]
        }
    
    def _get_nuclei_version(self) -> str:
        """Get Nuclei version"""
        try:
            result = subprocess.run(
                [self.nuclei_path, "-version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                return result.stdout.strip()
        except:
            pass
        
        return "unknown"
    
    def _get_template_count(self) -> int:
        """Get number of available templates"""
        try:
            # Run nuclei with list templates option
            result = subprocess.run(
                [self.nuclei_path, "-tl"],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                # Count lines in output
                return len(result.stdout.strip().split('\n'))
        except:
            pass
        
        return 0
      