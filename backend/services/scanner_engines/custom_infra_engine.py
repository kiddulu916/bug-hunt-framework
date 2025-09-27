"""
Custom Infrastructure Scanner Engine
Network infrastructure and service vulnerability detection
"""

import asyncio
import socket
import ssl
import subprocess
import logging
import json
import re
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse
import aiohttp
import concurrent.futures
from datetime import datetime, timedelta

from services.vulnerability_scanner import VulnerabilityFinding, ScanEngineType, VulnSeverity


class CustomInfraEngine:
    """Custom infrastructure vulnerability scanner"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.engine_type = ScanEngineType.CUSTOM_INFRA
        
        # Common vulnerable ports and services
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 6379
        ]
        
        # SSL/TLS vulnerability patterns
        self.ssl_vulnerabilities = {
            'sslv2': {'severity': VulnSeverity.HIGH, 'description': 'SSLv2 is enabled'},
            'sslv3': {'severity': VulnSeverity.HIGH, 'description': 'SSLv3 is enabled (POODLE)'},
            'rc4': {'severity': VulnSeverity.MEDIUM, 'description': 'RC4 cipher suites enabled'},
            'weak_dh': {'severity': VulnSeverity.MEDIUM, 'description': 'Weak Diffie-Hellman parameters'},
            'expired_cert': {'severity': VulnSeverity.MEDIUM, 'description': 'SSL certificate expired'},
            'self_signed': {'severity': VulnSeverity.LOW, 'description': 'Self-signed SSL certificate'},
            'weak_signature': {'severity': VulnSeverity.MEDIUM, 'description': 'Weak signature algorithm (MD5/SHA1)'}
        }
        
        # Service fingerprint patterns
        self.service_patterns = {
            'ssh': {
                'port': 22,
                'banner_regex': r'SSH-(\d+\.\d+)',
                'vulnerabilities': [
                    {'pattern': r'SSH-1\.', 'vuln': 'ssh_v1', 'severity': VulnSeverity.HIGH},
                    {'pattern': r'OpenSSH_[3-6]\.', 'vuln': 'openssh_old', 'severity': VulnSeverity.MEDIUM}
                ]
            },
            'ftp': {
                'port': 21,
                'banner_regex': r'220.*FTP',
                'vulnerabilities': [
                    {'pattern': r'vsftpd 2\.3\.4', 'vuln': 'vsftpd_backdoor', 'severity': VulnSeverity.CRITICAL},
                    {'pattern': r'ProFTPD 1\.3\.3[a-c]', 'vuln': 'proftpd_backdoor', 'severity': VulnSeverity.CRITICAL}
                ]
            },
            'telnet': {
                'port': 23,
                'banner_regex': r'.*login:',
                'vulnerabilities': [
                    {'pattern': r'.*', 'vuln': 'telnet_enabled', 'severity': VulnSeverity.HIGH}
                ]
            },
            'smtp': {
                'port': 25,
                'banner_regex': r'220.*SMTP',
                'vulnerabilities': [
                    {'pattern': r'Postfix', 'vuln': 'smtp_open_relay', 'severity': VulnSeverity.MEDIUM}
                ]
            }
        }
        
        # Network discovery timeouts
        self.connect_timeout = 3
        self.read_timeout = 5
    
    async def scan_targets(self, targets: List[Dict[str, Any]], scan_config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Scan infrastructure targets for vulnerabilities"""
        findings = []
        
        try:
            # Extract hosts from targets
            hosts = self._extract_hosts(targets)
            
            # Perform network discovery
            if scan_config.get('network_discovery', True):
                discovery_results = await self._network_discovery(hosts, scan_config)
                findings.extend(discovery_results)
            
            # Port scanning
            if scan_config.get('port_scanning', True):
                port_scan_results = await self._port_scanning(hosts, scan_config)
                findings.extend(port_scan_results)
            
            # Service detection and vulnerability testing
            if scan_config.get('service_detection', True):
                service_results = await self._service_detection(hosts, scan_config)
                findings.extend(service_results)
            
            # SSL/TLS testing
            if scan_config.get('ssl_testing', True):
                ssl_results = await self._ssl_tls_testing(hosts, scan_config)
                findings.extend(ssl_results)
            
            # DNS security testing
            if scan_config.get('dns_testing', True):
                dns_results = await self._dns_security_testing(hosts, scan_config)
                findings.extend(dns_results)
            
        except Exception as e:
            self.logger.error(f"Infrastructure scanning error: {str(e)}")
            
        return findings
    
    def _extract_hosts(self, targets: List[Dict[str, Any]]) -> List[str]:
        """Extract hostnames and IPs from target URLs"""
        hosts = set()
        
        for target in targets:
            url = target.get('url', '')
            if url:
                parsed = urlparse(url)
                if parsed.hostname:
                    hosts.add(parsed.hostname)
        
        return list(hosts)
    
    async def _network_discovery(self, hosts: List[str], config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Perform network discovery and basic reconnaissance"""
        findings = []
        
        for host in hosts:
            try:
                # Check if host is responsive
                if await self._is_host_alive(host):
                    # Resolve hostname to IP
                    ip_address = await self._resolve_hostname(host)
                    
                    if ip_address:
                        # Check for private IP exposure
                        if self._is_private_ip(ip_address):
                            finding = VulnerabilityFinding(
                                vulnerability_id=f"private_ip_{host}",
                                name="Private IP Address Exposed",
                                description=f"Host {host} resolves to private IP {ip_address}",
                                severity=VulnSeverity.INFO,
                                confidence=1.0,
                                affected_url=f"http://{host}",
                                affected_parameter=None,
                                http_method="N/A",
                                payload=None,
                                evidence={"ip_address": ip_address, "hostname": host},
                                remediation="Ensure private IPs are not exposed in public DNS",
                                references=["https://tools.ietf.org/html/rfc1918"],
                                tags=["network", "information_disclosure"],
                                discovered_by=self.engine_type.value,
                                scan_engine=self.engine_type,
                                template_id="private_ip_exposure"
                            )
                            findings.append(finding)
            
            except Exception as e:
                self.logger.error(f"Network discovery error for {host}: {str(e)}")
        
        return findings
    
    async def _port_scanning(self, hosts: List[str], config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Perform port scanning on target hosts"""
        findings = []
        max_concurrent = config.get('max_concurrent_ports', 50)
        
        for host in hosts:
            try:
                # Determine port range
                if config.get('aggressive_scan', False):
                    port_range = range(1, 65536)
                else:
                    port_range = self.common_ports
                
                # Scan ports with concurrency limit
                semaphore = asyncio.Semaphore(max_concurrent)
                tasks = [self._scan_port(host, port, semaphore) for port in port_range]
                
                port_results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Process open ports
                open_ports = [result for result in port_results 
                             if isinstance(result, dict) and result.get('open')]
                
                # Check for dangerous open ports
                for port_info in open_ports:
                    port = port_info['port']
                    
                    # Flag dangerous services
                    if port in [23, 135, 139, 445, 1433, 1521, 3389]:
                        severity = VulnSeverity.HIGH if port in [23, 135, 3389] else VulnSeverity.MEDIUM
                        
                        finding = VulnerabilityFinding(
                            vulnerability_id=f"dangerous_port_{host}_{port}",
                            name=f"Dangerous Service Port Open ({port})",
                            description=f"Port {port} is open on {host}, potentially exposing a dangerous service",
                            severity=severity,
                            confidence=0.8,
                            affected_url=f"tcp://{host}:{port}",
                            affected_parameter=None,
                            http_method="N/A",
                            payload=None,
                            evidence={"port": port, "service": self._get_service_name(port)},
                            remediation=f"Close port {port} if not required, or restrict access",
                            references=["https://www.iana.org/assignments/service-names-port-numbers/"],
                            tags=["network", "port_scan", "dangerous_service"],
                            discovered_by=self.engine_type.value,
                            scan_engine=self.engine_type,
                            template_id=f"dangerous_port_{port}"
                        )
                        findings.append(finding)
            
            except Exception as e:
                self.logger.error(f"Port scanning error for {host}: {str(e)}")
        
        return findings
    
    async def _scan_port(self, host: str, port: int, semaphore: asyncio.Semaphore) -> Dict[str, Any]:
        """Scan a single port"""
        async with semaphore:
            try:
                # Attempt connection
                future = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(future, timeout=self.connect_timeout)
                
                # Port is open
                writer.close()
                await writer.wait_closed()
                
                return {
                    'host': host,
                    'port': port,
                    'open': True,
                    'service': self._get_service_name(port)
                }
                
            except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                return {'host': host, 'port': port, 'open': False}
            except Exception as e:
                self.logger.debug(f"Port scan error {host}:{port}: {str(e)}")
                return {'host': host, 'port': port, 'open': False}
    
    async def _service_detection(self, hosts: List[str], config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Detect services and test for known vulnerabilities"""
        findings = []
        
        for host in hosts:
            for service_name, service_info in self.service_patterns.items():
                try:
                    port = service_info['port']
                    
                    # Check if port is open
                    if await self._is_port_open(host, port):
                        # Grab banner
                        banner = await self._grab_banner(host, port)
                        
                        if banner and re.search(service_info['banner_regex'], banner, re.IGNORECASE):
                            # Service detected, check for vulnerabilities
                            for vuln_check in service_info['vulnerabilities']:
                                if re.search(vuln_check['pattern'], banner, re.IGNORECASE):
                                    finding = VulnerabilityFinding(
                                        vulnerability_id=f"{vuln_check['vuln']}_{host}_{port}",
                                        name=f"Vulnerable {service_name.upper()} Service",
                                        description=f"Vulnerable {service_name} service detected on {host}:{port}",
                                        severity=vuln_check['severity'],
                                        confidence=0.9,
                                        affected_url=f"{service_name}://{host}:{port}",
                                        affected_parameter=None,
                                        http_method="N/A",
                                        payload=None,
                                        evidence={"banner": banner, "service": service_name},
                                        remediation=f"Update {service_name} service to latest version",
                                        references=[],
                                        tags=["network", "service_vulnerability", service_name],
                                        discovered_by=self.engine_type.value,
                                        scan_engine=self.engine_type,
                                        template_id=vuln_check['vuln']
                                    )
                                    findings.append(finding)
                
                except Exception as e:
                    self.logger.error(f"Service detection error for {host}:{service_info['port']}: {str(e)}")
        
        return findings
    
    async def _ssl_tls_testing(self, hosts: List[str], config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Test SSL/TLS configuration for vulnerabilities"""
        findings = []
        
        for host in hosts:
            try:
                # Test HTTPS port
                if await self._is_port_open(host, 443):
                    ssl_findings = await self._test_ssl_configuration(host, 443)
                    findings.extend(ssl_findings)
                
                # Test other SSL ports if aggressive scanning
                if config.get('aggressive_scan', False):
                    ssl_ports = [993, 995, 465, 587, 636]
                    for port in ssl_ports:
                        if await self._is_port_open(host, port):
                            ssl_findings = await self._test_ssl_configuration(host, port)
                            findings.extend(ssl_findings)
            
            except Exception as e:
                self.logger.error(f"SSL testing error for {host}: {str(e)}")
        
        return findings
    
    async def _test_ssl_configuration(self, host: str, port: int) -> List[VulnerabilityFinding]:
        """Test SSL/TLS configuration for a specific host:port"""
        findings = []
        
        try:
            # Create SSL context for testing
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate info
            with socket.create_connection((host, port), timeout=self.connect_timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    # Check certificate validity
                    if cert:
                        # Check expiration
                        not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                        if not_after < datetime.now():
                            finding = VulnerabilityFinding(
                                vulnerability_id=f"expired_cert_{host}_{port}",
                                name="Expired SSL Certificate",
                                description=f"SSL certificate on {host}:{port} has expired",
                                severity=VulnSeverity.MEDIUM,
                                confidence=1.0,
                                affected_url=f"https://{host}:{port}",
                                affected_parameter=None,
                                http_method="N/A",
                                payload=None,
                                evidence={"expiry_date": cert['notAfter'], "certificate": cert},
                                remediation="Renew SSL certificate",
                                references=["https://tools.ietf.org/html/rfc5280"],
                                tags=["ssl", "certificate", "expired"],
                                discovered_by=self.engine_type.value,
                                scan_engine=self.engine_type,
                                template_id="expired_ssl_cert"
                            )
                            findings.append(finding)
                        
                        # Check self-signed
                        if cert.get('issuer') == cert.get('subject'):
                            finding = VulnerabilityFinding(
                                vulnerability_id=f"self_signed_cert_{host}_{port}",
                                name="Self-Signed SSL Certificate",
                                description=f"Self-signed SSL certificate detected on {host}:{port}",
                                severity=VulnSeverity.LOW,
                                confidence=1.0,
                                affected_url=f"https://{host}:{port}",
                                affected_parameter=None,
                                http_method="N/A",
                                payload=None,
                                evidence={"certificate": cert},
                                remediation="Use certificate from trusted CA",
                                references=["https://tools.ietf.org/html/rfc5280"],
                                tags=["ssl", "certificate", "self_signed"],
                                discovered_by=self.engine_type.value,
                                scan_engine=self.engine_type,
                                template_id="self_signed_cert"
                            )
                            findings.append(finding)
                    
                    # Check cipher strength
                    if cipher:
                        cipher_name = cipher[0]
                        
                        # Check for weak ciphers
                        if 'RC4' in cipher_name:
                            finding = VulnerabilityFinding(
                                vulnerability_id=f"weak_cipher_{host}_{port}",
                                name="Weak SSL Cipher Suite",
                                description=f"Weak cipher suite {cipher_name} in use on {host}:{port}",
                                severity=VulnSeverity.MEDIUM,
                                confidence=1.0,
                                affected_url=f"https://{host}:{port}",
                                affected_parameter=None,
                                http_method="N/A",
                                payload=None,
                                evidence={"cipher": cipher_name, "full_cipher": cipher},
                                remediation="Disable weak cipher suites in SSL configuration",
                                references=["https://tools.ietf.org/html/rfc7465"],
                                tags=["ssl", "cipher", "weak_crypto"],
                                discovered_by=self.engine_type.value,
                                scan_engine=self.engine_type,
                                template_id="weak_ssl_cipher"
                            )
                            findings.append(finding)
        
        except Exception as e:
            self.logger.debug(f"SSL test error for {host}:{port}: {str(e)}")
        
        return findings
    
    async def _dns_security_testing(self, hosts: List[str], config: Dict[str, Any]) -> List[VulnerabilityFinding]:
        """Test DNS security configuration"""
        findings = []
        
        for host in hosts:
            try:
                # Test DNS cache poisoning
                if await self._test_dns_cache_poisoning(host):
                    finding = VulnerabilityFinding(
                        vulnerability_id=f"dns_cache_poisoning_{host}",
                        name="DNS Cache Poisoning Vulnerability",
                        description=f"DNS server for {host} may be vulnerable to cache poisoning",
                        severity=VulnSeverity.HIGH,
                        confidence=0.7,
                        affected_url=f"dns://{host}",
                        affected_parameter=None,
                        http_method="N/A",
                        payload=None,
                        evidence={"dns_server": host},
                        remediation="Implement DNS security measures (DNSSEC)",
                        references=["https://tools.ietf.org/html/rfc4033"],
                        tags=["dns", "cache_poisoning"],
                        discovered_by=self.engine_type.value,
                        scan_engine=self.engine_type,
                        template_id="dns_cache_poisoning"
                    )
                    findings.append(finding)
                
                # Test for DNS zone transfer
                if await self._test_dns_zone_transfer(host):
                    finding = VulnerabilityFinding(
                        vulnerability_id=f"dns_zone_transfer_{host}",
                        name="DNS Zone Transfer Allowed",
                        description=f"DNS zone transfer is allowed for {host}",
                        severity=VulnSeverity.MEDIUM,
                        confidence=0.9,
                        affected_url=f"dns://{host}",
                        affected_parameter=None,
                        http_method="N/A",
                        payload=None,
                        evidence={"dns_server": host},
                        remediation="Restrict DNS zone transfers to authorized servers only",
                        references=["https://tools.ietf.org/html/rfc1034"],
                        tags=["dns", "zone_transfer", "information_disclosure"],
                        discovered_by=self.engine_type.value,
                        scan_engine=self.engine_type,
                        template_id="dns_zone_transfer"
                    )
                    findings.append(finding)
            
            except Exception as e:
                self.logger.error(f"DNS testing error for {host}: {str(e)}")
        
        return findings
    
    # Helper methods
    
    async def _is_host_alive(self, host: str) -> bool:
        """Check if host is alive"""
        try:
            # Try to resolve hostname
            await asyncio.get_event_loop().getaddrinfo(host, None)
            return True
        except:
            return False
    
    async def _resolve_hostname(self, host: str) -> Optional[str]:
        """Resolve hostname to IP address"""
        try:
            result = await asyncio.get_event_loop().getaddrinfo(host, None)
            return result[0][4][0]
        except:
            return None
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private"""
        try:
            import ipaddress
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj.is_private
        except:
            return False
    
    async def _is_port_open(self, host: str, port: int) -> bool:
        """Check if port is open"""
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.connect_timeout)
            writer.close()
            await writer.wait_closed()
            return True
        except:
            return False
    
    async def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """Grab service banner"""
        try:
            future = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(future, timeout=self.connect_timeout)
            
            # Try to read banner
            banner = await asyncio.wait_for(reader.read(1024), timeout=self.read_timeout)
            
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore').strip()
        except:
            return None
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for port"""
        service_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 143: 'imap', 443: 'https', 993: 'imaps',
            995: 'pop3s', 3306: 'mysql', 3389: 'rdp', 5432: 'postgresql'
        }
        return service_map.get(port, 'unknown')
    
    async def _test_dns_cache_poisoning(self, host: str) -> bool:
        """Test for DNS cache poisoning vulnerability"""
        # Simplified test - would need more sophisticated implementation
        try:
            # Check if DNS server accepts queries from unauthorized sources
            return False  # Placeholder
        except:
            return False
    
    async def _test_dns_zone_transfer(self, host: str) -> bool:
        """Test for DNS zone transfer vulnerability"""
        try:
            # Use dig or nslookup to test zone transfer
            proc = await asyncio.create_subprocess_exec(
                'dig', 'axfr', f'@{host}', host,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            
            # Check if zone transfer was successful
            if proc.returncode == 0 and b'XFR size' in stdout:
                return True
            
        except Exception as e:
            self.logger.debug(f"Zone transfer test error: {str(e)}")
        
        return False
      