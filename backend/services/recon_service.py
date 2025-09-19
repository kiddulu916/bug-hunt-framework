"""
Reconnaissance Service for Bug Bounty Automation Platform
Handles passive and active reconnaissance using various tools and techniques
"""

import asyncio
import json
import logging
import re
import subprocess
import tempfile
import os
import socket
import ssl
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any, Set
from dataclasses import dataclass
from enum import Enum
from urllib.parse import urlparse, urljoin
import ipaddress

import aiohttp
import requests
import dns.resolver
import dns.reversename
from celery import shared_task
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_

from backend.models import (
    Target, ScanSession, ReconResult, ToolExecution,
    ScanStatus, ToolStatus
)
from backend.core.database import get_db_session
from backend.services.notification_service import NotificationService


class ReconType(Enum):
    SUBDOMAIN = "subdomain"
    ENDPOINT = "endpoint" 
    SERVICE = "service"
    TECHNOLOGY = "technology"
    EMAIL = "email"
    SOCIAL_MEDIA = "social_media"
    CERTIFICATE = "certificate"
    DNS_RECORD = "dns_record"
    IP_ADDRESS = "ip_address"
    PORT = "port"


class ReconMethod(Enum):
    DNS_ENUMERATION = "dns_enumeration"
    CERTIFICATE_TRANSPARENCY = "certificate_transparency"
    SEARCH_ENGINE = "search_engine"
    WEB_CRAWLING = "web_crawling"
    PORT_SCANNING = "port_scanning"
    SERVICE_DETECTION = "service_detection"
    TECHNOLOGY_DETECTION = "technology_detection"
    OSINT = "osint"
    BRUTE_FORCE = "brute_force"
    API_DISCOVERY = "api_discovery"


@dataclass
class ReconConfig:
    """Configuration for reconnaissance operations"""
    passive_only: bool = False
    max_subdomains: int = 1000
    max_endpoints: int = 5000
    port_scan_top_ports: int = 1000
    enable_service_detection: bool = True
    enable_technology_detection: bool = True
    enable_certificate_transparency: bool = True
    enable_search_engines: bool = True
    enable_web_crawling: bool = True
    crawl_depth: int = 3
    wordlist_size: str = "medium"  # small, medium, large
    timeout_seconds: int = 30


@dataclass
class ReconResult:
    """Result from a reconnaissance operation"""
    result_type: ReconType
    discovered_asset: str
    confidence_score: float
    discovery_method: ReconMethod
    discovered_by_tool: str
    additional_data: Dict[str, Any]
    ip_address: Optional[str] = None
    port: Optional[int] = None
    service_name: Optional[str] = None
    service_version: Optional[str] = None
    technologies: List[str] = None


class PassiveReconEngine:
    """Engine for passive reconnaissance techniques"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
    async def subdomain_enumeration_passive(self, target: Target) -> List[ReconResult]:
        """Passive subdomain enumeration using multiple sources"""
        results = []
        domain = self._extract_domain(target.main_url)
        
        # Certificate Transparency logs
        ct_subdomains = await self._certificate_transparency_search(domain)
        for subdomain in ct_subdomains:
            results.append(ReconResult(
                result_type=ReconType.SUBDOMAIN,
                discovered_asset=subdomain,
                confidence_score=0.9,
                discovery_method=ReconMethod.CERTIFICATE_TRANSPARENCY,
                discovered_by_tool="crt.sh",
                additional_data={"source": "certificate_transparency"}
            ))
        
        # DNS enumeration using common records
        dns_subdomains = await self._dns_passive_enumeration(domain)
        for subdomain in dns_subdomains:
            results.append(ReconResult(
                result_type=ReconType.SUBDOMAIN,
                discovered_asset=subdomain,
                confidence_score=0.8,
                discovery_method=ReconMethod.DNS_ENUMERATION,
                discovered_by_tool="dns_resolver",
                additional_data={"source": "dns_records"}
            ))
        
        # Search engine dorking
        search_subdomains = await self._search_engine_subdomain_discovery(domain)
        for subdomain in search_subdomains:
            results.append(ReconResult(
                result_type=ReconType.SUBDOMAIN,
                discovered_asset=subdomain,
                confidence_score=0.7,
                discovery_method=ReconMethod.SEARCH_ENGINE,
                discovered_by_tool="search_engines",
                additional_data={"source": "search_engine_dorking"}
            ))
        
        return results
    
    async def _certificate_transparency_search(self, domain: str) -> Set[str]:
        """Search certificate transparency logs for subdomains"""
        subdomains = set()
        
        try:
            # crt.sh API
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{domain}&output=json"
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for cert in data:
                            name_value = cert.get('name_value', '')
                            for line in name_value.split('\n'):
                                subdomain = line.strip()
                                if subdomain and self._is_valid_subdomain(subdomain, domain):
                                    subdomains.add(subdomain)
        except Exception as e:
            self.logger.error(f"Certificate transparency search failed: {e}")
        
        return subdomains
    
    async def _dns_passive_enumeration(self, domain: str) -> Set[str]:
        """Passive DNS enumeration using common record types"""
        subdomains = set()
        
        # Common DNS record types to check
        record_types = ['A', 'AAAA', 'CNAME', 'MX', 'NS', 'TXT', 'SRV']
        
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 10
            
            for record_type in record_types:
                try:
                    answers = resolver.resolve(domain, record_type)
                    for answer in answers:
                        # Extract potential subdomains from DNS responses
                        answer_str = str(answer).rstrip('.')
                        if self._is_valid_subdomain(answer_str, domain):
                            subdomains.add(answer_str)
                except dns.resolver.NXDOMAIN:
                    continue
                except Exception as e:
                    self.logger.debug(f"DNS query failed for {domain} {record_type}: {e}")
                    continue
        except Exception as e:
            self.logger.error(f"DNS enumeration failed: {e}")
        
        return subdomains
    
    async def _search_engine_subdomain_discovery(self, domain: str) -> Set[str]:
        """Discover subdomains using search engine dorking"""
        subdomains = set()
        
        # Google dorking queries
        dork_queries = [
            f"site:{domain}",
            f"site:*.{domain}",
            f"inurl:{domain}",
            f"intitle:\"{domain}\""
        ]
        
        try:
            async with aiohttp.ClientSession() as session:
                for query in dork_queries:
                    # Note: In production, you'd want to use proper search APIs
                    # This is a simplified example
                    search_url = f"https://www.google.com/search?q={query}"
                    try:
                        async with session.get(search_url, timeout=10) as response:
                            if response.status == 200:
                                content = await response.text()
                                # Extract potential subdomains from search results
                                subdomain_pattern = rf'\b([a-zA-Z0-9.-]+\.{re.escape(domain)})\b'
                                matches = re.findall(subdomain_pattern, content)
                                for match in matches:
                                    if self._is_valid_subdomain(match, domain):
                                        subdomains.add(match)
                    except Exception as e:
                        self.logger.debug(f"Search engine query failed: {e}")
                        continue
                    
                    # Rate limiting
                    await asyncio.sleep(2)
        except Exception as e:
            self.logger.error(f"Search engine discovery failed: {e}")
        
        return subdomains
    
    async def osint_email_discovery(self, target: Target) -> List[ReconResult]:
        """Discover email addresses through OSINT"""
        results = []
        domain = self._extract_domain(target.main_url)
        
        # Common email patterns
        email_patterns = [
            "admin", "support", "info", "contact", "sales", "marketing",
            "security", "webmaster", "noreply", "hello", "help"
        ]
        
        for pattern in email_patterns:
            email = f"{pattern}@{domain}"
            results.append(ReconResult(
                result_type=ReconType.EMAIL,
                discovered_asset=email,
                confidence_score=0.5,  # Low confidence for pattern-based
                discovery_method=ReconMethod.OSINT,
                discovered_by_tool="email_pattern_generator",
                additional_data={"pattern": pattern, "verification_needed": True}
            ))
        
        return results
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path
        except Exception:
            return url
    
    def _is_valid_subdomain(self, subdomain: str, parent_domain: str) -> bool:
        """Validate if a subdomain is valid and belongs to parent domain"""
        if not subdomain or not parent_domain:
            return False
        
        # Remove protocol if present
        subdomain = subdomain.replace('http://', '').replace('https://', '')
        
        # Must end with the parent domain
        if not subdomain.endswith(parent_domain):
            return False
        
        # Must be a valid hostname format
        if not re.match(r'^[a-zA-Z0-9.-]+$', subdomain):
            return False
        
        # Avoid wildcards and invalid patterns
        if '*' in subdomain or '..' in subdomain:
            return False
        
        return True


class ActiveReconEngine:
    """Engine for active reconnaissance techniques"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def subdomain_enumeration_active(self, target: Target, 
                                         config: ReconConfig) -> List[ReconResult]:
        """Active subdomain enumeration using brute force and tools"""
        results = []
        domain = self._extract_domain(target.main_url)
        
        # Tool-based enumeration
        tool_results = await self._run_subdomain_tools(domain, config)
        results.extend(tool_results)
        
        # DNS brute force with wordlists
        if not config.passive_only:
            brute_results = await self._dns_brute_force(domain, config)
            results.extend(brute_results)
        
        return results
    
    async def port_scanning(self, targets: List[str], config: ReconConfig) -> List[ReconResult]:
        """Perform port scanning on discovered assets"""
        results = []
        
        for target_ip in targets:
            port_results = await self._scan_ports(target_ip, config)
            results.extend(port_results)
        
        return results
    
    async def service_detection(self, target_ip: str, port: int) -> Optional[ReconResult]:
        """Detect service running on specific port"""
        try:
            # Banner grabbing
            banner = await self._grab_banner(target_ip, port)
            
            if banner:
                service_info = self._parse_service_banner(banner)
                
                return ReconResult(
                    result_type=ReconType.SERVICE,
                    discovered_asset=f"{target_ip}:{port}",
                    confidence_score=0.8,
                    discovery_method=ReconMethod.SERVICE_DETECTION,
                    discovered_by_tool="banner_grabber",
                    ip_address=target_ip,
                    port=port,
                    service_name=service_info.get('service'),
                    service_version=service_info.get('version'),
                    additional_data={"banner": banner, "parsed_info": service_info}
                )
        except Exception as e:
            self.logger.debug(f"Service detection failed for {target_ip}:{port}: {e}")
        
        return None
    
    async def web_technology_detection(self, url: str) -> List[ReconResult]:
        """Detect web technologies used by target"""
        results = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        content = await response.text()
                        headers = dict(response.headers)
                        
                        # Detect technologies
                        technologies = self._detect_technologies(content, headers)
                        
                        for tech in technologies:
                            results.append(ReconResult(
                                result_type=ReconType.TECHNOLOGY,
                                discovered_asset=url,
                                confidence_score=tech['confidence'],
                                discovery_method=ReconMethod.TECHNOLOGY_DETECTION,
                                discovered_by_tool="web_analyzer",
                                technologies=[tech['name']],
                                additional_data={
                                    "version": tech.get('version'),
                                    "detection_method": tech['method'],
                                    "evidence": tech.get('evidence')
                                }
                            ))
        except Exception as e:
            self.logger.error(f"Technology detection failed for {url}: {e}")
        
        return results
    
    async def web_crawling(self, start_url: str, config: ReconConfig) -> List[ReconResult]:
        """Crawl website to discover endpoints"""
        results = []
        discovered_urls = set()
        to_crawl = {start_url}
        crawled = set()
        depth = 0
        
        while to_crawl and depth < config.crawl_depth:
            current_batch = to_crawl.copy()
            to_crawl.clear()
            depth += 1
            
            for url in current_batch:
                if url in crawled or len(discovered_urls) >= config.max_endpoints:
                    continue
                
                crawled.add(url)
                
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(url, timeout=config.timeout_seconds) as response:
                            if response.status == 200:
                                content = await response.text()
                                
                                # Extract links
                                new_urls = self._extract_links(content, url)
                                
                                for new_url in new_urls:
                                    if new_url not in discovered_urls and self._is_in_scope(new_url, start_url):
                                        discovered_urls.add(new_url)
                                        to_crawl.add(new_url)
                                        
                                        results.append(ReconResult(
                                            result_type=ReconType.ENDPOINT,
                                            discovered_asset=new_url,
                                            confidence_score=0.9,
                                            discovery_method=ReconMethod.WEB_CRAWLING,
                                            discovered_by_tool="web_crawler",
                                            additional_data={
                                                "parent_url": url,
                                                "depth": depth,
                                                "response_code": response.status
                                            }
                                        ))
                except Exception as e:
                    self.logger.debug(f"Crawling failed for {url}: {e}")
                    continue
                
                # Rate limiting
                await asyncio.sleep(0.5)
        
        return results
    
    async def api_discovery(self, base_url: str) -> List[ReconResult]:
        """Discover API endpoints"""
        results = []
        
        # Common API paths
        api_paths = [
            "/api", "/api/v1", "/api/v2", "/api/v3",
            "/rest", "/restapi", "/graphql",
            "/swagger", "/swagger.json", "/swagger.yaml",
            "/openapi.json", "/api-docs",
            "/docs", "/documentation"
        ]
        
        for path in api_paths:
            api_url = urljoin(base_url, path)
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(api_url, timeout=15) as response:
                        if response.status in [200, 401, 403]:  # API exists but may require auth
                            content_type = response.headers.get('content-type', '')
                            
                            results.append(ReconResult(
                                result_type=ReconType.ENDPOINT,
                                discovered_asset=api_url,
                                confidence_score=0.8,
                                discovery_method=ReconMethod.API_DISCOVERY,
                                discovered_by_tool="api_discovery",
                                additional_data={
                                    "response_code": response.status,
                                    "content_type": content_type,
                                    "api_type": self._detect_api_type(api_url, content_type)
                                }
                            ))
            except Exception as e:
                self.logger.debug(f"API discovery failed for {api_url}: {e}")
                continue
        
        return results
    
    async def _run_subdomain_tools(self, domain: str, config: ReconConfig) -> List[ReconResult]:
        """Run external subdomain enumeration tools"""
        results = []
        
        # Subfinder
        subfinder_results = await self._run_subfinder(domain)
        results.extend(subfinder_results)
        
        # Amass
        amass_results = await self._run_amass(domain, config.passive_only)
        results.extend(amass_results)
        
        # Assetfinder
        assetfinder_results = await self._run_assetfinder(domain)
        results.extend(assetfinder_results)
        
        return results
    
    async def _run_subfinder(self, domain: str) -> List[ReconResult]:
        """Run subfinder tool"""
        results = []
        
        try:
            cmd = ['subfinder', '-d', domain, '-silent', '-o', '/dev/stdout']
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = stdout.decode().strip().split('\n')
                for subdomain in subdomains:
                    if subdomain.strip():
                        results.append(ReconResult(
                            result_type=ReconType.SUBDOMAIN,
                            discovered_asset=subdomain.strip(),
                            confidence_score=0.9,
                            discovery_method=ReconMethod.DNS_ENUMERATION,
                            discovered_by_tool="subfinder",
                            additional_data={"source": "subfinder"}
                        ))
        except Exception as e:
            self.logger.error(f"Subfinder execution failed: {e}")
        
        return results
    
    async def _run_amass(self, domain: str, passive_only: bool) -> List[ReconResult]:
        """Run amass tool"""
        results = []
        
        try:
            cmd = ['amass', 'enum', '-d', domain, '-silent']
            if passive_only:
                cmd.append('-passive')
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = stdout.decode().strip().split('\n')
                for subdomain in subdomains:
                    if subdomain.strip():
                        results.append(ReconResult(
                            result_type=ReconType.SUBDOMAIN,
                            discovered_asset=subdomain.strip(),
                            confidence_score=0.95,
                            discovery_method=ReconMethod.DNS_ENUMERATION,
                            discovered_by_tool="amass",
                            additional_data={"source": "amass", "passive": passive_only}
                        ))
        except Exception as e:
            self.logger.error(f"Amass execution failed: {e}")
        
        return results
    
    async def _run_assetfinder(self, domain: str) -> List[ReconResult]:
        """Run assetfinder tool"""
        results = []
        
        try:
            cmd = ['assetfinder', '--subs-only', domain]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode == 0:
                subdomains = stdout.decode().strip().split('\n')
                for subdomain in subdomains:
                    if subdomain.strip():
                        results.append(ReconResult(
                            result_type=ReconType.SUBDOMAIN,
                            discovered_asset=subdomain.strip(),
                            confidence_score=0.85,
                            discovery_method=ReconMethod.DNS_ENUMERATION,
                            discovered_by_tool="assetfinder",
                            additional_data={"source": "assetfinder"}
                        ))
        except Exception as e:
            self.logger.error(f"Assetfinder execution failed: {e}")
        
        return results
    
    async def _dns_brute_force(self, domain: str, config: ReconConfig) -> List[ReconResult]:
        """DNS brute force enumeration"""
        results = []
        
        # Get wordlist based on config
        wordlist = self._get_subdomain_wordlist(config.wordlist_size)
        
        # Limit concurrent DNS queries
        semaphore = asyncio.Semaphore(50)
        
        async def check_subdomain(subdomain):
            async with semaphore:
                full_domain = f"{subdomain}.{domain}"
                try:
                    resolver = dns.resolver.Resolver()
                    resolver.timeout = 5
                    answers = resolver.resolve(full_domain, 'A')
                    
                    if answers:
                        ip_address = str(answers[0])
                        return ReconResult(
                            result_type=ReconType.SUBDOMAIN,
                            discovered_asset=full_domain,
                            confidence_score=1.0,
                            discovery_method=ReconMethod.BRUTE_FORCE,
                            discovered_by_tool="dns_brute_force",
                            ip_address=ip_address,
                            additional_data={"brute_force": True, "resolved_ip": ip_address}
                        )
                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout):
                    return None
                except Exception as e:
                    self.logger.debug(f"DNS brute force failed for {full_domain}: {e}")
                    return None
        
        # Process wordlist
        tasks = []
        for subdomain in wordlist:
            if len(results) >= config.max_subdomains:
                break
            tasks.append(check_subdomain(subdomain))
        
        # Execute DNS checks
        dns_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in dns_results:
            if isinstance(result, ReconResult):
                results.append(result)
        
        return results
    
    def _get_subdomain_wordlist(self, size: str) -> List[str]:
        """Get subdomain wordlist based on size"""
        wordlists = {
            "small": [
                "www", "mail", "ftp", "admin", "test", "dev", "staging", "api",
                "app", "mobile", "secure", "vpn", "remote", "support", "help",
                "blog", "shop", "store", "news", "forum", "portal", "gateway"
            ],
            "medium": [
                # Small list plus more
                "www", "mail", "ftp", "admin", "test", "dev", "staging", "api",
                "app", "mobile", "secure", "vpn", "remote", "support", "help",
                "blog", "shop", "store", "news", "forum", "portal", "gateway",
                "cdn", "static", "assets", "media", "images", "files", "docs",
                "download", "uploads", "backup", "old", "new", "beta", "alpha",
                "demo", "sandbox", "qa", "uat", "prod", "production", "live",
                "internal", "intranet", "extranet", "public", "private", "secret"
            ]
        }
        
        if size == "large":
            # In production, load from file
            return wordlists["medium"] + [f"sub{i}" for i in range(100)]
        
        return wordlists.get(size, wordlists["medium"])
    
    async def _scan_ports(self, target_ip: str, config: ReconConfig) -> List[ReconResult]:
        """Scan ports on target IP"""
        results = []
        
        # Common ports to scan
        if config.port_scan_top_ports <= 100:
            ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        else:
            # Use nmap's top 1000 ports (simplified subset)
            ports = list(range(1, min(1001, config.port_scan_top_ports + 1)))
        
        # Limit concurrent port scans
        semaphore = asyncio.Semaphore(100)
        
        async def scan_port(port):
            async with semaphore:
                try:
                    reader, writer = await asyncio.wait_for(
                        asyncio.open_connection(target_ip, port),
                        timeout=5
                    )
                    writer.close()
                    await writer.wait_closed()
                    
                    return ReconResult(
                        result_type=ReconType.PORT,
                        discovered_asset=f"{target_ip}:{port}",
                        confidence_score=1.0,
                        discovery_method=ReconMethod.PORT_SCANNING,
                        discovered_by_tool="port_scanner",
                        ip_address=target_ip,
                        port=port,
                        additional_data={"state": "open"}
                    )
                except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
                    return None
                except Exception as e:
                    self.logger.debug(f"Port scan failed for {target_ip}:{port}: {e}")
                    return None
        
        # Scan ports
        tasks = [scan_port(port) for port in ports]
        scan_results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in scan_results:
            if isinstance(result, ReconResult):
                results.append(result)
        
        return results
    
    async def _grab_banner(self, target_ip: str, port: int) -> Optional[str]:
        """Grab service banner from port"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port),
                timeout=10
            )
            
            # Try to read banner
            banner = await asyncio.wait_for(reader.read(1024), timeout=5)
            
            writer.close()
            await writer.wait_closed()
            
            return banner.decode('utf-8', errors='ignore').strip()
        except Exception:
            return None
    
    def _parse_service_banner(self, banner: str) -> Dict[str, str]:
        """Parse service information from banner"""
        service_info = {}
        
        # Common service patterns
        patterns = {
            'SSH': r'SSH-(\d+\.\d+)-(.+)',
            'HTTP': r'Server: (.+)',
            'FTP': r'FTP.+\((.+)\)',
            'SMTP': r'(\d{3}) (.+) ESMTP (.+)',
            'MySQL': r'(\d+\.\d+\.\d+)',
            'PostgreSQL': r'PostgreSQL (\d+\.\d+)'
        }
        
        for service, pattern in patterns.items():
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                service_info['service'] = service
                service_info['version'] = match.group(1) if match.groups() else 'unknown'
                break
        
        return service_info
    
    def _detect_technologies(self, content: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Detect web technologies from content and headers"""
        technologies = []
        
        # Header-based detection
        server_header = headers.get('server', '').lower()
        if 'nginx' in server_header:
            technologies.append({
                'name': 'Nginx',
                'confidence': 0.9,
                'method': 'server_header',
                'evidence': server_header
            })
        elif 'apache' in server_header:
            technologies.append({
                'name': 'Apache',
                'confidence': 0.9,
                'method': 'server_header',
                'evidence': server_header
            })
        
        # Content-based detection
        content_lower = content.lower()
        
        # Framework detection
        if 'django' in content_lower:
            technologies.append({
                'name': 'Django',
                'confidence': 0.8,
                'method': 'content_analysis'
            })
        elif 'react' in content_lower or 'react-dom' in content_lower:
            technologies.append({
                'name': 'React',
                'confidence': 0.8,
                'method': 'content_analysis'
            })
        elif 'angular' in content_lower:
            technologies.append({
                'name': 'Angular',
                'confidence': 0.8,
                'method': 'content_analysis'
            })
        
        # JavaScript libraries
        if 'jquery' in content_lower:
            technologies.append({
                'name': 'jQuery',
                'confidence': 0.7,
                'method': 'content_analysis'
            })
        
        # CMS detection
        if 'wp-content' in content_lower or 'wordpress' in content_lower:
            technologies.append({
                'name': 'WordPress',
                'confidence': 0.9,
                'method': 'content_analysis'
            })
        elif 'drupal' in content_lower:
            technologies.append({
                'name': 'Drupal',
                'confidence': 0.8,
                'method': 'content_analysis'
            })
        
        # CDN detection
        cdn_headers = ['cf-ray', 'x-cache', 'x-served-by', 'x-amz-cf-id']
        for header in cdn_headers:
            if header in headers:
                if 'cloudflare' in headers.get(header, '').lower():
                    technologies.append({
                        'name': 'Cloudflare',
                        'confidence': 0.9,
                        'method': 'header_analysis',
                        'evidence': f"{header}: {headers[header]}"
                    })
                break
        
        return technologies
    
    def _extract_links(self, content: str, base_url: str) -> Set[str]:
        """Extract links from HTML content"""
        links = set()
        
        # Simple regex for href attributes
        href_pattern = r'href=["\']([^"\']+)["\']'
        matches = re.findall(href_pattern, content, re.IGNORECASE)
        
        for link in matches:
            # Convert relative URLs to absolute
            absolute_url = urljoin(base_url, link)
            
            # Filter out non-HTTP links
            if absolute_url.startswith(('http://', 'https://')):
                links.add(absolute_url)
        
        return links
    
    def _is_in_scope(self, url: str, base_url: str) -> bool:
        """Check if URL is in scope for crawling"""
        try:
            base_domain = urlparse(base_url).netloc
            url_domain = urlparse(url).netloc
            return base_domain == url_domain
        except Exception:
            return False
    
    def _detect_api_type(self, url: str, content_type: str) -> str:
        """Detect API type from URL and content type"""
        url_lower = url.lower()
        
        if 'graphql' in url_lower:
            return 'GraphQL'
        elif 'swagger' in url_lower or 'openapi' in url_lower:
            return 'OpenAPI/Swagger'
        elif 'rest' in url_lower or 'api' in url_lower:
            return 'REST'
        elif 'application/json' in content_type:
            return 'JSON API'
        else:
            return 'Unknown'
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path
        except Exception:
            return url


class ReconService:
    """Main reconnaissance service orchestrating passive and active recon"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.passive_engine = PassiveReconEngine()
        self.active_engine = ActiveReconEngine()
        self.notification_service = NotificationService()
    
    @shared_task
    def run_reconnaissance_async(self, scan_session_id: str, config_dict: Dict[str, Any]):
        """Celery task for asynchronous reconnaissance"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            config = ReconConfig(**config_dict)
            result = loop.run_until_complete(
                self.run_reconnaissance(scan_session_id, config)
            )
            return result
        finally:
            loop.close()
    
    async def run_reconnaissance(self, scan_session_id: str, 
                               config: ReconConfig = None) -> Dict[str, Any]:
        """Run complete reconnaissance process"""
        if config is None:
            config = ReconConfig()
        
        with get_db_session() as db:
            scan_session = db.query(ScanSession).filter(
                ScanSession.id == scan_session_id
            ).first()
            
            if not scan_session:
                raise ValueError(f"Scan session {scan_session_id} not found")
            
            target = scan_session.target
            if not target.is_active:
                raise ValueError(f"Target {target.target_name} is not active")
            
            # Update scan session status
            scan_session.current_phase = "passive_recon"
            db.commit()
            
            # Notify start
            await self.notification_service.send_scan_notification(scan_session, "started")
            
            results_summary = {
                "total_discovered": 0,
                "subdomains": 0,
                "endpoints": 0,
                "services": 0,
                "technologies": 0,
                "emails": 0,
                "ports": 0
            }
            
            try:
                # Phase 1: Passive Reconnaissance
                self.logger.info(f"Starting passive reconnaissance for {target.target_name}")
                passive_results = await self._run_passive_reconnaissance(target, config)
                
                # Store passive results
                for result in passive_results:
                    await self._store_recon_result(result, scan_session_id, db)
                    results_summary[f"{result.result_type.value}s"] += 1
                    results_summary["total_discovered"] += 1
                
                # Update scan progress
                scan_session.current_phase = "active_recon"
                scan_session.phase_progress = {"passive_recon": 100, "active_recon": 0}
                db.commit()
                
                # Phase 2: Active Reconnaissance (if not passive-only)
                if not config.passive_only:
                    self.logger.info(f"Starting active reconnaissance for {target.target_name}")
                    active_results = await self._run_active_reconnaissance(
                        target, passive_results, config
                    )
                    
                    # Store active results
                    for result in active_results:
                        await self._store_recon_result(result, scan_session_id, db)
                        results_summary[f"{result.result_type.value}s"] += 1
                        results_summary["total_discovered"] += 1
                
                # Update final counts in scan session
                scan_session.total_subdomains_found = results_summary["subdomains"]
                scan_session.total_endpoints_found = results_summary["endpoints"]
                scan_session.current_phase = "vulnerability_testing"
                scan_session.phase_progress = {
                    "passive_recon": 100,
                    "active_recon": 100,
                    "vulnerability_testing": 0
                }
                db.commit()
                
                # Send completion notification
                await self.notification_service.send_recon_discovery_notification(
                    scan_session, "subdomains", results_summary["subdomains"]
                )
                await self.notification_service.send_recon_discovery_notification(
                    scan_session, "endpoints", results_summary["endpoints"]
                )
                
                self.logger.info(f"Reconnaissance completed for {target.target_name}")
                return results_summary
                
            except Exception as e:
                self.logger.error(f"Reconnaissance failed for {target.target_name}: {e}")
                scan_session.status = ScanStatus.FAILED
                db.commit()
                
                await self.notification_service.send_scan_notification(scan_session, "failed")
                raise
    
    async def _run_passive_reconnaissance(self, target: Target, 
                                        config: ReconConfig) -> List[ReconResult]:
        """Run passive reconnaissance phase"""
        all_results = []
        
        # Subdomain enumeration
        subdomain_results = await self.passive_engine.subdomain_enumeration_passive(target)
        all_results.extend(subdomain_results)
        
        # Email discovery
        email_results = await self.passive_engine.osint_email_discovery(target)
        all_results.extend(email_results)
        
        # Technology detection on main URL
        tech_results = await self.active_engine.web_technology_detection(target.main_url)
        all_results.extend(tech_results)
        
        # Deduplicate results
        return self._deduplicate_results(all_results)
    
    async def _run_active_reconnaissance(self, target: Target, 
                                       passive_results: List[ReconResult],
                                       config: ReconConfig) -> List[ReconResult]:
        """Run active reconnaissance phase"""
        all_results = []
        
        # Extract discovered subdomains for further testing
        discovered_subdomains = [
            result.discovered_asset for result in passive_results
            if result.result_type == ReconType.SUBDOMAIN
        ]
        
        # Add main domain if not already discovered
        main_domain = self._extract_domain(target.main_url)
        if main_domain not in discovered_subdomains:
            discovered_subdomains.append(main_domain)
        
        # Active subdomain enumeration
        active_subdomain_results = await self.active_engine.subdomain_enumeration_active(
            target, config
        )
        all_results.extend(active_subdomain_results)
        
        # Collect all unique subdomains for further testing
        all_subdomains = list(set(discovered_subdomains + [
            result.discovered_asset for result in active_subdomain_results
            if result.result_type == ReconType.SUBDOMAIN
        ]))
        
        # Resolve subdomains to IPs for port scanning
        resolved_ips = await self._resolve_subdomains_to_ips(all_subdomains)
        
        # Port scanning
        if resolved_ips:
            port_results = await self.active_engine.port_scanning(resolved_ips, config)
            all_results.extend(port_results)
            
            # Service detection on open ports
            for port_result in port_results:
                if port_result.result_type == ReconType.PORT:
                    service_result = await self.active_engine.service_detection(
                        port_result.ip_address, port_result.port
                    )
                    if service_result:
                        all_results.append(service_result)
        
        # Web crawling and endpoint discovery
        web_targets = []
        for subdomain in all_subdomains[:10]:  # Limit to prevent excessive crawling
            if self._is_web_service(subdomain):
                web_targets.extend([f"http://{subdomain}", f"https://{subdomain}"])
        
        for web_target in web_targets:
            try:
                # Check if target is accessible
                if await self._is_url_accessible(web_target):
                    # Crawl for endpoints
                    crawl_results = await self.active_engine.web_crawling(web_target, config)
                    all_results.extend(crawl_results)
                    
                    # API discovery
                    api_results = await self.active_engine.api_discovery(web_target)
                    all_results.extend(api_results)
                    
                    # Technology detection
                    tech_results = await self.active_engine.web_technology_detection(web_target)
                    all_results.extend(tech_results)
            except Exception as e:
                self.logger.debug(f"Web reconnaissance failed for {web_target}: {e}")
                continue
        
        return self._deduplicate_results(all_results)
    
    async def _resolve_subdomains_to_ips(self, subdomains: List[str]) -> List[str]:
        """Resolve subdomains to IP addresses"""
        ips = set()
        
        for subdomain in subdomains:
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 10
                answers = resolver.resolve(subdomain, 'A')
                
                for answer in answers:
                    ip = str(answer)
                    # Validate IP and exclude private ranges in some cases
                    try:
                        ip_obj = ipaddress.ip_address(ip)
                        if not ip_obj.is_private or True:  # Include private IPs for now
                            ips.add(ip)
                    except ValueError:
                        continue
            except Exception as e:
                self.logger.debug(f"DNS resolution failed for {subdomain}: {e}")
                continue
        
        return list(ips)
    
    def _is_web_service(self, hostname: str) -> bool:
        """Check if hostname likely hosts a web service"""
        web_indicators = ['www', 'web', 'app', 'portal', 'admin', 'api']
        return any(indicator in hostname.lower() for indicator in web_indicators) or True
    
    async def _is_url_accessible(self, url: str) -> bool:
        """Check if URL is accessible"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(url, timeout=10) as response:
                    return response.status < 500
        except Exception:
            return False
    
    def _deduplicate_results(self, results: List[ReconResult]) -> List[ReconResult]:
        """Remove duplicate reconnaissance results"""
        seen = set()
        deduplicated = []
        
        for result in results:
            # Create a unique key for deduplication
            key = (result.result_type.value, result.discovered_asset)
            
            if key not in seen:
                seen.add(key)
                deduplicated.append(result)
        
        return deduplicated
    
    async def _store_recon_result(self, result: ReconResult, scan_session_id: str, db: Session):
        """Store reconnaissance result in database"""
        # Check scope before storing
        is_in_scope = await self._validate_scope(result, scan_session_id, db)
        
        recon_record = ReconResult(
            scan_session_id=scan_session_id,
            result_type=result.result_type.value,
            discovered_asset=result.discovered_asset,
            ip_address=result.ip_address,
            port=result.port,
            protocol="tcp" if result.port else None,
            service_name=result.service_name,
            service_version=result.service_version,
            technologies=result.technologies or [],
            discovered_by_tool=result.discovered_by_tool,
            discovery_method=result.discovery_method.value,
            confidence_score=result.confidence_score,
            is_in_scope=is_in_scope,
            additional_info=result.additional_data
        )
        
        db.add(recon_record)
        db.commit()
    
    async def _validate_scope(self, result: ReconResult, scan_session_id: str, db: Session) -> bool:
        """Validate if discovered asset is in scope"""
        scan_session = db.query(ScanSession).filter(
            ScanSession.id == scan_session_id
        ).first()
        
        if not scan_session:
            return False
        
        target = scan_session.target
        discovered_asset = result.discovered_asset
        
        # Check against out-of-scope assets
        for out_of_scope in target.out_of_scope_assets + target.out_of_scope_urls:
            if out_of_scope.strip() and out_of_scope.strip() in discovered_asset:
                return False
        
        # Check against in-scope assets
        for in_scope in target.in_scope_assets + target.in_scope_urls:
            if in_scope.strip() and in_scope.strip() in discovered_asset:
                return True
        
        # Check if asset belongs to main domain or wildcard
        try:
            main_domain = self._extract_domain(target.main_url)
            wildcard_domain = self._extract_domain(target.wildcard_url) if target.wildcard_url else None
            
            if main_domain in discovered_asset:
                return True
            if wildcard_domain and wildcard_domain in discovered_asset:
                return True
        except Exception as e:
            self.logger.error(f"Error validating scope: {e}")
        
        # Default to in-scope if uncertain
        return True
    
    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        try:
            parsed = urlparse(url)
            return parsed.netloc or parsed.path
        except Exception:
            return url
    
    async def get_reconnaissance_results(self, scan_session_id: str, 
                                       result_type: Optional[str] = None,
                                       in_scope_only: bool = True) -> List[Dict[str, Any]]:
        """Get reconnaissance results for a scan session"""
        with get_db_session() as db:
            query = db.query(ReconResult).filter(
                ReconResult.scan_session_id == scan_session_id
            )
            
            if result_type:
                query = query.filter(ReconResult.result_type == result_type)
            
            if in_scope_only:
                query = query.filter(ReconResult.is_in_scope == True)
            
            results = query.order_by(ReconResult.discovered_at.desc()).all()
            
            return [
                {
                    "id": str(result.id),
                    "result_type": result.result_type,
                    "discovered_asset": result.discovered_asset,
                    "ip_address": result.ip_address,
                    "port": result.port,
                    "service_name": result.service_name,
                    "service_version": result.service_version,
                    "technologies": result.technologies,
                    "discovered_by_tool": result.discovered_by_tool,
                    "discovery_method": result.discovery_method,
                    "confidence_score": result.confidence_score,
                    "is_in_scope": result.is_in_scope,
                    "discovered_at": result.discovered_at.isoformat(),
                    "additional_info": result.additional_info
                }
                for result in results
            ]
    
    async def get_reconnaissance_statistics(self, scan_session_id: str) -> Dict[str, Any]:
        """Get reconnaissance statistics for a scan session"""
        with get_db_session() as db:
            results = db.query(ReconResult).filter(
                ReconResult.scan_session_id == scan_session_id
            ).all()
            
            stats = {
                "total_discovered": len(results),
                "in_scope": len([r for r in results if r.is_in_scope]),
                "out_of_scope": len([r for r in results if not r.is_in_scope]),
                "by_type": {},
                "by_tool": {},
                "by_method": {},
                "high_confidence": len([r for r in results if r.confidence_score >= 0.8])
            }
            
            # Count by type
            for result_type in ReconType:
                count = len([r for r in results if r.result_type == result_type.value])
                stats["by_type"][result_type.value] = count
            
            # Count by tool
            tools = set(r.discovered_by_tool for r in results)
            for tool in tools:
                count = len([r for r in results if r.discovered_by_tool == tool])
                stats["by_tool"][tool] = count
            
            # Count by method
            methods = set(r.discovery_method for r in results)
            for method in methods:
                count = len([r for r in results if r.discovery_method == method])
                stats["by_method"][method] = count
            
            return stats
    
    async def export_reconnaissance_results(self, scan_session_id: str, 
                                          format: str = "json") -> str:
        """Export reconnaissance results in specified format"""
        results = await self.get_reconnaissance_results(scan_session_id, in_scope_only=False)
        
        if format.lower() == "json":
            return json.dumps(results, indent=2)
        elif format.lower() == "csv":
            # Convert to CSV format
            import csv
            import io
            
            output = io.StringIO()
            if results:
                fieldnames = results[0].keys()
                writer = csv.DictWriter(output, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)
            
            return output.getvalue()
        else:
            raise ValueError(f"Unsupported export format: {format}")