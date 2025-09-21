"""
Reconnaissance Engine Module
============================

Handles both passive and active reconnaissance operations including subdomain
enumeration, port scanning, service identification, and technology profiling.
"""

import asyncio
import json
import logging
import re
import socket
import ssl
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urlparse, urljoin

import aiohttp
import dns.resolver
from bs4 import BeautifulSoup

from . import ToolExecutionError, ScopeValidationError


@dataclass
class ReconTarget:
    """Container for reconnaissance target information."""
    domain: str
    ip_addresses: List[str] = None
    subdomains: Set[str] = None
    ports: Dict[int, str] = None
    services: List[Dict] = None
    technologies: List[Dict] = None
    
    def __post_init__(self):
        if self.ip_addresses is None:
            self.ip_addresses = []
        if self.subdomains is None:
            self.subdomains = set()
        if self.ports is None:
            self.ports = {}
        if self.services is None:
            self.services = []
        if self.technologies is None:
            self.technologies = []


class ReconEngine:
    """
    Main reconnaissance engine for passive and active information gathering.
    """
    
    def __init__(self, target_id: str, config: Dict[str, Any], db_session=None):
        """
        Initialize the reconnaissance engine.
        
        Args:
            target_id: Target identifier
            config: Reconnaissance configuration
            db_session: Database session for storing results
        """
        self.target_id = target_id
        self.config = config
        self.db_session = db_session
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.subdomain_enum = SubdomainEnumerator(config.get('subdomain', {}))
        self.port_scanner = PortScanner(config.get('port_scan', {}))
        self.service_identifier = ServiceIdentifier(config.get('service', {}))
        self.tech_profiler = TechnologyProfiler(config.get('technology', {}))
        self.asset_discovery = AssetDiscovery(config.get('asset', {}))
        
        # Thread pool for parallel operations
        self.executor = ThreadPoolExecutor(
            max_workers=config.get('max_workers', 10)
        )
        
        # DNS resolver configuration
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = config.get('dns_timeout', 5)
        self.resolver.lifetime = config.get('dns_lifetime', 10)
    
    async def enumerate_subdomains_passive(self) -> List[Dict[str, Any]]:
        """
        Perform passive subdomain enumeration using various sources.
        
        Returns:
            List of discovered subdomains with metadata
        """
        self.logger.info(f"Starting passive subdomain enumeration for target {self.target_id}")
        
        subdomains = []
        tasks = []
        
        # Use multiple passive sources
        if self.config.get('use_certspotter', True):
            tasks.append(self.subdomain_enum.query_certspotter(self.target_id))
        
        if self.config.get('use_crtsh', True):
            tasks.append(self.subdomain_enum.query_crtsh(self.target_id))
        
        if self.config.get('use_securitytrails', False):
            tasks.append(self.subdomain_enum.query_securitytrails(self.target_id))
        
        if self.config.get('use_virustotal', False):
            tasks.append(self.subdomain_enum.query_virustotal(self.target_id))
        
        # Execute all tasks in parallel
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Consolidate results
        all_subdomains = set()
        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Subdomain enumeration task failed: {str(result)}")
                continue
            if result:
                all_subdomains.update(result)
        
        # Resolve and validate subdomains
        for subdomain in all_subdomains:
            subdomain_data = await self._validate_subdomain(subdomain)
            if subdomain_data:
                subdomains.append(subdomain_data)
        
        self.logger.info(f"Found {len(subdomains)} valid subdomains")
        
        # Store results
        if self.db_session:
            self._store_subdomains(subdomains)
        
        return subdomains
    
    async def enumerate_subdomains_active(self) -> List[Dict[str, Any]]:
        """
        Perform active subdomain enumeration using DNS brute-forcing.
        
        Returns:
            List of discovered subdomains
        """
        self.logger.info("Starting active subdomain enumeration")
        
        # Use tools like Amass, Subfinder
        subdomains = []
        
        if self.config.get('use_amass', True):
            amass_results = await self.subdomain_enum.run_amass(self.target_id)
            subdomains.extend(amass_results)
        
        if self.config.get('use_subfinder', True):
            subfinder_results = await self.subdomain_enum.run_subfinder(self.target_id)
            subdomains.extend(subfinder_results)
        
        if self.config.get('dns_bruteforce', False):
            bruteforce_results = await self.subdomain_enum.dns_bruteforce(
                self.target_id,
                self.config.get('wordlist', 'wordlists/subdomains.txt')
            )
            subdomains.extend(bruteforce_results)
        
        return subdomains
    
    async def gather_osint(self) -> Dict[str, Any]:
        """
        Gather Open Source Intelligence about the target.
        
        Returns:
            Dictionary containing OSINT data
        """
        self.logger.info("Gathering OSINT data")
        
        osint_data = {
            'whois': {},
            'dns_records': {},
            'ssl_certificates': [],
            'exposed_services': [],
            'leaked_credentials': [],
            'social_media': [],
            'github_repos': [],
            'pastebin_data': []
        }
        
        # WHOIS lookup
        try:
            osint_data['whois'] = await self._whois_lookup(self.target_id)
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed: {str(e)}")
        
        # DNS record enumeration
        try:
            osint_data['dns_records'] = await self._enumerate_dns_records(self.target_id)
        except Exception as e:
            self.logger.error(f"DNS enumeration failed: {str(e)}")
        
        # SSL certificate analysis
        try:
            osint_data['ssl_certificates'] = await self._analyze_ssl_certificates(self.target_id)
        except Exception as e:
            self.logger.error(f"SSL analysis failed: {str(e)}")
        
        # Search for exposed services (Shodan, Censys)
        if self.config.get('use_shodan', False):
            osint_data['exposed_services'] = await self._search_shodan(self.target_id)
        
        # GitHub reconnaissance
        if self.config.get('github_recon', True):
            osint_data['github_repos'] = await self._search_github(self.target_id)
        
        return osint_data
    
    async def profile_technology_passive(self) -> List[Dict[str, Any]]:
        """
        Profile technology stack using passive methods.
        
        Returns:
            List of identified technologies
        """
        self.logger.info("Profiling technology stack (passive)")
        
        technologies = []
        
        # Analyze HTTP headers and responses
        target_url = f"https://{self.target_id}"
        
        try:
            tech_data = await self.tech_profiler.analyze_web_technologies(target_url)
            technologies.extend(tech_data)
        except Exception as e:
            self.logger.error(f"Technology profiling failed: {str(e)}")
        
        # Check for known technology indicators
        indicators = await self.tech_profiler.check_technology_indicators(target_url)
        technologies.extend(indicators)
        
        return technologies
    
    async def scan_ports(self, targets: List[str]) -> List[Dict[str, Any]]:
        """
        Perform port scanning on targets.
        
        Args:
            targets: List of target hosts
            
        Returns:
            List of port scan results
        """
        self.logger.info(f"Starting port scan on {len(targets)} targets")
        
        results = []
        
        for target in targets:
            try:
                # Resolve target to IP
                ip = await self._resolve_target(target)
                if not ip:
                    continue
                
                # Perform port scan
                if self.config.get('scan_type') == 'nmap':
                    scan_result = await self.port_scanner.nmap_scan(ip)
                elif self.config.get('scan_type') == 'masscan':
                    scan_result = await self.port_scanner.masscan_scan(ip)
                else:
                    scan_result = await self.port_scanner.tcp_scan(ip)
                
                results.append({
                    'target': target,
                    'ip': ip,
                    'ports': scan_result,
                    'timestamp': datetime.utcnow().isoformat()
                })
                
            except Exception as e:
                self.logger.error(f"Port scan failed for {target}: {str(e)}")
        
        return results
    
    async def identify_services(self, port_results: List[Dict]) -> List[Dict[str, Any]]:
        """
        Identify services running on discovered ports.
        
        Args:
            port_results: Port scan results
            
        Returns:
            List of identified services
        """
        self.logger.info("Identifying services on open ports")
        
        services = []
        
        for result in port_results:
            target = result['target']
            ip = result['ip']
            
            for port_info in result.get('ports', []):
                port = port_info['port']
                
                try:
                    service = await self.service_identifier.identify_service(
                        ip, port, port_info.get('protocol', 'tcp')
                    )
                    
                    if service:
                        services.append({
                            'target': target,
                            'ip': ip,
                            'port': port,
                            'service': service,
                            'version': port_info.get('version'),
                            'banner': port_info.get('banner'),
                            'timestamp': datetime.utcnow().isoformat()
                        })
                        
                except Exception as e:
                    self.logger.error(f"Service identification failed for {ip}:{port}: {str(e)}")
        
        return services
    
    async def crawl_web_assets(self, targets: List[str]) -> List[Dict[str, Any]]:
        """
        Crawl web applications to discover assets.
        
        Args:
            targets: List of target URLs/domains
            
        Returns:
            List of discovered web assets
        """
        self.logger.info(f"Crawling {len(targets)} targets for web assets")
        
        all_assets = []
        
        for target in targets:
            try:
                # Ensure proper URL format
                if not target.startswith(('http://', 'https://')):
                    target = f"https://{target}"
                
                assets = await self.asset_discovery.crawl_website(
                    target,
                    max_depth=self.config.get('crawl_depth', 3),
                    max_pages=self.config.get('max_pages', 100)
                )
                
                all_assets.append({
                    'target': target,
                    'assets': assets,
                    'timestamp': datetime.utcnow().isoformat()
                })
                
            except Exception as e:
                self.logger.error(f"Web crawling failed for {target}: {str(e)}")
        
        return all_assets
    
    async def capture_screenshots(self, targets: List[str]) -> List[Dict[str, Any]]:
        """
        Capture screenshots of web applications.
        
        Args:
            targets: List of target URLs
            
        Returns:
            List of screenshot metadata
        """
        self.logger.info(f"Capturing screenshots for {len(targets)} targets")
        
        screenshots = []
        
        for target in targets:
            try:
                if not target.startswith(('http://', 'https://')):
                    target = f"https://{target}"
                
                screenshot_path = await self._capture_screenshot(target)
                
                screenshots.append({
                    'target': target,
                    'screenshot_path': screenshot_path,
                    'timestamp': datetime.utcnow().isoformat()
                })
                
            except Exception as e:
                self.logger.error(f"Screenshot capture failed for {target}: {str(e)}")
        
        return screenshots
    
    async def _validate_subdomain(self, subdomain: str) -> Optional[Dict[str, Any]]:
        """
        Validate and resolve a subdomain.
        
        Args:
            subdomain: Subdomain to validate
            
        Returns:
            Subdomain data if valid, None otherwise
        """
        try:
            answers = self.resolver.resolve(subdomain, 'A')
            ips = [str(rdata) for rdata in answers]
            
            return {
                'subdomain': subdomain,
                'ip_addresses': ips,
                'validated': True,
                'timestamp': datetime.utcnow().isoformat()
            }
        except Exception:
            return None
    
    async def _resolve_target(self, target: str) -> Optional[str]:
        """
        Resolve target to IP address.
        
        Args:
            target: Target hostname or domain
            
        Returns:
            IP address or None
        """
        try:
            # If already an IP, return it
            socket.inet_aton(target)
            return target
        except socket.error:
            # Resolve hostname
            try:
                return socket.gethostbyname(target)
            except socket.gaierror:
                return None
    
    async def _whois_lookup(self, domain: str) -> Dict[str, Any]:
        """
        Perform WHOIS lookup.
        
        Args:
            domain: Target domain
            
        Returns:
            WHOIS data
        """
        try:
            result = subprocess.run(
                ['whois', domain],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                return self._parse_whois_output(result.stdout)
            
        except Exception as e:
            self.logger.error(f"WHOIS lookup failed: {str(e)}")
        
        return {}
    
    def _parse_whois_output(self, output: str) -> Dict[str, Any]:
        """Parse WHOIS output into structured data."""
        data = {
            'registrar': None,
            'creation_date': None,
            'expiration_date': None,
            'name_servers': [],
            'registrant': {},
            'raw': output
        }
        
        # Parse common WHOIS fields
        patterns = {
            'registrar': r'Registrar:\s*(.+)',
            'creation_date': r'Creation Date:\s*(.+)',
            'expiration_date': r'Expir\w+ Date:\s*(.+)',
            'name_server': r'Name Server:\s*(.+)'
        }
        
        for key, pattern in patterns.items():
            matches = re.findall(pattern, output, re.IGNORECASE)
            if matches:
                if key == 'name_server':
                    data['name_servers'] = matches
                else:
                    data[key] = matches[0]
        
        return data
    
    async def _enumerate_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """
        Enumerate various DNS record types.
        
        Args:
            domain: Target domain
            
        Returns:
            Dictionary of DNS records
        """
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'SOA', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = self.resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except Exception:
                records[record_type] = []
        
        return records
    
    async def _analyze_ssl_certificates(self, domain: str) -> List[Dict[str, Any]]:
        """
        Analyze SSL certificates for the domain.
        
        Args:
            domain: Target domain
            
        Returns:
            List of certificate information
        """
        certs = []
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    certs.append({
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    })
                    
        except Exception as e:
            self.logger.error(f"SSL certificate analysis failed: {str(e)}")
        
        return certs
    
    async def _search_shodan(self, domain: str) -> List[Dict[str, Any]]:
        """Search Shodan for exposed services."""
        # This would require Shodan API integration
        return []
    
    async def _search_github(self, domain: str) -> List[Dict[str, Any]]:
        """Search GitHub for related repositories and potential leaks."""
        repos = []
        
        # Search for domain mentions in code
        search_queries = [
            f'"{domain}"',
            f'api_key {domain}',
            f'password {domain}',
            f'token {domain}'
        ]
        
        # Would require GitHub API integration
        return repos
    
    async def _capture_screenshot(self, url: str) -> str:
        """
        Capture screenshot of a web page.
        
        Args:
            url: Target URL
            
        Returns:
            Path to screenshot file
        """
        # This would require a headless browser like Playwright or Selenium
        # For now, return placeholder
        screenshot_path = f"/tmp/screenshots/{urlparse(url).netloc}.png"
        return screenshot_path
    
    def _store_subdomains(self, subdomains: List[Dict]):
        """Store subdomain results in database."""
        if not self.db_session:
            return
        
        try:
            from .db_interfaces import ReconResultManager
            recon_manager = ReconResultManager(self.db_session, self.logger)
            recon_manager.store_subdomains(self.target_id, subdomains)
        except Exception as e:
            self.logger.error(f"Failed to store subdomains: {str(e)}")


class SubdomainEnumerator:
    """Handle subdomain enumeration operations."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize subdomain enumerator."""
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    async def query_certspotter(self, domain: str) -> Set[str]:
        """Query CertSpotter for subdomains."""
        subdomains = set()
        
        try:
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        for cert in data:
                            for name in cert.get('dns_names', []):
                                if domain in name:
                                    subdomains.add(name)
                                    
        except Exception as e:
            self.logger.error(f"CertSpotter query failed: {str(e)}")
        
        return subdomains
    
    async def query_crtsh(self, domain: str) -> Set[str]:
        """Query crt.sh for certificate transparency logs."""
        subdomains = set()
        
        try:
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=30) as response:
                    if response.status == 200:
                        data = await response.json()
                        for entry in data:
                            name = entry.get('name_value', '')
                            if domain in name:
                                # Handle wildcards and multiple entries
                                names = name.replace('*.', '').split('\n')
                                subdomains.update(names)
                                
        except Exception as e:
            self.logger.error(f"crt.sh query failed: {str(e)}")
        
        return subdomains
    
    async def query_securitytrails(self, domain: str) -> Set[str]:
        """Query SecurityTrails API for subdomains."""
        # Requires API key
        return set()
    
    async def query_virustotal(self, domain: str) -> Set[str]:
        """Query VirusTotal for subdomains."""
        # Requires API key
        return set()
    
    async def run_amass(self, domain: str) -> List[Dict[str, Any]]:
        """Run Amass for subdomain enumeration."""
        subdomains = []
        
        try:
            cmd = [
                'amass', 'enum',
                '-passive',
                '-d', domain,
                '-json', '-'
            ]
            
            if self.config.get('amass_config'):
                cmd.extend(['-config', self.config['amass_config']])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line:
                        try:
                            data = json.loads(line)
                            subdomains.append({
                                'subdomain': data.get('name'),
                                'source': data.get('source'),
                                'ip_addresses': data.get('addresses', [])
                            })
                        except json.JSONDecodeError:
                            continue
                            
        except Exception as e:
            self.logger.error(f"Amass execution failed: {str(e)}")
        
        return subdomains
    
    async def run_subfinder(self, domain: str) -> List[Dict[str, Any]]:
        """Run Subfinder for subdomain enumeration."""
        subdomains = []
        
        try:
            cmd = [
                'subfinder',
                '-d', domain,
                '-json',
                '-all'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=180
            )
            
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    if line:
                        try:
                            data = json.loads(line)
                            subdomains.append({
                                'subdomain': data.get('host'),
                                'source': data.get('source')
                            })
                        except json.JSONDecodeError:
                            continue
                            
        except Exception as e:
            self.logger.error(f"Subfinder execution failed: {str(e)}")
        
        return subdomains
    
    async def dns_bruteforce(self, domain: str, wordlist: str) -> List[Dict[str, Any]]:
        """Perform DNS brute-force attack."""
        subdomains = []
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        try:
            with open(wordlist, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
            
            # Limit wordlist size for performance
            words = words[:self.config.get('max_bruteforce_words', 1000)]
            
            # Use asyncio for parallel resolution
            tasks = []
            for word in words:
                subdomain = f"{word}.{domain}"
                tasks.append(self._resolve_subdomain(subdomain, resolver))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for subdomain, ips in results:
                if ips and not isinstance(ips, Exception):
                    subdomains.append({
                        'subdomain': subdomain,
                        'ip_addresses': ips,
                        'source': 'dns_bruteforce'
                    })
                    
        except Exception as e:
            self.logger.error(f"DNS brute-force failed: {str(e)}")
        
        return subdomains
    
    async def _resolve_subdomain(self, subdomain: str, resolver) -> Tuple[str, List[str]]:
        """Resolve a subdomain to IP addresses."""
        try:
            answers = resolver.resolve(subdomain, 'A')
            return subdomain, [str(rdata) for rdata in answers]
        except:
            return subdomain, []


class PortScanner:
    """Handle port scanning operations."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize port scanner."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 8080, 8443]
    
    async def nmap_scan(self, target: str) -> List[Dict[str, Any]]:
        """Perform Nmap scan."""
        open_ports = []
        
        try:
            # Build Nmap command
            cmd = ['nmap', '-sS', '-sV', '-O', '-A', '--open']
            
            # Add port specification
            if self.config.get('port_range'):
                cmd.extend(['-p', self.config['port_range']])
            elif self.config.get('top_ports'):
                cmd.extend(['--top-ports', str(self.config['top_ports'])])
            else:
                cmd.extend(['-p', ','.join(map(str, self.common_ports))])
            
            # Add timing template
            timing = self.config.get('timing', 'T3')
            cmd.append(f'-{timing}')
            
            # Add output format
            cmd.extend(['-oX', '-', target])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                # Parse XML output
                open_ports = self._parse_nmap_xml(result.stdout)
                
        except Exception as e:
            self.logger.error(f"Nmap scan failed: {str(e)}")
        
        return open_ports
    
    async def masscan_scan(self, target: str) -> List[Dict[str, Any]]:
        """Perform Masscan scan."""
        open_ports = []
        
        try:
            cmd = [
                'masscan',
                target,
                '-p', self.config.get('port_range', '1-65535'),
                '--rate', str(self.config.get('rate', 1000)),
                '--output-format', 'json'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                # Parse JSON output
                for line in result.stdout.split('\n'):
                    if line.strip() and not line.startswith('#'):
                        try:
                            data = json.loads(line)
                            for port_info in data.get('ports', []):
                                open_ports.append({
                                    'port': port_info['port'],
                                    'protocol': port_info['proto'],
                                    'state': 'open',
                                    'service': port_info.get('service')
                                })
                        except json.JSONDecodeError:
                            continue
                            
        except Exception as e:
            self.logger.error(f"Masscan failed: {str(e)}")
        
        return open_ports
    
    async def tcp_scan(self, target: str) -> List[Dict[str, Any]]:
        """Perform basic TCP connect scan."""
        open_ports = []
        
        ports_to_scan = self._get_ports_to_scan()
        
        for port in ports_to_scan:
            if await self._check_port_open(target, port):
                service = self._guess_service(port)
                open_ports.append({
                    'port': port,
                    'protocol': 'tcp',
                    'state': 'open',
                    'service': service
                })
        
        return open_ports
    
    async def _check_port_open(self, host: str, port: int) -> bool:
        """Check if a TCP port is open."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.config.get('timeout', 2))
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except:
            return False
    
    def _get_ports_to_scan(self) -> List[int]:
        """Get list of ports to scan."""
        if self.config.get('port_range'):
            # Parse port range (e.g., "1-1000")
            range_parts = self.config['port_range'].split('-')
            if len(range_parts) == 2:
                start, end = map(int, range_parts)
                return list(range(start, end + 1))
        
        return self.config.get('ports', self.common_ports)
    
    def _guess_service(self, port: int) -> str:
        """Guess service based on port number."""
        service_map = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            143: 'imap',
            443: 'https',
            445: 'smb',
            1433: 'mssql',
            3306: 'mysql',
            3389: 'rdp',
            5432: 'postgresql',
            5900: 'vnc',
            6379: 'redis',
            8080: 'http-alt',
            8443: 'https-alt',
            27017: 'mongodb'
        }
        return service_map.get(port, 'unknown')
    
    def _parse_nmap_xml(self, xml_output: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output."""
        # Would use xml.etree.ElementTree to parse
        # Placeholder for now
        return []


class ServiceIdentifier:
    """Identify services running on open ports."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize service identifier."""
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    async def identify_service(self, host: str, port: int, protocol: str = 'tcp') -> Dict[str, Any]:
        """
        Identify service running on a specific port.
        
        Args:
            host: Target host
            port: Port number
            protocol: Protocol (tcp/udp)
            
        Returns:
            Service information
        """
        service_info = {
            'name': 'unknown',
            'version': None,
            'banner': None,
            'fingerprint': None
        }
        
        try:
            # Try banner grabbing first
            banner = await self._grab_banner(host, port)
            if banner:
                service_info['banner'] = banner
                service_info.update(self._parse_banner(banner))
            
            # Try specific service probes
            if port == 80 or port == 8080:
                http_info = await self._probe_http(host, port)
                service_info.update(http_info)
            elif port == 443 or port == 8443:
                https_info = await self._probe_https(host, port)
                service_info.update(https_info)
            elif port == 22:
                ssh_info = await self._probe_ssh(host, port)
                service_info.update(ssh_info)
            elif port == 21:
                ftp_info = await self._probe_ftp(host, port)
                service_info.update(ftp_info)
            
        except Exception as e:
            self.logger.error(f"Service identification failed for {host}:{port}: {str(e)}")
        
        return service_info
    
    async def _grab_banner(self, host: str, port: int) -> Optional[str]:
        """Grab service banner."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # Send a generic probe
            sock.send(b'\r\n')
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            return banner.strip() if banner else None
            
        except Exception:
            return None
    
    def _parse_banner(self, banner: str) -> Dict[str, Any]:
        """Parse service information from banner."""
        info = {}
        
        # Common banner patterns
        patterns = {
            'ssh': r'SSH-[\d.]+-(.+)',
            'ftp': r'220[- ](.+)',
            'smtp': r'220[- ](.+) ESMTP (.+)',
            'http': r'Server: (.+)',
            'mysql': r'mysql_native_password',
            'redis': r'\$\d+\r\n'
        }
        
        for service, pattern in patterns.items():
            if re.search(pattern, banner, re.IGNORECASE):
                info['name'] = service
                match = re.search(pattern, banner, re.IGNORECASE)
                if match and match.groups():
                    info['version'] = match.group(1)
                break
        
        return info
    
    async def _probe_http(self, host: str, port: int) -> Dict[str, Any]:
        """Probe HTTP service."""
        info = {'name': 'http'}
        
        try:
            url = f"http://{host}:{port}"
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=5) as response:
                    headers = response.headers
                    
                    # Extract server information
                    if 'Server' in headers:
                        info['version'] = headers['Server']
                    
                    # Extract powered-by information
                    if 'X-Powered-By' in headers:
                        info['powered_by'] = headers['X-Powered-By']
                    
        except Exception:
            pass
        
        return info
    
    async def _probe_https(self, host: str, port: int) -> Dict[str, Any]:
        """Probe HTTPS service."""
        info = {'name': 'https'}
        
        try:
            # Get SSL certificate information
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    info['ssl_cert'] = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer'])
                    }
                    
            # Also probe as HTTP
            http_info = await self._probe_http(host, port)
            info.update(http_info)
            info['name'] = 'https'  # Keep it as HTTPS
            
        except Exception:
            pass
        
        return info
    
    async def _probe_ssh(self, host: str, port: int) -> Dict[str, Any]:
        """Probe SSH service."""
        info = {'name': 'ssh'}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # SSH sends banner immediately
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if banner.startswith('SSH-'):
                parts = banner.strip().split('-')
                if len(parts) >= 3:
                    info['version'] = '-'.join(parts[2:])
                    
        except Exception:
            pass
        
        return info
    
    async def _probe_ftp(self, host: str, port: int) -> Dict[str, Any]:
        """Probe FTP service."""
        info = {'name': 'ftp'}
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((host, port))
            
            # FTP sends banner immediately
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            sock.close()
            
            if banner.startswith('220'):
                # Extract FTP server version
                match = re.search(r'220[- ](.+)', banner)
                if match:
                    info['version'] = match.group(1)
                    
        except Exception:
            pass
        
        return info


class TechnologyProfiler:
    """Profile technology stack of web applications."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize technology profiler."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Technology signatures
        self.signatures = {
            'frameworks': {
                'Laravel': ['laravel_session', 'X-Laravel-Cache'],
                'Django': ['csrftoken', 'django'],
                'Ruby on Rails': ['_rails_session', 'X-Rails-'],
                'Express': ['X-Powered-By: Express'],
                'Spring': ['JSESSIONID', 'spring'],
                'ASP.NET': ['ASP.NET_SessionId', 'X-AspNet-Version'],
                'WordPress': ['/wp-content/', '/wp-admin/', 'wp-json'],
                'Drupal': ['Drupal', '/sites/default/'],
                'Joomla': ['/components/', 'joomla']
            },
            'servers': {
                'Nginx': ['nginx', 'X-Nginx'],
                'Apache': ['Apache', 'mod_'],
                'IIS': ['Microsoft-IIS', 'ASP.NET'],
                'Tomcat': ['Apache-Coyote', 'tomcat'],
                'LiteSpeed': ['LiteSpeed']
            },
            'languages': {
                'PHP': ['.php', 'X-Powered-By: PHP'],
                'Python': ['.py', 'python'],
                'Ruby': ['.rb', 'ruby'],
                'Java': ['.jsp', 'java', 'servlet'],
                'JavaScript': ['node', 'express', 'react', 'vue', 'angular'],
                'C#': ['.aspx', 'asp.net']
            },
            'cdn': {
                'Cloudflare': ['CF-RAY', '__cfduid', 'cloudflare'],
                'AWS CloudFront': ['x-amz-cf-', 'CloudFront'],
                'Akamai': ['akamai', 'AkamaiGHost'],
                'Fastly': ['Fastly', 'x-fastly-']
            },
            'analytics': {
                'Google Analytics': ['google-analytics.com', 'ga.js', '_ga'],
                'Google Tag Manager': ['googletagmanager.com', 'gtm.js'],
                'Facebook Pixel': ['facebook.com/tr', 'fbq'],
                'Hotjar': ['hotjar.com', '_hjid']
            }
        }
    
    async def analyze_web_technologies(self, url: str) -> List[Dict[str, Any]]:
        """
        Analyze technologies used by a web application.
        
        Args:
            url: Target URL
            
        Returns:
            List of identified technologies
        """
        technologies = []
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=10) as response:
                    headers = dict(response.headers)
                    body = await response.text()
                    cookies = response.cookies
                    
                    # Analyze headers
                    tech_from_headers = self._analyze_headers(headers)
                    technologies.extend(tech_from_headers)
                    
                    # Analyze HTML content
                    tech_from_body = self._analyze_body(body)
                    technologies.extend(tech_from_body)
                    
                    # Analyze cookies
                    tech_from_cookies = self._analyze_cookies(cookies)
                    technologies.extend(tech_from_cookies)
                    
                    # Analyze JavaScript libraries
                    js_libs = await self._analyze_javascript(url, body)
                    technologies.extend(js_libs)
                    
        except Exception as e:
            self.logger.error(f"Technology analysis failed for {url}: {str(e)}")
        
        # Deduplicate
        seen = set()
        unique_tech = []
        for tech in technologies:
            key = (tech['category'], tech['name'])
            if key not in seen:
                seen.add(key)
                unique_tech.append(tech)
        
        return unique_tech
    
    def _analyze_headers(self, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze HTTP headers for technology indicators."""
        technologies = []
        
        for category, signatures in self.signatures.items():
            for tech_name, indicators in signatures.items():
                for indicator in indicators:
                    for header_name, header_value in headers.items():
                        if indicator.lower() in header_name.lower() or \
                           indicator.lower() in header_value.lower():
                            technologies.append({
                                'category': category,
                                'name': tech_name,
                                'confidence': 'high',
                                'source': 'headers',
                                'indicator': indicator
                            })
                            break
        
        return technologies
    
    def _analyze_body(self, html: str) -> List[Dict[str, Any]]:
        """Analyze HTML body for technology indicators."""
        technologies = []
        soup = BeautifulSoup(html, 'html.parser')
        
        # Check meta tags
        meta_generators = soup.find_all('meta', {'name': 'generator'})
        for meta in meta_generators:
            content = meta.get('content', '')
            if content:
                technologies.append({
                    'category': 'cms',
                    'name': content.split(' ')[0],
                    'version': content.split(' ')[1] if ' ' in content else None,
                    'confidence': 'high',
                    'source': 'meta_tag'
                })
        
        # Check for framework indicators in HTML
        for category, signatures in self.signatures.items():
            for tech_name, indicators in signatures.items():
                for indicator in indicators:
                    if indicator in html:
                        technologies.append({
                            'category': category,
                            'name': tech_name,
                            'confidence': 'medium',
                            'source': 'html_content',
                            'indicator': indicator
                        })
                        break
        
        return technologies
    
    def _analyze_cookies(self, cookies) -> List[Dict[str, Any]]:
        """Analyze cookies for technology indicators."""
        technologies = []
        
        cookie_indicators = {
            'PHP': ['PHPSESSID'],
            'ASP.NET': ['ASP.NET_SessionId'],
            'Java': ['JSESSIONID'],
            'Laravel': ['laravel_session'],
            'Django': ['csrftoken', 'sessionid']
        }
        
        for cookie in cookies:
            for tech, indicators in cookie_indicators.items():
                if cookie.key in indicators:
                    technologies.append({
                        'category': 'language',
                        'name': tech,
                        'confidence': 'high',
                        'source': 'cookies',
                        'indicator': cookie.key
                    })
        
        return technologies
    
    async def _analyze_javascript(self, url: str, html: str) -> List[Dict[str, Any]]:
        """Analyze JavaScript libraries and frameworks."""
        technologies = []
        soup = BeautifulSoup(html, 'html.parser')
        
        # Common JavaScript library patterns
        js_patterns = {
            'jQuery': [r'jquery[\.-][\d\.]+', r'\$\.fn\.jquery'],
            'React': [r'react[\.-][\d\.]+', r'React\.version'],
            'Angular': [r'angular[\.-][\d\.]+', r'ng-version'],
            'Vue.js': [r'vue[\.-][\d\.]+', r'Vue\.version'],
            'Bootstrap': [r'bootstrap[\.-][\d\.]+'],
            'Lodash': [r'lodash[\.-][\d\.]+'],
            'Moment.js': [r'moment[\.-][\d\.]+']
        }
        
        # Check script tags
        scripts = soup.find_all('script', src=True)
        for script in scripts:
            src = script['src']
            for lib, patterns in js_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, src, re.IGNORECASE):
                        technologies.append({
                            'category': 'javascript_library',
                            'name': lib,
                            'confidence': 'high',
                            'source': 'script_tag',
                            'url': src
                        })
                        break
        
        return technologies
    
    async def check_technology_indicators(self, url: str) -> List[Dict[str, Any]]:
        """
        Check for specific technology indicators.
        
        Args:
            url: Target URL
            
        Returns:
            List of technology indicators
        """
        indicators = []
        
        # Check for common files/paths
        tech_paths = {
            'WordPress': ['/wp-admin/', '/wp-content/', '/wp-includes/'],
            'Drupal': ['/sites/default/', '/modules/', '/misc/drupal.js'],
            'Joomla': ['/administrator/', '/components/', '/modules/'],
            'Magento': ['/skin/frontend/', '/js/mage/', '/app/etc/local.xml'],
            'phpMyAdmin': ['/phpmyadmin/', '/pma/'],
            'Jenkins': ['/jenkins/', '/login?from=%2F'],
            'GitLab': ['/users/sign_in', '/api/v4/'],
            'Grafana': ['/login', '/api/datasources'],
            'Kibana': ['/app/kibana', '/api/status']
        }
        
        for tech, paths in tech_paths.items():
            for path in paths:
                full_url = urljoin(url, path)
                if await self._check_path_exists(full_url):
                    indicators.append({
                        'category': 'application',
                        'name': tech,
                        'confidence': 'high',
                        'source': 'path_check',
                        'indicator': path
                    })
                    break
        
        return indicators
    
    async def _check_path_exists(self, url: str) -> bool:
        """Check if a URL path exists."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.head(url, timeout=5, allow_redirects=True) as response:
                    return response.status < 400
        except:
            return False


class AssetDiscovery:
    """Discover and enumerate web assets."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize asset discovery."""
        self.config = config
        self.logger = logging.getLogger(__name__)
    
    async def crawl_website(self, url: str, max_depth: int = 3, max_pages: int = 100) -> Dict[str, Any]:
        """
        Crawl website to discover assets.
        
        Args:
            url: Starting URL
            max_depth: Maximum crawl depth
            max_pages: Maximum pages to crawl
            
        Returns:
            Dictionary of discovered assets
        """
        assets = {
            'pages': [],
            'forms': [],
            'inputs': [],
            'scripts': [],
            'stylesheets': [],
            'images': [],
            'documents': [],
            'api_endpoints': [],
            'external_links': [],
            'emails': [],
            'comments': []
        }
        
        visited = set()
        to_visit = [(url, 0)]
        base_domain = urlparse(url).netloc
        
        while to_visit and len(visited) < max_pages:
            current_url, depth = to_visit.pop(0)
            
            if current_url in visited or depth > max_depth:
                continue
            
            visited.add(current_url)
            
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(current_url, timeout=10) as response:
                        if response.status != 200:
                            continue
                        
                        content_type = response.headers.get('Content-Type', '')
                        if 'text/html' not in content_type:
                            continue
                        
                        html = await response.text()
                        soup = BeautifulSoup(html, 'html.parser')
                        
                        # Add current page
                        assets['pages'].append({
                            'url': current_url,
                            'title': soup.title.string if soup.title else None,
                            'depth': depth
                        })
                        
                        # Extract forms
                        forms = self._extract_forms(soup, current_url)
                        assets['forms'].extend(forms)
                        
                        # Extract inputs
                        inputs = self._extract_inputs(soup, current_url)
                        assets['inputs'].extend(inputs)
                        
                        # Extract scripts
                        scripts = self._extract_scripts(soup, current_url)
                        assets['scripts'].extend(scripts)
                        
                        # Extract stylesheets
                        stylesheets = self._extract_stylesheets(soup, current_url)
                        assets['stylesheets'].extend(stylesheets)
                        
                        # Extract images
                        images = self._extract_images(soup, current_url)
                        assets['images'].extend(images)
                        
                        # Extract documents
                        documents = self._extract_documents(soup, current_url)
                        assets['documents'].extend(documents)
                        
                        # Extract API endpoints
                        api_endpoints = self._extract_api_endpoints(html)
                        assets['api_endpoints'].extend(api_endpoints)
                        
                        # Extract emails
                        emails = self._extract_emails(html)
                        assets['emails'].extend(emails)
                        
                        # Extract comments
                        comments = self._extract_comments(html)
                        assets['comments'].extend(comments)
                        
                        # Extract links for crawling
                        links = soup.find_all('a', href=True)
                        for link in links:
                            href = urljoin(current_url, link['href'])
                            parsed = urlparse(href)
                            
                            # Skip non-HTTP(S) URLs
                            if parsed.scheme not in ['http', 'https']:
                                continue
                            
                            # Check if internal or external link
                            if parsed.netloc == base_domain:
                                if href not in visited:
                                    to_visit.append((href, depth + 1))
                            else:
                                assets['external_links'].append(href)
                                
            except Exception as e:
                self.logger.error(f"Failed to crawl {current_url}: {str(e)}")
        
        # Deduplicate assets
        for key in assets:
            if isinstance(assets[key], list):
                assets[key] = list(set(assets[key])) if all(isinstance(x, str) for x in assets[key]) else assets[key]
        
        return assets
    
    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML."""
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': []
            }
            
            # Extract form inputs
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'type': input_tag.get('type', 'text'),
                    'name': input_tag.get('name'),
                    'id': input_tag.get('id'),
                    'required': input_tag.has_attr('required')
                }
                form_data['inputs'].append(input_data)
            
            forms.append(form_data)
        
        return forms
    
    def _extract_inputs(self, soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
        """Extract all input fields."""
        inputs = []
        
        for input_tag in soup.find_all(['input', 'textarea', 'select']):
            inputs.append({
                'type': input_tag.get('type', 'text'),
                'name': input_tag.get('name'),
                'id': input_tag.get('id'),
                'placeholder': input_tag.get('placeholder'),
                'page_url': base_url
            })
        
        return inputs
    
    def _extract_scripts(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract JavaScript files."""
        scripts = []
        
        for script in soup.find_all('script', src=True):
            script_url = urljoin(base_url, script['src'])
            scripts.append(script_url)
        
        return scripts
    
    def _extract_stylesheets(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract CSS files."""
        stylesheets = []
        
        for link in soup.find_all('link', rel='stylesheet'):
            if link.get('href'):
                css_url = urljoin(base_url, link['href'])
                stylesheets.append(css_url)
        
        return stylesheets
    
    def _extract_images(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract image URLs."""
        images = []
        
        for img in soup.find_all('img', src=True):
            img_url = urljoin(base_url, img['src'])
            images.append(img_url)
        
        return images
    
    def _extract_documents(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract document links (PDF, DOC, etc.)."""
        documents = []
        doc_extensions = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.csv']
        
        for link in soup.find_all('a', href=True):
            href = urljoin(base_url, link['href'])
            if any(href.lower().endswith(ext) for ext in doc_extensions):
                documents.append(href)
        
        return documents
    
    def _extract_api_endpoints(self, html: str) -> List[str]:
        """Extract potential API endpoints from JavaScript."""
        api_endpoints = []
        
        # Common API patterns
        patterns = [
            r'["\'](/api/[^"\']+)',
            r'["\'](/v\d+/[^"\']+)',
            r'fetch\(["\']([^"\']+)',
            r'axios\.[get|post|put|delete]\(["\']([^"\']+)',
            r'["\'](/graphql[^"\']*)',
            r'["\'](/rest/[^"\']+)'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html)
            api_endpoints.extend(matches)
        
        return list(set(api_endpoints))
    
    def _extract_emails(self, html: str) -> List[str]:
        """Extract email addresses."""
        email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(email_pattern, html)
        return list(set(emails))
    
    def _extract_comments(self, html: str) -> List[str]:
        """Extract HTML comments."""
        comments = []
        
        # HTML comments
        html_comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
        comments.extend([c.strip() for c in html_comments if c.strip()])
        
        # JavaScript comments (might contain sensitive info)
        js_comments = re.findall(r'//(.*)$', html, re.MULTILINE)
        comments.extend([c.strip() for c in js_comments if c.strip() and len(c.strip()) > 10])
        
        return comments