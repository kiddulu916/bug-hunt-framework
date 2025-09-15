"""
Target management service.
Provides target validation, scope management, and configuration generation.
"""

import re
import logging
import ipaddress
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any, Tuple
from urllib.parse import urlparse, urljoin
from datetime import datetime
import socket
import ssl

from apps.targets.models import Target, BugBountyPlatform
from core.exceptions import (
    InvalidTargetException,
    OutOfScopeException,
    TargetException
)
from core.constants import (
    TOOL_CONFIGS,
    BUG_BOUNTY_PLATFORMS,
    DEFAULT_REQUESTS_PER_SECOND,
    DEFAULT_CONCURRENT_REQUESTS
)

logger = logging.getLogger(__name__)

class TargetService:
    """
    Service for target management, validation, and configuration.
    """
    
    def __init__(self):
        self.scope_cache = {}  # Cache for scope validation results
        self.connectivity_cache = {}  # Cache for connectivity test results
        self.cache_timeout = 300  # 5 minutes

    def validate_scope(self, in_scope_urls: List[str], out_of_scope_urls: List[str]) -> Dict[str, Any]:
        """
        Validate scope configuration for conflicts and issues.
        
        Args:
            in_scope_urls: List of in-scope URL patterns
            out_of_scope_urls: List of out-of-scope URL patterns
            
        Returns:
            dict: Validation result with is_valid and message
        """
        try:
            validation_result = {
                'is_valid': True,
                'message': 'Scope configuration is valid',
                'warnings': [],
                'conflicts': []
            }
            
            # Check for empty scope
            if not in_scope_urls:
                validation_result['is_valid'] = False
                validation_result['message'] = 'At least one in-scope URL pattern is required'
                return validation_result
            
            # Validate URL patterns
            for url_pattern in in_scope_urls:
                if not self._validate_url_pattern(url_pattern):
                    validation_result['warnings'].append(f'Invalid in-scope URL pattern: {url_pattern}')
            
            for url_pattern in out_of_scope_urls:
                if not self._validate_url_pattern(url_pattern):
                    validation_result['warnings'].append(f'Invalid out-of-scope URL pattern: {url_pattern}')
            
            # Check for conflicts between in-scope and out-of-scope
            conflicts = self._find_scope_conflicts(in_scope_urls, out_of_scope_urls)
            if conflicts:
                validation_result['conflicts'] = conflicts
                validation_result['warnings'].extend([f'Scope conflict: {c}' for c in conflicts])
            
            # Check for overly broad patterns
            broad_patterns = self._find_broad_patterns(in_scope_urls)
            if broad_patterns:
                validation_result['warnings'].extend([
                    f'Broad scope pattern detected: {p}' for p in broad_patterns
                ])
            
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating scope: {e}")
            return {
                'is_valid': False,
                'message': f'Scope validation error: {e}',
                'warnings': [],
                'conflicts': []
            }

    def validate_asset_scope(self, asset_url: str, in_scope_urls: List[str],
                           out_of_scope_urls: List[str], in_scope_assets: List[str],
                           out_of_scope_assets: List[str]) -> Dict[str, Any]:
        """
        Validate if an asset URL is within the defined scope.
        
        Args:
            asset_url: URL/asset to validate
            in_scope_urls: In-scope URL patterns
            out_of_scope_urls: Out-of-scope URL patterns
            in_scope_assets: In-scope asset patterns
            out_of_scope_assets: Out-of-scope asset patterns
            
        Returns:
            dict: Validation result with scope determination
        """
        try:
            cache_key = f"{asset_url}:{hash(str(sorted(in_scope_urls + out_of_scope_urls)))}"
            
            # Check cache
            if cache_key in self.scope_cache:
                cached_result = self.scope_cache[cache_key]
                if (datetime.utcnow() - cached_result['timestamp']).seconds < self.cache_timeout:
                    return cached_result['result']
            
            validation_result = {
                'asset_url': asset_url,
                'is_valid': False,
                'is_in_scope': False,
                'is_out_of_scope': False,
                'matching_patterns': [],
                'validation_reason': '',
                'recommendations': []
            }
            
            # Parse URL for analysis
            parsed_url = urlparse(asset_url)
            if not parsed_url.netloc:
                validation_result['validation_reason'] = 'Invalid URL format'
                return validation_result
            
            # Check out-of-scope first (takes precedence)
            out_scope_matches = self._match_patterns(
                asset_url, out_of_scope_urls + out_of_scope_assets
            )
            
            if out_scope_matches:
                validation_result['is_out_of_scope'] = True
                validation_result['matching_patterns'] = out_scope_matches
                validation_result['validation_reason'] = 'Asset matches out-of-scope patterns'
                validation_result['recommendations'].append('Asset is explicitly out of scope')
                
                # Cache result
                self.scope_cache[cache_key] = {
                    'result': validation_result,
                    'timestamp': datetime.utcnow()
                }
                return validation_result
            
            # Check in-scope patterns
            in_scope_matches = self._match_patterns(
                asset_url, in_scope_urls + in_scope_assets
            )
            
            if in_scope_matches:
                validation_result['is_valid'] = True
                validation_result['is_in_scope'] = True
                validation_result['matching_patterns'] = in_scope_matches
                validation_result['validation_reason'] = 'Asset matches in-scope patterns'
            else:
                validation_result['validation_reason'] = 'Asset does not match any in-scope patterns'
                validation_result['recommendations'].append('Verify asset is intended to be in scope')
            
            # Additional recommendations
            if self._is_likely_test_environment(asset_url):
                validation_result['recommendations'].append('Asset appears to be a test environment')
            
            if self._is_high_risk_endpoint(asset_url):
                validation_result['recommendations'].append('High-risk endpoint detected - proceed with caution')
            
            # Cache result
            self.scope_cache[cache_key] = {
                'result': validation_result,
                'timestamp': datetime.utcnow()
            }
            
            return validation_result
            
        except Exception as e:
            logger.error(f"Error validating asset scope for {asset_url}: {e}")
            return {
                'asset_url': asset_url,
                'is_valid': False,
                'is_in_scope': False,
                'is_out_of_scope': False,
                'matching_patterns': [],
                'validation_reason': f'Validation error: {e}',
                'recommendations': ['Manual verification recommended']
            }

    def generate_scan_configuration(self, target: Target) -> Dict[str, Any]:
        """
        Generate scan configuration based on target settings.
        
        Args:
            target: Target instance
            
        Returns:
            dict: Comprehensive scan configuration
        """
        try:
            config = {
                'target_id': str(target.id),
                'target_name': target.target_name,
                'platform': target.platform.value,
                'main_url': target.main_url,
                'scan_config': {
                    'phases': ['passive_recon', 'active_recon', 'vulnerability_testing'],
                    'tools': list(TOOL_CONFIGS.keys()),
                    'depth': 'comprehensive'
                },
                'tool_configs': self._generate_tool_configs(target),
                'rate_limiting': {
                    'requests_per_second': target.requests_per_second,
                    'concurrent_requests': target.concurrent_requests,
                    'delay_ms': target.request_delay_ms
                },
                'authentication': {
                    'type': 'headers' if target.authentication_headers else 'none',
                    'headers': target.authentication_headers or {}
                },
                'scope_rules': {
                    'in_scope': target.in_scope_urls + target.in_scope_assets,
                    'out_of_scope': target.out_of_scope_urls + target.out_of_scope_assets
                },
                'http_config': {
                    'user_agents': target.user_agents,
                    'required_headers': target.required_headers,
                    'follow_redirects': True,
                    'verify_ssl': True
                },
                'special_instructions': self._generate_special_instructions(target)
            }
            
            # Platform-specific adjustments
            config = self._apply_platform_specific_config(config, target.platform)
            
            return config
            
        except Exception as e:
            logger.error(f"Error generating scan configuration for target {target.id}: {e}")
            raise InvalidTargetException(f"Failed to generate scan configuration: {e}")

    async def test_connectivity(self, url: str, timeout: int = 10) -> Dict[str, Any]:
        """
        Test connectivity to a target URL.
        
        Args:
            url: URL to test
            timeout: Request timeout in seconds
            
        Returns:
            dict: Connectivity test results
        """
        try:
            # Check cache
            cache_key = url
            if cache_key in self.connectivity_cache:
                cached_result = self.connectivity_cache[cache_key]
                if (datetime.utcnow() - cached_result['timestamp']).seconds < self.cache_timeout:
                    return cached_result['result']
            
            start_time = datetime.utcnow()
            
            result = {
                'url': url,
                'is_reachable': False,
                'response_time_ms': None,
                'status_code': None,
                'response_headers': {},
                'error_message': None,
                'ssl_info': None,
                'dns_resolution': None,
                'tested_at': start_time
            }
            
            # Parse URL
            parsed_url = urlparse(url)
            if not parsed_url.netloc:
                result['error_message'] = 'Invalid URL format'
                return result
            
            # DNS resolution test
            try:
                dns_info = await self._resolve_dns(parsed_url.netloc)
                result['dns_resolution'] = dns_info
            except Exception as e:
                result['error_message'] = f'DNS resolution failed: {e}'
                return result
            
            # HTTP connectivity test
            try:
                async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=timeout)) as session:
                    request_start = datetime.utcnow()
                    
                    async with session.get(url, allow_redirects=False) as response:
                        request_end = datetime.utcnow()
                        
                        result['is_reachable'] = True
                        result['response_time_ms'] = (request_end - request_start).total_seconds() * 1000
                        result['status_code'] = response.status
                        result['response_headers'] = dict(response.headers)
                        
                        # SSL information for HTTPS
                        if parsed_url.scheme == 'https':
                            ssl_info = await self._get_ssl_info(parsed_url.netloc, 443)
                            result['ssl_info'] = ssl_info
            
            except asyncio.TimeoutError:
                result['error_message'] = f'Request timed out after {timeout} seconds'
            except aiohttp.ClientError as e:
                result['error_message'] = f'HTTP client error: {e}'
            except Exception as e:
                result['error_message'] = f'Unexpected error: {e}'
            
            # Cache result
            self.connectivity_cache[cache_key] = {
                'result': result,
                'timestamp': datetime.utcnow()
            }
            
            return result
            
        except Exception as e:
            logger.error(f"Error testing connectivity to {url}: {e}")
            return {
                'url': url,
                'is_reachable': False,
                'error_message': f'Connectivity test error: {e}',
                'tested_at': datetime.utcnow()
            }

    # Private helper methods

    def _validate_url_pattern(self, pattern: str) -> bool:
        """Validate URL pattern format."""
        try:
            # Basic URL validation
            if not pattern or len(pattern) < 3:
                return False
            
            # Check for valid URL schemes
            if '://' in pattern:
                parsed = urlparse(pattern)
                if parsed.scheme not in ['http', 'https']:
                    return False
                if not parsed.netloc:
                    return False
            
            # Check for wildcard patterns
            if '*' in pattern:
                # Ensure wildcards are in valid positions
                if pattern.count('*') > 3:  # Too many wildcards
                    return False
            
            return True
            
        except Exception:
            return False

    def _find_scope_conflicts(self, in_scope: List[str], out_of_scope: List[str]) -> List[str]:
        """Find conflicts between in-scope and out-of-scope patterns."""
        conflicts = []
        
        for in_pattern in in_scope:
            for out_pattern in out_of_scope:
                if self._patterns_conflict(in_pattern, out_pattern):
                    conflicts.append(f'{in_pattern} conflicts with {out_pattern}')
        
        return conflicts

    def _patterns_conflict(self, pattern1: str, pattern2: str) -> bool:
        """Check if two URL patterns conflict."""
        # Simplified conflict detection - exact matches
        if pattern1 == pattern2:
            return True
        
        # Check for subdomain conflicts
        p1_clean = pattern1.replace('*', '').replace('https://', '').replace('http://', '')
        p2_clean = pattern2.replace('*', '').replace('https://', '').replace('http://', '')
        
        if p1_clean in p2_clean or p2_clean in p1_clean:
            return True
        
        return False

    def _find_broad_patterns(self, patterns: List[str]) -> List[str]:
        """Find overly broad scope patterns."""
        broad_patterns = []
        
        for pattern in patterns:
            # Check for very broad wildcards
            if pattern.count('*') > 2:
                broad_patterns.append(pattern)
            
            # Check for top-level domain wildcards
            if pattern.startswith('*'):
                broad_patterns.append(pattern)
            
            # Check for path wildcards that might be too broad
            if pattern.endswith('/*') and pattern.count('/') <= 2:
                broad_patterns.append(pattern)
        
        return broad_patterns

    def _match_patterns(self, asset_url: str, patterns: List[str]) -> List[str]:
        """Match asset URL against list of patterns."""
        matches = []
        
        for pattern in patterns:
            if self._url_matches_pattern(asset_url, pattern):
                matches.append(pattern)
        
        return matches

    def _url_matches_pattern(self, url: str, pattern: str) -> bool:
        """Check if URL matches a specific pattern."""
        try:
            # Handle IP address patterns
            if self._is_ip_pattern(pattern):
                return self._match_ip_pattern(url, pattern)
            
            # Handle domain patterns
            if self._is_domain_pattern(pattern):
                return self._match_domain_pattern(url, pattern)
            
            # Handle URL patterns
            return self._match_url_pattern(url, pattern)
            
        except Exception as e:
            logger.warning(f"Error matching URL {url} against pattern {pattern}: {e}")
            return False

    def _is_ip_pattern(self, pattern: str) -> bool:
        """Check if pattern is an IP address or IP range."""
        try:
            # Check for CIDR notation
            if '/' in pattern:
                ipaddress.ip_network(pattern, strict=False)
                return True
            
            # Check for single IP
            ipaddress.ip_address(pattern)
            return True
            
        except ValueError:
            return False

    def _is_domain_pattern(self, pattern: str) -> bool:
        """Check if pattern is a domain pattern (no protocol)."""
        return '://' not in pattern and not self._is_ip_pattern(pattern)

    def _match_ip_pattern(self, url: str, pattern: str) -> bool:
        """Match URL against IP pattern."""
        try:
            parsed_url = urlparse(url)
            host = parsed_url.netloc.split(':')[0]  # Remove port
            
            # Try to resolve hostname to IP if needed
            try:
                host_ip = socket.gethostbyname(host)
            except socket.gaierror:
                host_ip = host
            
            if '/' in pattern:
                # CIDR notation
                network = ipaddress.ip_network(pattern, strict=False)
                return ipaddress.ip_address(host_ip) in network
            else:
                # Single IP
                return host_ip == pattern
                
        except Exception:
            return False

    def _match_domain_pattern(self, url: str, pattern: str) -> bool:
        """Match URL against domain pattern."""
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.split(':')[0].lower()
            pattern_lower = pattern.lower()
            
            # Exact match
            if domain == pattern_lower:
                return True
            
            # Wildcard subdomain match
            if pattern_lower.startswith('*.'):
                base_domain = pattern_lower[2:]
                return domain.endswith('.' + base_domain) or domain == base_domain
            
            # Suffix match for subdomains
            if domain.endswith('.' + pattern_lower):
                return True
            
            return False
            
        except Exception:
            return False

    def _match_url_pattern(self, url: str, pattern: str) -> bool:
        """Match URL against full URL pattern."""
        try:
            # Convert pattern to regex
            regex_pattern = self._pattern_to_regex(pattern)
            return bool(re.match(regex_pattern, url, re.IGNORECASE))
            
        except Exception:
            return False

    def _pattern_to_regex(self, pattern: str) -> str:
        """Convert URL pattern with wildcards to regex."""
        # Escape special regex characters except *
        escaped = re.escape(pattern)
        
        # Replace escaped * with regex equivalent
        regex_pattern = escaped.replace(r'\*', '.*')
        
        # Ensure pattern matches from start
        if not regex_pattern.startswith('^'):
            regex_pattern = '^' + regex_pattern
        
        return regex_pattern

    def _is_likely_test_environment(self, url: str) -> bool:
        """Check if URL appears to be a test environment."""
        test_indicators = [
            'test', 'testing', 'dev', 'development', 'staging', 'stage',
            'demo', 'sandbox', 'qa', 'uat', 'localhost', '127.0.0.1'
        ]
        
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in test_indicators)

    def _is_high_risk_endpoint(self, url: str) -> bool:
        """Check if URL appears to be a high-risk endpoint."""
        high_risk_indicators = [
            '/admin', '/administrator', '/wp-admin', '/panel',
            '/api', '/upload', '/file', '/backup', '/config'
        ]
        
        url_lower = url.lower()
        return any(indicator in url_lower for indicator in high_risk_indicators)

    def _generate_tool_configs(self, target: Target) -> Dict[str, Dict[str, Any]]:
        """Generate tool-specific configurations."""
        tool_configs = {}
        
        for tool_name, base_config in TOOL_CONFIGS.items():
            tool_config = base_config.copy()
            
            # Apply target-specific rate limiting
            if tool_name in ['httpx', 'nuclei', 'gobuster']:
                tool_config['rate_limit'] = target.requests_per_second
                tool_config['threads'] = target.concurrent_requests
            
            # Apply authentication if available
            if target.authentication_headers and tool_name in ['httpx', 'nuclei']:
                tool_config['headers'] = target.authentication_headers
            
            # Platform-specific adjustments
            if target.platform == BugBountyPlatform.HACKERONE:
                # More conservative settings for HackerOne
                tool_config['timeout'] = tool_config.get('timeout', 30) * 2
            
            tool_configs[tool_name] = tool_config
        
        return tool_configs

    def _generate_special_instructions(self, target: Target) -> List[str]:
        """Generate special instructions based on target configuration."""
        instructions = []
        
        if target.special_requirements:
            instructions.append(f"Special requirements: {target.special_requirements}")
        
        if target.program_notes:
            instructions.append(f"Program notes: {target.program_notes}")
        
        # Rate limiting warnings
        if target.requests_per_second > 10:
            instructions.append("High request rate configured - monitor for rate limiting")
        
        if target.requests_per_second < 1:
            instructions.append("Very conservative request rate - scans may take longer")
        
        # Authentication instructions
        if target.authentication_headers:
            instructions.append("Authentication headers configured - use for authenticated scanning")
        
        # Scope instructions
        if len(target.out_of_scope_urls) > len(target.in_scope_urls):
            instructions.append("Large exclusion list - verify scope carefully")
        
        return instructions

    def _apply_platform_specific_config(self, config: Dict[str, Any], 
                                      platform: BugBountyPlatform) -> Dict[str, Any]:
        """Apply platform-specific configuration adjustments."""
        platform_configs = {
            BugBountyPlatform.HACKERONE: {
                'conservative_mode': True,
                'max_threads': 5,
                'respect_robots_txt': True
            },
            BugBountyPlatform.BUGCROWD: {
                'conservative_mode': True,
                'max_threads': 10,
                'respect_robots_txt': True
            },
            BugBountyPlatform.INTIGRITI: {
                'conservative_mode': False,
                'max_threads': 15,
                'respect_robots_txt': False
            },
            BugBountyPlatform.PRIVATE: {
                'conservative_mode': False,
                'max_threads': 20,
                'respect_robots_txt': False
            }
        }
        
        platform_config = platform_configs.get(platform, {})
        
        if platform_config.get('conservative_mode'):
            # Reduce scan aggressiveness
            config['rate_limiting']['requests_per_second'] = min(
                config['rate_limiting']['requests_per_second'], 5.0
            )
            config['rate_limiting']['concurrent_requests'] = min(
                config['rate_limiting']['concurrent_requests'], 
                platform_config.get('max_threads', 10)
            )
        
        config['platform_specific'] = platform_config
        
        return config

    async def _resolve_dns(self, hostname: str) -> Dict[str, Any]:
        """Resolve DNS information for hostname."""
        try:
            loop = asyncio.get_event_loop()
            
            # Get address info
            addr_info = await loop.getaddrinfo(hostname, None)
            
            ipv4_addresses = []
            ipv6_addresses = []
            
            for family, type, proto, canonname, sockaddr in addr_info:
                if family == socket.AF_INET:
                    ipv4_addresses.append(sockaddr[0])
                elif family == socket.AF_INET6:
                    ipv6_addresses.append(sockaddr[0])
            
            return {
                'hostname': hostname,
                'ipv4_addresses': list(set(ipv4_addresses)),
                'ipv6_addresses': list(set(ipv6_addresses)),
                'resolved_at': datetime.utcnow()
            }
            
        except Exception as e:
            raise Exception(f"DNS resolution failed: {e}")

    async def _get_ssl_info(self, hostname: str, port: int) -> Dict[str, Any]:
        """Get SSL certificate information."""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate info
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'valid': True,
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'signature_algorithm': cert.get('signatureAlgorithm'),
                        'protocol': ssock.version(),
                        'cipher': ssock.cipher()
                    }
                    
                    # Check if certificate is expired
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    ssl_info['is_expired'] = not_after < datetime.utcnow()
                    ssl_info['expires_in_days'] = (not_after - datetime.utcnow()).days
                    
                    return ssl_info
                    
        except Exception as e:
            return {
                'valid': False,
                'error': str(e),
                'checked_at': datetime.utcnow()
            }
            