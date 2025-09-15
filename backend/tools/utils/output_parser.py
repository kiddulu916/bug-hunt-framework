"""
Output Parser Utilities
backend/tools/utils/output_parser.py

Common utilities for parsing tool outputs and extracting structured data
"""

import re
import json
import csv
import xml.etree.ElementTree as ET
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
from urllib.parse import urlparse


class OutputParser:
    """Utility class for parsing various output formats"""

    @staticmethod
    def parse_json_lines(content: str) -> List[Dict[str, Any]]:
        """Parse JSON lines format (JSONL)"""
        results = []
        for line in content.strip().split('\n'):
            if line.strip():
                try:
                    results.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    continue
        return results

    @staticmethod
    def parse_csv_content(content: str, headers: List[str] = None) -> List[Dict[str, Any]]:
        """Parse CSV content"""
        results = []
        lines = content.strip().split('\n')

        if not lines:
            return results

        # Use provided headers or extract from first line
        if headers:
            csv_headers = headers
            data_lines = lines
        else:
            csv_headers = [h.strip() for h in lines[0].split(',')]
            data_lines = lines[1:]

        for line in data_lines:
            if line.strip():
                values = [v.strip().strip('"') for v in line.split(',')]
                if len(values) == len(csv_headers):
                    results.append(dict(zip(csv_headers, values)))

        return results

    @staticmethod
    def parse_xml_content(content: str) -> Optional[ET.Element]:
        """Parse XML content"""
        try:
            return ET.fromstring(content)
        except ET.ParseError:
            return None

    @staticmethod
    def extract_urls(content: str) -> List[str]:
        """Extract URLs from text content"""
        url_pattern = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
        return re.findall(url_pattern, content, re.IGNORECASE)

    @staticmethod
    def extract_domains(content: str) -> List[str]:
        """Extract domain names from text content"""
        domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
        domains = re.findall(domain_pattern, content)
        # Filter out common false positives
        filtered_domains = []
        for domain in domains:
            if not any(domain.endswith(ext) for ext in ['.txt', '.json', '.xml', '.log']):
                filtered_domains.append(domain)
        return list(set(filtered_domains))

    @staticmethod
    def extract_ip_addresses(content: str) -> List[str]:
        """Extract IP addresses from text content"""
        ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        return list(set(re.findall(ip_pattern, content)))

    @staticmethod
    def extract_ports(content: str) -> List[int]:
        """Extract port numbers from text content"""
        port_pattern = r':(\d{1,5})\b'
        ports = re.findall(port_pattern, content)
        return [int(p) for p in ports if 1 <= int(p) <= 65535]

    @staticmethod
    def extract_emails(content: str) -> List[str]:
        """Extract email addresses from text content"""
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        return list(set(re.findall(email_pattern, content)))

    @staticmethod
    def parse_nmap_xml(xml_content: str) -> List[Dict[str, Any]]:
        """Parse Nmap XML output"""
        results = []
        try:
            root = ET.fromstring(xml_content)
            for host in root.findall('host'):
                host_data = OutputParser._parse_nmap_host(host)
                if host_data:
                    results.append(host_data)
        except ET.ParseError:
            pass
        return results

    @staticmethod
    def _parse_nmap_host(host_elem: ET.Element) -> Optional[Dict[str, Any]]:
        """Parse individual Nmap host element"""
        # Get IP address
        address_elem = host_elem.find('address[@addrtype="ipv4"]')
        if address_elem is None:
            address_elem = host_elem.find('address[@addrtype="ipv6"]')

        if address_elem is None:
            return None

        host_data = {
            'ip': address_elem.get('addr'),
            'hostnames': [],
            'ports': [],
            'os': None
        }

        # Get hostnames
        hostnames_elem = host_elem.find('hostnames')
        if hostnames_elem is not None:
            for hostname in hostnames_elem.findall('hostname'):
                host_data['hostnames'].append(hostname.get('name'))

        # Get OS information
        os_elem = host_elem.find('os')
        if os_elem is not None:
            osmatch = os_elem.find('osmatch')
            if osmatch is not None:
                host_data['os'] = osmatch.get('name')

        # Get ports
        ports_elem = host_elem.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                port_data = {
                    'port': int(port.get('portid')),
                    'protocol': port.get('protocol'),
                    'state': port.find('state').get('state'),
                    'service': None,
                    'version': None
                }

                service_elem = port.find('service')
                if service_elem is not None:
                    port_data['service'] = service_elem.get('name')
                    port_data['version'] = service_elem.get('version')

                host_data['ports'].append(port_data)

        return host_data

    @staticmethod
    def parse_gobuster_output(content: str) -> List[Dict[str, Any]]:
        """Parse Gobuster directory/file enumeration output"""
        results = []
        lines = content.strip().split('\n')

        for line in lines:
            line = line.strip()
            if line.startswith('/') and '(Status:' in line:
                # Extract path and status code
                parts = line.split('(Status:')
                if len(parts) >= 2:
                    path = parts[0].strip()
                    status_part = parts[1].split(')')[0].strip()

                    # Extract size if available
                    size = None
                    if '[Size:' in line:
                        size_match = re.search(r'\[Size:\s*(\d+)\]', line)
                        if size_match:
                            size = int(size_match.group(1))

                    results.append({
                        'type': 'directory',
                        'path': path,
                        'status_code': int(status_part),
                        'size': size
                    })

        return results

    @staticmethod
    def parse_ffuf_output(content: str) -> List[Dict[str, Any]]:
        """Parse FFUF fuzzing output"""
        results = []

        # Try to parse as JSON first
        try:
            data = json.loads(content)
            if 'results' in data:
                for result in data['results']:
                    results.append({
                        'type': 'fuzzing_result',
                        'url': result.get('url', ''),
                        'status_code': result.get('status', 0),
                        'length': result.get('length', 0),
                        'words': result.get('words', 0),
                        'lines': result.get('lines', 0),
                        'input': result.get('input', {}),
                        'position': result.get('position', 0)
                    })
            return results
        except json.JSONDecodeError:
            pass

        # Fallback to text parsing
        lines = content.strip().split('\n')
        for line in lines:
            if ':: Progress:' in line or line.startswith('Status:'):
                continue

            # Parse standard FFUF output format
            parts = line.split()
            if len(parts) >= 6 and parts[0].isdigit():
                results.append({
                    'type': 'fuzzing_result',
                    'status_code': int(parts[0]),
                    'size': int(parts[1]) if parts[1].isdigit() else 0,
                    'words': int(parts[2]) if parts[2].isdigit() else 0,
                    'lines': int(parts[3]) if parts[3].isdigit() else 0,
                    'url': parts[-1] if parts[-1].startswith('http') else ''
                })

        return results

    @staticmethod
    def parse_waybackurls_output(content: str) -> List[Dict[str, Any]]:
        """Parse waybackurls output"""
        results = []
        urls = content.strip().split('\n')

        for url in urls:
            url = url.strip()
            if url and url.startswith('http'):
                parsed = urlparse(url)
                results.append({
                    'type': 'archived_url',
                    'url': url,
                    'domain': parsed.netloc,
                    'path': parsed.path,
                    'query': parsed.query,
                    'fragment': parsed.fragment
                })

        return results

    @staticmethod
    def normalize_severity(severity: str) -> str:
        """Normalize severity levels across different tools"""
        severity = severity.lower().strip()

        severity_mapping = {
            'critical': 'critical',
            'crit': 'critical',
            'high': 'high',
            'medium': 'medium',
            'med': 'medium',
            'low': 'low',
            'info': 'info',
            'informational': 'info',
            'unknown': 'info'
        }

        return severity_mapping.get(severity, 'info')

    @staticmethod
    def extract_cve_ids(content: str) -> List[str]:
        """Extract CVE identifiers from text"""
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        return list(set(re.findall(cve_pattern, content, re.IGNORECASE)))

    @staticmethod
    def extract_cwe_ids(content: str) -> List[str]:
        """Extract CWE identifiers from text"""
        cwe_pattern = r'CWE-\d{1,4}'
        return list(set(re.findall(cwe_pattern, content, re.IGNORECASE)))

    @staticmethod
    def parse_file_by_extension(file_path: str) -> List[Dict[str, Any]]:
        """Parse file based on its extension"""
        path = Path(file_path)

        if not path.exists():
            return []

        try:
            content = path.read_text(encoding='utf-8', errors='ignore')
        except Exception:
            return []

        extension = path.suffix.lower()

        if extension == '.json':
            try:
                data = json.loads(content)
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    return [data]
            except json.JSONDecodeError:
                return OutputParser.parse_json_lines(content)

        elif extension == '.xml':
            return OutputParser.parse_nmap_xml(content)

        elif extension == '.csv':
            return OutputParser.parse_csv_content(content)

        elif extension in ['.txt', '.log']:
            # Try to detect format based on content
            if 'Status:' in content and ('Length:' in content or 'Size:' in content):
                return OutputParser.parse_gobuster_output(content)
            elif content.startswith('http') and '\n' in content:
                return OutputParser.parse_waybackurls_output(content)
            else:
                # Generic text parsing - extract domains, IPs, URLs
                results = []
                urls = OutputParser.extract_urls(content)
                domains = OutputParser.extract_domains(content)
                ips = OutputParser.extract_ip_addresses(content)
                emails = OutputParser.extract_emails(content)

                for url in urls:
                    results.append({'type': 'url', 'value': url})
                for domain in domains:
                    results.append({'type': 'domain', 'value': domain})
                for ip in ips:
                    results.append({'type': 'ip', 'value': ip})
                for email in emails:
                    results.append({'type': 'email', 'value': email})

                return results

        return []
