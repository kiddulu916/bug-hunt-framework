"""
Port Scanning Tools
backend/tools/active_recon/port_scanning.py

Implements wrappers for port scanning tools like nmap, masscan, etc.
"""

import json
import xml.etree.ElementTree as ET
from typing import Dict, List, Any

from ..base import BaseTool, ToolConfig, ToolCategory, register_tool


class NmapTool(BaseTool):
    """Wrapper for Nmap - network discovery and security auditing"""

    def __init__(self):
        super().__init__("nmap", ToolCategory.ACTIVE_RECON, "nmap")

    def build_command(self, config: ToolConfig) -> List[str]:
        """Build nmap command"""
        command = [
            self.binary_path,
            config.target,
            "-oX", f"{config.output_dir}/nmap_scan.xml",
            "-oN", f"{config.output_dir}/nmap_scan.txt",
            "--stats-every", "30s"
        ]

        # Default scan type
        scan_type = (
            config.custom_params.get("scan_type", "default") 
            if config.custom_params else "default"
        )

        if scan_type == "quick":
            command.extend(["-T4", "-F"])  # Fast scan, common ports only
        elif scan_type == "comprehensive":
            command.extend(["-T4", "-A", "-p-"])  # All ports, OS detection, scripts
        elif scan_type == "stealth":
            command.extend(["-sS", "-T2"])  # SYN scan, slower timing
        elif scan_type == "udp":
            command.extend(["-sU", "--top-ports", "1000"])  # UDP scan
        else:
            command.extend(["-T4", "--top-ports", "1000"])  # Default scan

        # Add service detection
        if (
            config.custom_params and 
            config.custom_params.get("service_detection", True)
        ):
            command.append("-sV")

        # Add OS detection
        if (
            config.custom_params and 
            config.custom_params.get("os_detection", False)
        ):
            command.append("-O")

        # Add script scanning
        if (
            config.custom_params and 
            config.custom_params.get("scripts", False)
        ):
            command.extend(["--script", "default,safe"])

        # Add timing if specified
        if config.custom_params and "timing" in config.custom_params:
            command.extend(["-T", str(config.custom_params["timing"])])

        return command

    def parse_output(self, stdout: str, stderr: str, output_files: List[str]) -> List[Dict[str, Any]]:
        """Parse nmap XML output"""
        results = []

        # Parse XML output
        for file_path in output_files:
            if 'nmap_scan.xml' in file_path:
                try:
                    tree = ET.parse(file_path)
                    root = tree.getroot()

                    for host in root.findall('host'):
                        # Get host address
                        address_elem = host.find('address[@addrtype="ipv4"]')
                        if address_elem is None:
                            address_elem = host.find('address[@addrtype="ipv6"]')

                        if address_elem is not None:
                            host_ip = address_elem.get('addr')

                            # Get hostname if available
                            hostname = ""
                            hostnames = host.find('hostnames')
                            if hostnames is not None:
                                hostname_elem = hostnames.find('hostname')
                                if hostname_elem is not None:
                                    hostname = hostname_elem.get('name', '')

                            # Get OS information
                            os_info = ""
                            os_elem = host.find('os')
                            if os_elem is not None:
                                osmatch = os_elem.find('osmatch')
                                if osmatch is not None:
                                    os_info = osmatch.get('name', '')

                            # Parse ports
                            ports_elem = host.find('ports')
                            if ports_elem is not None:
                                for port in ports_elem.findall('port'):
                                    port_id = port.get('portid')
                                    protocol = port.get('protocol')

                                    state_elem = port.find('state')
                                    state = state_elem.get('state') if state_elem is not None else 'unknown'

                                    service_elem = port.find('service')
                                    service_name = service_elem.get('name', '') if service_elem is not None else ''
                                    service_version = service_elem.get('version', '') if service_elem is not None else ''
                                    service_product = service_elem.get('product', '') if service_elem is not None else ''

                                    # Get script results
                                    scripts = []
                                    for script in port.findall('script'):
                                        scripts.append({
                                            'id': script.get('id'),
                                            'output': script.get('output', '')
                                        })

                                    results.append({
                                        'type': 'port',
                                        'host': host_ip,
                                        'hostname': hostname,
                                        'port': int(port_id),
                                        'protocol': protocol,
                                        'state': state,
                                        'service': service_name,
                                        'version': service_version,
                                        'product': service_product,
                                        'os': os_info,
                                        'scripts': scripts,
                                        'discovered_by': 'nmap'
                                    })
                            else:
                                # Host is up but no ports found
                                results.append({
                                    'type': 'host',
                                    'host': host_ip,
                                    'hostname': hostname,
                                    'state': 'up',
                                    'os': os_info,
                                    'discovered_by': 'nmap'
                                })

                except ET.ParseError as e:
                    self.logger.error("Error parsing nmap XML output: %s", e)
                except Exception as e:
                    self.logger.error("Error processing nmap output: %s", e)

        return results


class MasscanTool(BaseTool):
    """Wrapper for Masscan - fast port scanner"""

    def __init__(self):
        super().__init__("masscan", ToolCategory.ACTIVE_RECON, "masscan")

    def build_command(self, config: ToolConfig) -> List[str]:
        """Build masscan command"""
        command = [
            self.binary_path,
            config.target,
            "-oJ", f"{config.output_dir}/masscan_results.json",
            "-oX", f"{config.output_dir}/masscan_results.xml"
        ]

        # Default port range
        ports = config.custom_params.get("ports", "1-65535") if config.custom_params else "1-1000"
        command.extend(["-p", ports])

        # Rate limiting
        rate = config.rate_limit if config.rate_limit else 1000
        command.extend(["--rate", str(int(rate))])

        # Add other options
        if config.custom_params:
            if config.custom_params.get("banner_grab", False):
                command.append("--banners")

        return command

    def parse_output(self, stdout: str, stderr: str, output_files: List[str]) -> List[Dict[str, Any]]:
        """Parse masscan JSON output"""
        results = []

        # Parse JSON output
        for file_path in output_files:
            if 'masscan_results.json' in file_path:
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            if line.strip() and not line.strip().startswith('#'):
                                try:
                                    data = json.loads(line.strip().rstrip(','))
                                    if 'ports' in data:
                                        for port_info in data['ports']:
                                            results.append({
                                                'type': 'port',
                                                'host': data.get('ip', ''),
                                                'port': port_info.get('port', 0),
                                                'protocol': port_info.get('proto', ''),
                                                'state': port_info.get('status', 'open'),
                                                'service': port_info.get('service', {}).get('name', '') if 'service' in port_info else '',
                                                'banner': port_info.get('service', {}).get('banner', '') if 'service' in port_info else '',
                                                'discovered_by': 'masscan'
                                            })
                                except json.JSONDecodeError:
                                    continue
                except Exception as e:
                    self.logger.error("Error reading masscan output: %s", e)

        return results


class RustScanTool(BaseTool):
    """Wrapper for RustScan - fast port scanner"""

    def __init__(self):
        super().__init__("rustscan", ToolCategory.ACTIVE_RECON, "rustscan")

    def build_command(self, config: ToolConfig) -> List[str]:
        """Build rustscan command"""
        command = [
            self.binary_path,
            "-a", config.target,
            "--format", "json"
        ]

        # Batch size for speed
        if config.custom_params and "batch_size" in config.custom_params:
            command.extend(["-b", str(config.custom_params["batch_size"])])
        else:
            command.extend(["-b", "1000"])

        # Timeout
        if config.timeout:
            command.extend(["-t", str(config.timeout * 1000)])  # Convert to ms

        # Port range
        if config.custom_params and "ports" in config.custom_params:
            command.extend(["-p", config.custom_params["ports"]])

        return command

    def parse_output(self, stdout: str, stderr: str, output_files: List[str]) -> List[Dict[str, Any]]:
        """Parse rustscan JSON output"""
        results = []

        try:
            # RustScan outputs JSON to stdout
            for line in stdout.strip().split('\n'):
                if line.strip() and line.startswith('{'):
                    try:
                        data = json.loads(line)
                        if 'ips' in data:
                            for ip_data in data['ips']:
                                host = ip_data.get('Ip', '')
                                for port in ip_data.get('ports', []):
                                    results.append({
                                        'type': 'port',
                                        'host': host,
                                        'port': port,
                                        'protocol': 'tcp',  # RustScan default
                                        'state': 'open',
                                        'discovered_by': 'rustscan'
                                    })
                    except json.JSONDecodeError:
                        continue
        except Exception as e:
            self.logger.error("Error parsing rustscan output: %s", e)

        return results


# Register all port scanning tools
register_tool(NmapTool())
register_tool(MasscanTool())
register_tool(RustScanTool())
