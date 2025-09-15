"""
Subdomain Enumeration Tools
backend/tools/passive_recon/subdomain_enum.py

Implements wrappers for popular subdomain enumeration tools like subfinder, assetfinder, etc.
"""

import json
from typing import Dict, List, Any
from pathlib import Path

from ..base import BaseTool, ToolConfig, ToolCategory, register_tool


class SubfinderTool(BaseTool):
    """Wrapper for Subfinder - fast subdomain discovery tool"""

    def __init__(self):
        super().__init__("subfinder", ToolCategory.PASSIVE_RECON, "subfinder")

    def build_command(self, config: ToolConfig) -> List[str]:
        """Build subfinder command"""
        command = [
            self.binary_path,
            "-d", config.target,
            "-o", f"{config.output_dir}/subdomains.txt",
            "-silent",
            "-json"
        ]

        # Add rate limiting if specified
        if config.rate_limit:
            command.extend(["-rl", str(int(config.rate_limit))])

        # Add threads if specified
        if config.threads:
            command.extend(["-t", str(config.threads)])

        # Add custom parameters
        if config.custom_params:
            if config.custom_params.get("all_sources"):
                command.append("-all")
            if config.custom_params.get("recursive"):
                command.append("-recursive")
            if config.custom_params.get("sources"):
                command.extend(["-sources", ",".join(config.custom_params["sources"])])

        return command

    def parse_output(self, stdout: str, stderr: str, output_files: List[str]) -> List[Dict[str, Any]]:
        """Parse subfinder JSON output"""
        results = []

        # Parse JSON output from stdout
        for line in stdout.strip().split('\n'):
            if line.strip():
                try:
                    data = json.loads(line)
                    results.append({
                        'type': 'subdomain',
                        'subdomain': data.get('host', ''),
                        'source': data.get('source', 'subfinder'),
                        'ip': data.get('ip', ''),
                        'discovered_by': 'subfinder'
                    })
                except json.JSONDecodeError:
                    # Fallback to plain text parsing
                    if line.strip():
                        results.append({
                            'type': 'subdomain',
                            'subdomain': line.strip(),
                            'source': 'subfinder',
                            'discovered_by': 'subfinder'
                        })

        # Also parse output files if JSON parsing failed
        if not results:
            for file_path in output_files:
                if 'subdomains.txt' in file_path:
                    try:
                        with open(file_path, 'r') as f:
                            for line in f:
                                subdomain = line.strip()
                                if subdomain:
                                    results.append({
                                        'type': 'subdomain',
                                        'subdomain': subdomain,
                                        'source': 'subfinder',
                                        'discovered_by': 'subfinder'
                                    })
                    except Exception as e:
                        self.logger.error("Error reading output file {file_path}: %s", e)

        return results


class AssetfinderTool(BaseTool):
    """Wrapper for Assetfinder - subdomain enumeration tool"""

    def __init__(self):
        super().__init__("assetfinder", ToolCategory.PASSIVE_RECON, "assetfinder")

    def build_command(self, config: ToolConfig) -> List[str]:
        """Build assetfinder command"""
        command = [
            self.binary_path,
            "--subs-only",
            config.target
        ]

        return command

    def parse_output(self, stdout: str, stderr: str, output_files: List[str]) -> List[Dict[str, Any]]:
        """Parse assetfinder output"""
        results = []

        for line in stdout.strip().split('\n'):
            subdomain = line.strip()
            if subdomain and '.' in subdomain:
                results.append({
                    'type': 'subdomain',
                    'subdomain': subdomain,
                    'source': 'assetfinder',
                    'discovered_by': 'assetfinder'
                })

        return results


class AmassEnumTool(BaseTool):
    """Wrapper for Amass enum - comprehensive subdomain enumeration"""

    def __init__(self):
        super().__init__("amass", ToolCategory.PASSIVE_RECON, "amass")

    def build_command(self, config: ToolConfig) -> List[str]:
        """Build amass enum command"""
        command = [
            self.binary_path,
            "enum",
            "-d", config.target,
            "-o", f"{config.output_dir}/amass_subdomains.txt",
            "-json", f"{config.output_dir}/amass_results.json"
        ]

        # Add passive mode for faster execution
        command.append("-passive")

        # Add timeout if specified
        if config.timeout:
            command.extend(["-timeout", str(config.timeout // 60)])  # Convert to minutes

        return command

    def parse_output(self, stdout: str, stderr: str, output_files: List[str]) -> List[Dict[str, Any]]:
        """Parse amass JSON output"""
        results = []

        # Parse JSON output file
        for file_path in output_files:
            if 'amass_results.json' in file_path:
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            try:
                                data = json.loads(line.strip())
                                results.append({
                                    'type': 'subdomain',
                                    'subdomain': data.get('name', ''),
                                    'source': data.get('source', 'amass'),
                                    'ip': ','.join(data.get('addresses', [])) if data.get('addresses') else '',
                                    'discovered_by': 'amass',
                                    'tags': data.get('tag', ''),
                                    'metadata': {
                                        'domain': data.get('domain', ''),
                                        'type': data.get('type', ''),
                                        'timestamp': data.get('timestamp', '')
                                    }
                                })
                            except json.JSONDecodeError:
                                continue
                except Exception as e:
                    self.logger.error("Error reading amass JSON output: %s", e)

        # Fallback to text output
        if not results:
            for file_path in output_files:
                if 'amass_subdomains.txt' in file_path:
                    try:
                        with open(file_path, 'r') as f:
                            for line in f:
                                subdomain = line.strip()
                                if subdomain:
                                    results.append({
                                        'type': 'subdomain',
                                        'subdomain': subdomain,
                                        'source': 'amass',
                                        'discovered_by': 'amass'
                                    })
                    except Exception as e:
                        self.logger.error("Error reading amass text output: %s", e)

        return results


class FindomainTool(BaseTool):
    """Wrapper for Findomain - fast subdomain enumeration"""

    def __init__(self):
        super().__init__("findomain", ToolCategory.PASSIVE_RECON, "findomain")

    def build_command(self, config: ToolConfig) -> List[str]:
        """Build findomain command"""
        command = [
            self.binary_path,
            "-t", config.target,
            "-o", config.output_dir,
            "-q"  # Quiet mode
        ]

        # Add rate limiting
        if config.rate_limit:
            command.extend(["--rate-limit", str(int(config.rate_limit * 1000))])  # Convert to ms

        return command

    def parse_output(self, stdout: str, stderr: str, output_files: List[str]) -> List[Dict[str, Any]]:
        """Parse findomain output"""
        results = []

        # Parse output files
        for file_path in output_files:
            if Path(file_path).suffix == '.txt':
                try:
                    with open(file_path, 'r') as f:
                        for line in f:
                            subdomain = line.strip()
                            if subdomain:
                                results.append({
                                    'type': 'subdomain',
                                    'subdomain': subdomain,
                                    'source': 'findomain',
                                    'discovered_by': 'findomain'
                                })
                except Exception as e:
                    self.logger.error("Error reading findomain output: %s", e)

        return results


# Register all subdomain enumeration tools
register_tool(SubfinderTool())
register_tool(AssetfinderTool())
register_tool(AmassEnumTool())
register_tool(FindomainTool())
