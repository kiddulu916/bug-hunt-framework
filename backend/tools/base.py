"""
Base Tool Framework for Bug Bounty Automation Platform
backend/tools/base.py

Provides abstract base classes and common functionality for all penetration testing tools.
Enhanced for Docker architecture with container-based tool execution.
"""

import subprocess
import uuid
import logging
import os
import docker
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict
from enum import Enum
from django.conf import settings

logger = logging.getLogger(__name__)


class ToolStatus(Enum):
    """Tool execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class ToolCategory(Enum):
    """Tool categories for organization"""
    PASSIVE_RECON = "passive_recon"
    ACTIVE_RECON = "active_recon"
    VULNERABILITY_TESTING = "vulnerability_testing"
    EXPLOITATION = "exploitation"
    UTILITY = "utility"


@dataclass
class ToolResult:
    """Standardized tool execution result"""
    tool_name: str
    status: ToolStatus
    exit_code: int
    stdout: str
    stderr: str
    execution_time: float
    output_files: List[str]
    parsed_results: List[Dict[str, Any]]
    error_message: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = asdict(self)
        result['status'] = self.status.value
        return result


@dataclass
class ToolConfig:
    """Tool configuration parameters"""
    target: str
    output_dir: str
    rate_limit: Optional[float] = None
    timeout: Optional[int] = None
    threads: Optional[int] = None
    custom_params: Optional[Dict[str, Any]] = None
    scope_urls: Optional[List[str]] = None
    out_of_scope_urls: Optional[List[str]] = None


class BaseTool(ABC):
    """
    Abstract base class for all penetration testing tools.

    Provides common functionality for tool execution, output handling,
    rate limiting, and result parsing.
    """

    def __init__(self, name: str, category: ToolCategory, binary_path: str = None):
        self.name = name
        self.category = category
        self.binary_path = binary_path or name
        self.logger = logging.getLogger(f'tools.{name}')
        self.execution_id = str(uuid.uuid4())

    @abstractmethod
    def build_command(self, config: ToolConfig) -> List[str]:
        """Build the command to execute the tool"""
        pass

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str, output_files: List[str]) -> List[Dict[str, Any]]:
        """Parse tool output into structured data"""
        pass

    def validate_target(self, target: str, scope_urls: List[str] = None) -> bool:
        """Validate if target is in scope"""
        if not scope_urls:
            return True

        from urllib.parse import urlparse
        try:
            target_domain = urlparse(target if target.startswith(('http://', 'https://')) else f'http://{target}').netloc
            for scope_url in scope_urls:
                scope_domain = urlparse(scope_url).netloc
                if target_domain == scope_domain or target_domain.endswith(f'.{scope_domain}'):
                    return True
            return False
        except Exception as e:
            self.logger.warning("Target validation error: %s", e)
            return False

    def setup_output_directory(self, base_dir: str) -> str:
        """Create and return tool-specific output directory"""
        output_dir = Path(base_dir) / self.name / self.execution_id
        output_dir.mkdir(parents=True, exist_ok=True)
        return str(output_dir)

    def execute(self, config: ToolConfig) -> ToolResult:
        """
        Execute the tool with given configuration (Docker-aware)

        Args:
            config: ToolConfig object with execution parameters

        Returns:
            ToolResult object with execution results and parsed data
        """
        # Check if running in Docker mode
        if getattr(settings, 'BUG_BOUNTY_SETTINGS', {}).get('DOCKER_MODE', False):
            return self._execute_docker(config)
        else:
            return self._execute_local(config)

    def _execute_local(self, config: ToolConfig) -> ToolResult:
        """Execute tool locally (legacy method)"""
        start_time = datetime.now()
        self.logger.info(f"Starting {self.name} execution for target: {config.target}")

        # Validate target scope
        if not self.validate_target(config.target, config.scope_urls):
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.FAILED,
                exit_code=-1,
                stdout="",
                stderr="Target not in scope",
                execution_time=0.0,
                output_files=[],
                parsed_results=[],
                error_message="Target validation failed: not in scope"
            )

        # Setup output directory
        output_dir = self.setup_output_directory(config.output_dir)
        config.output_dir = output_dir

        # Build command
        try:
            command = self.build_command(config)
            self.logger.debug("Executing command: %s", ' '.join(command))
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.FAILED,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=0.0,
                output_files=[],
                parsed_results=[],
                error_message=f"Command building failed: {e}"
            )

        # Execute command
        try:
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=config.timeout or 3600,  # Default 1 hour timeout
                cwd=output_dir
            )

            execution_time = (datetime.now() - start_time).total_seconds()

            # Find output files
            output_files = []
            for file_path in Path(output_dir).glob('*'):
                if file_path.is_file():
                    output_files.append(str(file_path))

            # Parse results
            try:
                parsed_results = self.parse_output(process.stdout, process.stderr, output_files)
            except Exception as e:
                self.logger.error("Output parsing failed: %s", e)
                parsed_results = []

            # Determine status
            if process.returncode == 0:
                status = ToolStatus.COMPLETED
                error_message = None
            else:
                status = ToolStatus.FAILED
                error_message = f"Tool exited with code {process.returncode}"

            result = ToolResult(
                tool_name=self.name,
                status=status,
                exit_code=process.returncode,
                stdout=process.stdout,
                stderr=process.stderr,
                execution_time=execution_time,
                output_files=output_files,
                parsed_results=parsed_results,
                error_message=error_message,
                metadata={
                    'execution_id': self.execution_id,
                    'command': ' '.join(command),
                    'output_directory': output_dir
                }
            )

            self.logger.info("{self.name} completed in {execution_time:.2f}s with %s results", len(parsed_results))
            return result

        except subprocess.TimeoutExpired:
            execution_time = (datetime.now() - start_time).total_seconds()
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.TIMEOUT,
                exit_code=-1,
                stdout="",
                stderr="Tool execution timed out",
                execution_time=execution_time,
                output_files=[],
                parsed_results=[],
                error_message=f"Tool execution timed out after {config.timeout}s"
            )

        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error("Tool execution failed: %s", e)
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.FAILED,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                output_files=[],
                parsed_results=[],
                error_message=f"Execution failed: {e}"
            )

    def _execute_docker(self, config: ToolConfig) -> ToolResult:
        """Execute tool in Docker container"""
        start_time = datetime.now()
        self.logger.info(f"Starting {self.name} Docker execution for target: {config.target}")

        # Validate target scope
        if not self.validate_target(config.target, config.scope_urls):
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.FAILED,
                exit_code=-1,
                stdout="",
                stderr="Target not in scope",
                execution_time=0.0,
                output_files=[],
                parsed_results=[],
                error_message="Target validation failed: not in scope"
            )

        # Setup output directory (host path)
        output_dir = self.setup_output_directory(config.output_dir)
        config.output_dir = output_dir

        # Build command
        try:
            command = self.build_command(config)
            self.logger.debug("Executing Docker command: %s", ' '.join(command))
        except Exception as e:
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.FAILED,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=0.0,
                output_files=[],
                parsed_results=[],
                error_message=f"Command building failed: {e}"
            )

        # Execute in Docker container
        try:
            client = docker.from_env()
            container_name = getattr(settings, 'BUG_BOUNTY_SETTINGS', {}).get('TOOLS_CONTAINER_NAME', 'bugbounty_tools')

            # Get tools container
            try:
                container = client.containers.get(container_name)
            except docker.errors.NotFound:
                return ToolResult(
                    tool_name=self.name,
                    status=ToolStatus.FAILED,
                    exit_code=-1,
                    stdout="",
                    stderr=f"Tools container '{container_name}' not found",
                    execution_time=0.0,
                    output_files=[],
                    parsed_results=[],
                    error_message="Docker tools container not available"
                )

            # Execute command in container
            exec_result = container.exec_run(
                cmd=command,
                workdir='/app/scan_results',
                environment={
                    'TARGET': config.target,
                    'OUTPUT_DIR': '/app/scan_results'
                }
            )

            execution_time = (datetime.now() - start_time).total_seconds()

            # Decode output
            stdout = exec_result.output.decode('utf-8') if exec_result.output else ""
            stderr = ""
            exit_code = exec_result.exit_code

            # Find output files
            output_files = []
            try:
                for file_path in Path(output_dir).glob('*'):
                    if file_path.is_file():
                        output_files.append(str(file_path))
            except Exception as e:
                self.logger.warning(f"Error scanning output directory: {e}")

            # Parse results
            try:
                parsed_results = self.parse_output(stdout, stderr, output_files)
            except Exception as e:
                self.logger.error("Output parsing failed: %s", e)
                parsed_results = []

            # Determine status
            if exit_code == 0:
                status = ToolStatus.COMPLETED
                error_message = None
            else:
                status = ToolStatus.FAILED
                error_message = f"Tool exited with code {exit_code}"

            result = ToolResult(
                tool_name=self.name,
                status=status,
                exit_code=exit_code,
                stdout=stdout,
                stderr=stderr,
                execution_time=execution_time,
                output_files=output_files,
                parsed_results=parsed_results,
                error_message=error_message,
                metadata={
                    'execution_id': self.execution_id,
                    'command': ' '.join(command),
                    'output_directory': output_dir,
                    'container_name': container_name,
                    'execution_mode': 'docker'
                }
            )

            self.logger.info(f"{self.name} completed in {execution_time:.2f}s with {len(parsed_results)} results")
            return result

        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error("Docker tool execution failed: %s", e)
            return ToolResult(
                tool_name=self.name,
                status=ToolStatus.FAILED,
                exit_code=-1,
                stdout="",
                stderr=str(e),
                execution_time=execution_time,
                output_files=[],
                parsed_results=[],
                error_message=f"Docker execution failed: {e}"
            )

    def get_version(self) -> Optional[str]:
        """Get tool version if available"""
        try:
            result = subprocess.run(
                [self.binary_path, '--version'],
                capture_output=True,
                text=True,
                timeout=10
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None

    def is_available(self) -> bool:
        """Check if tool binary is available"""
        try:
            subprocess.run(
                [self.binary_path, '--help'],
                capture_output=True,
                timeout=10
            )
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            return False


class ToolRegistry:
    """Registry for managing available tools"""

    def __init__(self):
        self._tools: Dict[str, BaseTool] = {}
        self._categories: Dict[ToolCategory, List[str]] = {category: [] for category in ToolCategory}

    def register(self, tool: BaseTool) -> None:
        """Register a tool"""
        self._tools[tool.name] = tool
        self._categories[tool.category].append(tool.name)
        logger.info("Registered tool: {tool.name} (%s)", tool.category.value)

    def get_tool(self, name: str) -> Optional[BaseTool]:
        """Get tool by name"""
        return self._tools.get(name)

    def get_tools_by_category(self, category: ToolCategory) -> List[BaseTool]:
        """Get all tools in a category"""
        return [self._tools[name] for name in self._categories[category] if name in self._tools]

    def list_available_tools(self) -> Dict[str, List[str]]:
        """List all available tools grouped by category"""
        available = {}
        for category, tool_names in self._categories.items():
            available_tools = []
            for name in tool_names:
                tool = self._tools[name]
                if tool.is_available():
                    available_tools.append(name)
            available[category.value] = available_tools
        return available

    def get_tool_info(self, name: str) -> Optional[Dict[str, Any]]:
        """Get detailed tool information"""
        tool = self.get_tool(name)
        if not tool:
            return None

        return {
            'name': tool.name,
            'category': tool.category.value,
            'binary_path': tool.binary_path,
            'available': tool.is_available(),
            'version': tool.get_version(),
        }


# Global tool registry instance
tool_registry = ToolRegistry()


def register_tool(tool: BaseTool) -> None:
    """Register a tool with the global registry"""
    tool_registry.register(tool)


def get_tool(name: str) -> Optional[BaseTool]:
    """Get a tool from the global registry"""
    return tool_registry.get_tool(name)


def list_tools() -> Dict[str, List[str]]:
    """List all available tools"""
    return tool_registry.list_available_tools()
