"""
Scanning service for managing scan execution and tool orchestration.
Handles scan session lifecycle, tool execution, and progress tracking.
"""

import os
import asyncio
import subprocess
import logging
import json
import tempfile
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from pathlib import Path
import uuid

from apps.scans.models import ScanSession, ScanStatus, ToolExecution, ToolStatus
from apps.targets.models import Target
from core.constants import (
    TOOL_CONFIGS, TOOL_TIMEOUTS, RECON_PHASES, 
    MAX_CONCURRENT_SCANS, TOOL_PATHS
)
from core.exceptions import (
    ScanningException, ToolNotFoundException, ToolExecutionException,
    InvalidScanConfigurationException, ScanTimeoutException,
    ConcurrentScanLimitException
)
from services.target_service import TargetService

logger = logging.getLogger(__name__)

class ScanningService:
    """
    Service for managing scan execution and tool orchestration.
    """
    
    def __init__(self):
        self.target_service = TargetService()
        self.active_scans = {}  # Track running scans
        self.tool_queues = {}   # Tool execution queues
        self.scan_results_dir = Path(os.getenv('SCAN_RESULTS_DIR', '/tmp/scan_results'))
        self.scan_results_dir.mkdir(parents=True, exist_ok=True)

    async def execute_scan_session(self, scan_session_id: str, user_id: int) -> Dict[str, Any]:
        """
        Execute a complete scan session with all configured tools and phases.
        
        Args:
            scan_session_id: ID of scan session to execute
            user_id: ID of user who initiated the scan
            
        Returns:
            dict: Execution results and summary
        """
        try:
            # Check concurrent scan limits
            if len(self.active_scans) >= MAX_CONCURRENT_SCANS:
                raise ConcurrentScanLimitException(MAX_CONCURRENT_SCANS)
            
            # Get scan session and target from database
            # Note: In actual implementation, these would be database queries
            scan_session = await self._get_scan_session(scan_session_id)
            target = await self._get_target(scan_session.target_id)
            
            if not scan_session or not target:
                raise ScanningException(f"Scan session or target not found: {scan_session_id}")
            
            # Mark scan as running
            self.active_scans[scan_session_id] = {
                'status': ScanStatus.RUNNING,
                'started_at': datetime.utcnow(),
                'current_phase': None,
                'progress': 0.0,
                'user_id': user_id
            }
            
            logger.info(f"Starting scan session {scan_session_id} for target {target.target_name}")
            
            # Generate scan configuration
            scan_config = self.target_service.generate_scan_configuration(target)
            
            # Validate scan configuration
            validation_result = self.validate_scan_config(scan_config, target)
            if not validation_result.is_valid:
                raise InvalidScanConfigurationException(validation_result.message)
            
            # Execute scan phases
            execution_results = {
                'scan_session_id': scan_session_id,
                'target_id': str(target.id),
                'started_at': datetime.utcnow(),
                'phases_executed': [],
                'tools_executed': [],
                'results_summary': {},
                'errors': []
            }
            
            total_phases = len(scan_session.methodology_phases)
            phase_progress = 0
            
            for phase_index, phase in enumerate(scan_session.methodology_phases):
                try:
                    logger.info(f"Executing phase {phase} for scan {scan_session_id}")
                    
                    # Update current phase
                    self.active_scans[scan_session_id]['current_phase'] = phase
                    
                    # Execute phase
                    phase_result = await self._execute_scan_phase(
                        scan_session_id, phase, scan_config, target
                    )
                    
                    execution_results['phases_executed'].append({
                        'phase': phase,
                        'result': phase_result,
                        'completed_at': datetime.utcnow()
                    })
                    
                    # Update progress
                    phase_progress = ((phase_index + 1) / total_phases) * 100
                    self.active_scans[scan_session_id]['progress'] = phase_progress
                    
                except Exception as e:
                    logger.error(f"Error in phase {phase} for scan {scan_session_id}: {e}")
                    execution_results['errors'].append({
                        'phase': phase,
                        'error': str(e),
                        'timestamp': datetime.utcnow()
                    })
                    # Continue with next phase unless critical error
                    if isinstance(e, ScanTimeoutException):
                        break
            
            # Complete scan
            execution_results['completed_at'] = datetime.utcnow()
            execution_results['duration_seconds'] = (
                execution_results['completed_at'] - execution_results['started_at']
            ).total_seconds()
            
            # Generate results summary
            execution_results['results_summary'] = await self._generate_results_summary(
                scan_session_id, execution_results
            )
            
            # Mark scan as completed
            if scan_session_id in self.active_scans:
                self.active_scans[scan_session_id]['status'] = ScanStatus.COMPLETED
                self.active_scans[scan_session_id]['completed_at'] = datetime.utcnow()
            
            logger.info(f"Completed scan session {scan_session_id}")
            return execution_results
            
        except Exception as e:
            logger.error(f"Error executing scan session {scan_session_id}: {e}")
            
            # Mark scan as failed
            if scan_session_id in self.active_scans:
                self.active_scans[scan_session_id]['status'] = ScanStatus.FAILED
                self.active_scans[scan_session_id]['error'] = str(e)
            
            raise ScanningException(f"Scan execution failed: {e}")
        
        finally:
            # Cleanup
            if scan_session_id in self.active_scans:
                del self.active_scans[scan_session_id]

    async def pause_scan_session(self, scan_session_id: str) -> None:
        """Pause a running scan session."""
        if scan_session_id not in self.active_scans:
            raise ScanningException(f"Scan session {scan_session_id} is not running")
        
        self.active_scans[scan_session_id]['status'] = ScanStatus.PAUSED
        self.active_scans[scan_session_id]['paused_at'] = datetime.utcnow()
        
        # Signal running tools to pause (implementation specific)
        await self._pause_running_tools(scan_session_id)
        
        logger.info(f"Paused scan session {scan_session_id}")

    async def resume_scan_session(self, scan_session_id: str, user_id: int) -> None:
        """Resume a paused scan session."""
        if scan_session_id not in self.active_scans:
            raise ScanningException(f"Scan session {scan_session_id} is not active")
        
        if self.active_scans[scan_session_id]['status'] != ScanStatus.PAUSED:
            raise ScanningException(f"Scan session {scan_session_id} is not paused")
        
        self.active_scans[scan_session_id]['status'] = ScanStatus.RUNNING
        self.active_scans[scan_session_id]['resumed_at'] = datetime.utcnow()
        
        # Resume tool execution (implementation specific)
        await self._resume_scan_execution(scan_session_id)
        
        logger.info(f"Resumed scan session {scan_session_id}")

    async def stop_scan_session(self, scan_session_id: str) -> None:
        """Stop a running or paused scan session."""
        if scan_session_id not in self.active_scans:
            return  # Already stopped
        
        # Terminate running tools
        await self._terminate_running_tools(scan_session_id)
        
        # Mark as cancelled
        self.active_scans[scan_session_id]['status'] = ScanStatus.CANCELLED
        self.active_scans[scan_session_id]['stopped_at'] = datetime.utcnow()
        
        logger.info(f"Stopped scan session {scan_session_id}")

    def calculate_scan_progress(self, scan_session: ScanSession, 
                              tool_executions: List[ToolExecution]) -> Dict[str, Any]:
        """
        Calculate real-time progress for a scan session.
        
        Args:
            scan_session: Scan session instance
            tool_executions: List of tool executions
            
        Returns:
            dict: Progress information
        """
        try:
            progress_info = {
                'scan_session_id': str(scan_session.id),
                'overall_progress': 0.0,
                'current_phase': scan_session.current_phase,
                'phase_progress': {},
                'active_tools': [],
                'completed_tools': [],
                'failed_tools': [],
                'estimated_time_remaining': None,
                'resources_discovered': {
                    'subdomains': scan_session.total_subdomains_found,
                    'endpoints': scan_session.total_endpoints_found,
                    'vulnerabilities': scan_session.total_vulnerabilities
                },
                'recent_findings': [],
                'last_updated': datetime.utcnow()
            }
            
            # Calculate phase progress
            total_phases = len(scan_session.methodology_phases)
            if total_phases > 0:
                phase_weights = self._get_phase_weights()
                completed_weight = 0.0
                total_weight = sum(phase_weights.get(phase, 1.0) for phase in scan_session.methodology_phases)
                
                for phase in scan_session.methodology_phases:
                    phase_tools = [t for t in tool_executions if t.tool_category == phase]
                    phase_completion = self._calculate_phase_completion(phase_tools)
                    progress_info['phase_progress'][phase] = phase_completion
                    
                    if phase_completion >= 100.0:
                        completed_weight += phase_weights.get(phase, 1.0)
                    elif scan_session.current_phase == phase:
                        completed_weight += (phase_completion / 100.0) * phase_weights.get(phase, 1.0)
                
                progress_info['overall_progress'] = (completed_weight / total_weight) * 100.0
            
            # Categorize tools by status
            for tool_exec in tool_executions:
                if tool_exec.status == ToolStatus.RUNNING:
                    progress_info['active_tools'].append(tool_exec.tool_name)
                elif tool_exec.status == ToolStatus.COMPLETED:
                    progress_info['completed_tools'].append(tool_exec.tool_name)
                elif tool_exec.status == ToolStatus.FAILED:
                    progress_info['failed_tools'].append(tool_exec.tool_name)
            
            # Estimate time remaining
            if scan_session.started_at and progress_info['overall_progress'] > 5.0:
                elapsed_time = (datetime.utcnow() - scan_session.started_at).total_seconds()
                estimated_total_time = elapsed_time / (progress_info['overall_progress'] / 100.0)
                progress_info['estimated_time_remaining'] = int(estimated_total_time - elapsed_time)
            
            return progress_info
            
        except Exception as e:
            logger.error(f"Error calculating scan progress: {e}")
            return {
                'scan_session_id': str(scan_session.id),
                'overall_progress': 0.0,
                'error': str(e),
                'last_updated': datetime.utcnow()
            }

    async def get_scan_results(self, scan_session_id: str, 
                             include_raw_output: bool = False) -> Dict[str, Any]:
        """
        Get comprehensive results from a completed scan session.
        
        Args:
            scan_session_id: Scan session ID
            include_raw_output: Whether to include raw tool outputs
            
        Returns:
            dict: Comprehensive scan results
        """
        try:
            # Get scan session data (database query in real implementation)
            scan_session = await self._get_scan_session(scan_session_id)
            target = await self._get_target(scan_session.target_id)
            tool_executions = await self._get_tool_executions(scan_session_id)
            
            results = {
                'scan_session_id': scan_session_id,
                'target_name': target.target_name,
                'scan_duration_seconds': None,
                'phases_completed': [],
                'tools_executed': [],
                'subdomains_discovered': scan_session.total_subdomains_found,
                'endpoints_discovered': scan_session.total_endpoints_found,
                'services_discovered': 0,  # Would be calculated from results
                'technologies_identified': [],
                'vulnerabilities_found': scan_session.total_vulnerabilities,
                'vulnerability_breakdown': {
                    'critical': scan_session.critical_vulnerabilities,
                    'high': scan_session.high_vulnerabilities,
                    'medium': 0,  # Would be calculated
                    'low': 0,     # Would be calculated
                    'info': 0     # Would be calculated
                },
                'top_vulnerability_types': [],
                'tool_results': [],
                'successful_tools': [],
                'failed_tools': [],
                'raw_output_files': {},
                'processed_results_file': None,
                'scan_completed_at': scan_session.completed_at,
                'results_generated_at': datetime.utcnow()
            }
            
            # Calculate scan duration
            if scan_session.started_at and scan_session.completed_at:
                results['scan_duration_seconds'] = (
                    scan_session.completed_at - scan_session.started_at
                ).total_seconds()
            
            # Process tool execution results
            for tool_exec in tool_executions:
                tool_result = {
                    'tool_name': tool_exec.tool_name,
                    'status': tool_exec.status.value,
                    'execution_time': tool_exec.execution_time_seconds,
                    'results_count': tool_exec.parsed_results_count,
                    'output_file': tool_exec.output_file_path
                }
                
                if include_raw_output and tool_exec.raw_output:
                    tool_result['raw_output'] = tool_exec.raw_output
                
                results['tool_results'].append(tool_result)
                
                # Categorize tools
                if tool_exec.status == ToolStatus.COMPLETED:
                    results['successful_tools'].append(tool_exec.tool_name)
                    if tool_exec.output_file_path:
                        results['raw_output_files'][tool_exec.tool_name] = tool_exec.output_file_path
                elif tool_exec.status == ToolStatus.FAILED:
                    results['failed_tools'].append(tool_exec.tool_name)
            
            # Add phases that were completed
            results['phases_completed'] = scan_session.methodology_phases
            results['tools_executed'] = [t.tool_name for t in tool_executions]
            
            return results
            
        except Exception as e:
            logger.error(f"Error getting scan results for {scan_session_id}: {e}")
            raise ScanningException(f"Failed to get scan results: {e}")

    def validate_scan_config(self, scan_config: Dict[str, Any], target: Target) -> Any:
        """
        Validate scan configuration for correctness and safety.
        
        Args:
            scan_config: Scan configuration dictionary
            target: Target instance
            
        Returns:
            ValidationResult: Validation result with is_valid and message
        """
        class ValidationResult:
            def __init__(self, is_valid: bool, message: str):
                self.is_valid = is_valid
                self.message = message
        
        try:
            # Check required fields
            required_fields = ['target_id', 'scan_config', 'tool_configs', 'rate_limiting']
            for field in required_fields:
                if field not in scan_config:
                    return ValidationResult(False, f"Missing required field: {field}")
            
            # Validate rate limiting
            rate_config = scan_config['rate_limiting']
            if rate_config['requests_per_second'] > 100:
                return ValidationResult(False, "Request rate too high (max 100/sec)")
            
            if rate_config['concurrent_requests'] > 50:
                return ValidationResult(False, "Too many concurrent requests (max 50)")
            
            # Validate tools
            for tool_name in scan_config['scan_config'].get('tools', []):
                if tool_name not in TOOL_CONFIGS:
                    return ValidationResult(False, f"Unknown tool: {tool_name}")

            return ValidationResult(True, "Scan configuration is valid")

        except KeyError as e:
            return ValidationResult(False, f"Missing configuration key: {e}")
        except Exception as e:
            return ValidationResult(False, f"Configuration validation failed: {e}")