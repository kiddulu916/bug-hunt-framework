"""
Scan Orchestrator Module
========================

Main orchestration engine for coordinating all scanning activities according to
OWASP testing methodology phases. Manages workflow execution, progress tracking,
and coordination between different scanning engines.
"""

import asyncio
import json
import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Union
from queue import Queue, PriorityQueue

from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

# Import custom exceptions
from . import (
    ScannerException,
    ConfigurationError,
    ToolExecutionError,
    ScopeValidationError,
    RateLimitExceeded
)


# Scan Phase Enumeration
class ScanPhase(Enum):
    """Enumeration of scan phases following OWASP methodology."""
    INITIALIZATION = "initialization"
    PASSIVE_RECON = "passive_recon"
    ACTIVE_RECON = "active_recon"
    VULNERABILITY_TESTING = "vulnerability_testing"
    EXPLOITATION = "exploitation"
    REPORTING = "reporting"
    CLEANUP = "cleanup"
    COMPLETED = "completed"
    FAILED = "failed"


# Scan Priority Levels
class ScanPriority(Enum):
    """Priority levels for scan scheduling."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    BACKGROUND = 5


# Scan Status
class ScanStatus(Enum):
    """Status of scan execution."""
    QUEUED = "queued"
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class ScanContext:
    """Container for scan execution context and state."""
    scan_id: str
    target_id: str
    scan_type: str
    phases: List[ScanPhase]
    current_phase: ScanPhase = ScanPhase.INITIALIZATION
    status: ScanStatus = ScanStatus.QUEUED
    priority: ScanPriority = ScanPriority.MEDIUM
    config: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[Dict[str, Any]] = field(default_factory=list)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    progress: float = 0.0
    message: str = ""
    retry_count: int = 0
    max_retries: int = 3


class ScanOrchestrator:
    """
    Main orchestrator for managing and executing security scans.
    Coordinates different scanning engines and manages workflow execution.
    """
    
    def __init__(self, target_id: str, config: Dict[str, Any], db_session: Session = None):
        """
        Initialize the scan orchestrator.
        
        Args:
            target_id: UUID of the target to scan
            config: Configuration dictionary
            db_session: SQLAlchemy database session
        """
        self.target_id = target_id
        self.config = config
        self.db_session = db_session
        self.logger = logging.getLogger(__name__)
        
        # Initialize scan context
        self.scan_context = ScanContext(
            scan_id=str(uuid.uuid4()),
            target_id=target_id,
            scan_type=config.get('scan_type', 'full'),
            phases=self._determine_scan_phases(config),
            config=config
        )
        
        # Initialize phase handlers
        self.phase_handlers = self._initialize_phase_handlers()
        
        # Initialize thread pool for parallel operations
        self.executor = ThreadPoolExecutor(
            max_workers=config.get('max_workers', 10)
        )
        
        # Initialize progress tracking
        self.progress_tracker = ProgressTracker(self.scan_context)
        
        # Initialize rate limiter
        self.rate_limiter = RateLimiter(config.get('rate_limit', {}))
        
        # Initialize workflow manager
        self.workflow_manager = WorkflowManager(self.scan_context, config)
        
        # Initialize scan scheduler if needed
        self.scheduler = None
        if config.get('enable_scheduler', False):
            self.scheduler = ScanScheduler(self)
    
    def _determine_scan_phases(self, config: Dict[str, Any]) -> List[ScanPhase]:
        """
        Determine which scan phases to execute based on configuration.
        
        Args:
            config: Scan configuration
            
        Returns:
            List of scan phases to execute
        """
        scan_type = config.get('scan_type', 'full')
        
        if scan_type == 'full':
            return [
                ScanPhase.INITIALIZATION,
                ScanPhase.PASSIVE_RECON,
                ScanPhase.ACTIVE_RECON,
                ScanPhase.VULNERABILITY_TESTING,
                ScanPhase.EXPLOITATION,
                ScanPhase.REPORTING,
                ScanPhase.CLEANUP
            ]
        elif scan_type == 'recon_only':
            return [
                ScanPhase.INITIALIZATION,
                ScanPhase.PASSIVE_RECON,
                ScanPhase.ACTIVE_RECON,
                ScanPhase.REPORTING,
                ScanPhase.CLEANUP
            ]
        elif scan_type == 'vulnerability_only':
            return [
                ScanPhase.INITIALIZATION,
                ScanPhase.VULNERABILITY_TESTING,
                ScanPhase.REPORTING,
                ScanPhase.CLEANUP
            ]
        elif scan_type == 'custom':
            phases = [ScanPhase.INITIALIZATION]
            custom_phases = config.get('custom_phases', [])
            for phase_name in custom_phases:
                try:
                    phases.append(ScanPhase(phase_name))
                except ValueError:
                    self.logger.warning(f"Invalid phase name: {phase_name}")
            phases.extend([ScanPhase.REPORTING, ScanPhase.CLEANUP])
            return phases
        else:
            raise ConfigurationError(f"Unknown scan type: {scan_type}")
    
    def _initialize_phase_handlers(self) -> Dict[ScanPhase, Callable]:
        """
        Initialize handlers for each scan phase.
        
        Returns:
            Dictionary mapping phases to handler functions
        """
        return {
            ScanPhase.INITIALIZATION: self._handle_initialization,
            ScanPhase.PASSIVE_RECON: self._handle_passive_recon,
            ScanPhase.ACTIVE_RECON: self._handle_active_recon,
            ScanPhase.VULNERABILITY_TESTING: self._handle_vulnerability_testing,
            ScanPhase.EXPLOITATION: self._handle_exploitation,
            ScanPhase.REPORTING: self._handle_reporting,
            ScanPhase.CLEANUP: self._handle_cleanup,
        }
    
    async def execute_scan(self) -> Dict[str, Any]:
        """
        Execute the complete scan workflow asynchronously.
        
        Returns:
            Dictionary containing scan results
        """
        self.logger.info(f"Starting scan {self.scan_context.scan_id} for target {self.target_id}")
        
        try:
            # Update scan status
            self.scan_context.status = ScanStatus.INITIALIZING
            self.scan_context.start_time = datetime.utcnow()
            self._update_scan_session()
            
            # Execute each phase in sequence
            for phase in self.scan_context.phases:
                if self.scan_context.status == ScanStatus.CANCELLED:
                    self.logger.info(f"Scan {self.scan_context.scan_id} cancelled")
                    break
                
                await self._execute_phase(phase)
                
                # Check for critical errors
                if self._has_critical_errors():
                    self.logger.error(f"Critical error in phase {phase.value}, aborting scan")
                    self.scan_context.status = ScanStatus.FAILED
                    break
            
            # Finalize scan
            if self.scan_context.status != ScanStatus.FAILED:
                self.scan_context.status = ScanStatus.COMPLETED
            
            self.scan_context.end_time = datetime.utcnow()
            self._update_scan_session()
            
            self.logger.info(f"Scan {self.scan_context.scan_id} completed with status {self.scan_context.status.value}")
            
            return self._prepare_final_results()
            
        except Exception as e:
            self.logger.error(f"Unexpected error in scan execution: {str(e)}", exc_info=True)
            self.scan_context.status = ScanStatus.FAILED
            self.scan_context.errors.append({
                'phase': self.scan_context.current_phase.value,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
            self._update_scan_session()
            raise ScannerException(f"Scan execution failed: {str(e)}")
    
    async def _execute_phase(self, phase: ScanPhase):
        """
        Execute a single scan phase.
        
        Args:
            phase: The scan phase to execute
        """
        self.logger.info(f"Executing phase: {phase.value}")
        self.scan_context.current_phase = phase
        self.scan_context.status = ScanStatus.RUNNING
        self._update_scan_session()
        
        handler = self.phase_handlers.get(phase)
        if not handler:
            self.logger.warning(f"No handler found for phase {phase.value}")
            return
        
        try:
            # Apply rate limiting
            await self.rate_limiter.acquire()
            
            # Execute phase handler
            phase_results = await handler()
            
            # Store phase results
            self.scan_context.results[phase.value] = phase_results
            
            # Update progress
            self.progress_tracker.update_phase_progress(phase, 100)
            
        except Exception as e:
            self.logger.error(f"Error in phase {phase.value}: {str(e)}", exc_info=True)
            self.scan_context.errors.append({
                'phase': phase.value,
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat()
            })
            
            # Retry logic
            if self.scan_context.retry_count < self.scan_context.max_retries:
                self.scan_context.retry_count += 1
                self.logger.info(f"Retrying phase {phase.value} (attempt {self.scan_context.retry_count})")
                await asyncio.sleep(5 * self.scan_context.retry_count)  # Exponential backoff
                await self._execute_phase(phase)
            else:
                raise
    
    async def _handle_initialization(self) -> Dict[str, Any]:
        """
        Handle initialization phase.
        
        Returns:
            Initialization results
        """
        self.logger.info("Initializing scan environment")
        
        results = {
            'phase': 'initialization',
            'timestamp': datetime.utcnow().isoformat(),
            'checks': {}
        }
        
        # Validate target scope
        from .utils import ScopeValidator
        scope_validator = ScopeValidator(self.config.get('scope', {}))
        is_valid, reason = scope_validator.validate_target(self.target_id)
        results['checks']['scope_validation'] = {
            'valid': is_valid,
            'reason': reason
        }
        
        if not is_valid:
            raise ScopeValidationError(f"Target out of scope: {reason}")
        
        # Check tool availability
        from .utils import ToolExecutor
        tool_executor = ToolExecutor()
        tools_status = tool_executor.check_tools_availability(
            self.config.get('required_tools', [])
        )
        results['checks']['tools_availability'] = tools_status
        
        # Initialize working directories
        import os
        work_dir = f"/tmp/scans/{self.scan_context.scan_id}"
        os.makedirs(work_dir, exist_ok=True)
        results['work_directory'] = work_dir
        self.scan_context.metadata['work_dir'] = work_dir
        
        # Load target information from database
        if self.db_session:
            from .db_interfaces import TargetManager
            target_manager = TargetManager(self.db_session, self.logger)
            target_info = target_manager.get_target_info(self.target_id)
            results['target_info'] = target_info
            self.scan_context.metadata['target'] = target_info
        
        return results
    
    async def _handle_passive_recon(self) -> Dict[str, Any]:
        """
        Handle passive reconnaissance phase.
        
        Returns:
            Passive recon results
        """
        self.logger.info("Starting passive reconnaissance")
        
        from .recon_engine import ReconEngine
        recon_engine = ReconEngine(
            target_id=self.target_id,
            config=self.config.get('passive_recon', {}),
            db_session=self.db_session
        )
        
        results = {
            'phase': 'passive_recon',
            'timestamp': datetime.utcnow().isoformat(),
            'discoveries': {}
        }
        
        # Perform subdomain enumeration
        if self.config.get('passive_recon', {}).get('subdomain_enum', True):
            subdomains = await recon_engine.enumerate_subdomains_passive()
            results['discoveries']['subdomains'] = subdomains
            self.progress_tracker.update_task_progress('subdomain_enumeration', 100)
        
        # Perform OSINT gathering
        if self.config.get('passive_recon', {}).get('osint', True):
            osint_data = await recon_engine.gather_osint()
            results['discoveries']['osint'] = osint_data
            self.progress_tracker.update_task_progress('osint_gathering', 100)
        
        # Technology profiling
        if self.config.get('passive_recon', {}).get('tech_profiling', True):
            tech_stack = await recon_engine.profile_technology_passive()
            results['discoveries']['technology'] = tech_stack
            self.progress_tracker.update_task_progress('tech_profiling', 100)
        
        # Store results in database
        if self.db_session:
            from .db_interfaces import ReconResultManager
            recon_manager = ReconResultManager(self.db_session, self.logger)
            recon_manager.store_passive_recon_results(
                self.scan_context.scan_id,
                results['discoveries']
            )
        
        return results
    
    async def _handle_active_recon(self) -> Dict[str, Any]:
        """
        Handle active reconnaissance phase.
        
        Returns:
            Active recon results
        """
        self.logger.info("Starting active reconnaissance")
        
        from .recon_engine import ReconEngine
        recon_engine = ReconEngine(
            target_id=self.target_id,
            config=self.config.get('active_recon', {}),
            db_session=self.db_session
        )
        
        results = {
            'phase': 'active_recon',
            'timestamp': datetime.utcnow().isoformat(),
            'discoveries': {}
        }
        
        # Get targets from passive recon
        passive_results = self.scan_context.results.get('passive_recon', {})
        targets = passive_results.get('discoveries', {}).get('subdomains', [])
        
        if not targets and self.scan_context.metadata.get('target'):
            targets = [self.scan_context.metadata['target'].get('domain')]
        
        # Port scanning
        if self.config.get('active_recon', {}).get('port_scan', True):
            port_results = await recon_engine.scan_ports(targets)
            results['discoveries']['ports'] = port_results
            self.progress_tracker.update_task_progress('port_scanning', 100)
        
        # Service identification
        if self.config.get('active_recon', {}).get('service_detection', True):
            services = await recon_engine.identify_services(port_results)
            results['discoveries']['services'] = services
            self.progress_tracker.update_task_progress('service_detection', 100)
        
        # Web crawling and sitemap generation
        if self.config.get('active_recon', {}).get('web_crawl', True):
            web_assets = await recon_engine.crawl_web_assets(targets)
            results['discoveries']['web_assets'] = web_assets
            self.progress_tracker.update_task_progress('web_crawling', 100)
        
        # Screenshot capture
        if self.config.get('active_recon', {}).get('screenshots', True):
            screenshots = await recon_engine.capture_screenshots(targets)
            results['discoveries']['screenshots'] = screenshots
            self.progress_tracker.update_task_progress('screenshot_capture', 100)
        
        # Store results in database
        if self.db_session:
            from .db_interfaces import ReconResultManager
            recon_manager = ReconResultManager(self.db_session, self.logger)
            recon_manager.store_active_recon_results(
                self.scan_context.scan_id,
                results['discoveries']
            )
        
        return results
    
    async def _handle_vulnerability_testing(self) -> Dict[str, Any]:
        """
        Handle vulnerability testing phase.
        
        Returns:
            Vulnerability testing results
        """
        self.logger.info("Starting vulnerability testing")
        
        from .vulnerability_scanner import VulnerabilityScanner
        vuln_scanner = VulnerabilityScanner(
            target_id=self.target_id,
            config=self.config.get('vulnerability_testing', {}),
            db_session=self.db_session
        )
        
        results = {
            'phase': 'vulnerability_testing',
            'timestamp': datetime.utcnow().isoformat(),
            'vulnerabilities': []
        }
        
        # Gather targets from recon phases
        targets = self._gather_testing_targets()
        
        # Run automated scanners in parallel
        scan_tasks = []
        
        # Nuclei scanning
        if self.config.get('vulnerability_testing', {}).get('nuclei', True):
            scan_tasks.append(vuln_scanner.run_nuclei_scan(targets))
        
        # Custom vulnerability checks
        if self.config.get('vulnerability_testing', {}).get('custom_checks', True):
            scan_tasks.append(vuln_scanner.run_custom_checks(targets))
        
        # Fuzzing
        if self.config.get('vulnerability_testing', {}).get('fuzzing', True):
            scan_tasks.append(vuln_scanner.run_fuzzing(targets))
        
        # Execute all scanning tasks
        scan_results = await asyncio.gather(*scan_tasks, return_exceptions=True)
        
        # Process and consolidate results
        for scan_result in scan_results:
            if isinstance(scan_result, Exception):
                self.logger.error(f"Scan task failed: {str(scan_result)}")
                continue
            if scan_result:
                results['vulnerabilities'].extend(scan_result)
        
        # Deduplicate and prioritize findings
        results['vulnerabilities'] = self._deduplicate_vulnerabilities(
            results['vulnerabilities']
        )
        
        # Calculate CVSS scores
        for vuln in results['vulnerabilities']:
            vuln['cvss_score'] = self._calculate_cvss_score(vuln)
        
        # Sort by severity
        results['vulnerabilities'].sort(
            key=lambda x: x.get('cvss_score', 0),
            reverse=True
        )
        
        # Store results in database
        if self.db_session:
            from .db_interfaces import VulnerabilityManager
            vuln_manager = VulnerabilityManager(self.db_session, self.logger)
            for vuln in results['vulnerabilities']:
                vuln_manager.store_vulnerability(
                    self.scan_context.scan_id,
                    vuln
                )
        
        self.progress_tracker.update_task_progress('vulnerability_scanning', 100)
        
        return results
    
    async def _handle_exploitation(self) -> Dict[str, Any]:
        """
        Handle exploitation phase for vulnerability verification.
        
        Returns:
            Exploitation results
        """
        self.logger.info("Starting exploitation phase")
        
        from .exploitation_engine import ExploitationEngine
        exploit_engine = ExploitationEngine(
            target_id=self.target_id,
            config=self.config.get('exploitation', {}),
            db_session=self.db_session
        )
        
        results = {
            'phase': 'exploitation',
            'timestamp': datetime.utcnow().isoformat(),
            'exploited_vulnerabilities': [],
            'proof_of_concepts': []
        }
        
        # Get high-priority vulnerabilities for exploitation
        vuln_results = self.scan_context.results.get('vulnerability_testing', {})
        vulnerabilities = vuln_results.get('vulnerabilities', [])
        
        # Filter for exploitable vulnerabilities
        exploitable = [
            v for v in vulnerabilities
            if v.get('cvss_score', 0) >= self.config.get('exploitation', {}).get('min_cvss', 7.0)
            and v.get('exploitable', True)
        ]
        
        self.logger.info(f"Found {len(exploitable)} potentially exploitable vulnerabilities")
        
        for vuln in exploitable[:self.config.get('exploitation', {}).get('max_exploits', 10)]:
            try:
                # Verify vulnerability
                verification_result = await exploit_engine.verify_vulnerability(vuln)
                
                if verification_result['verified']:
                    # Generate proof of concept
                    poc = await exploit_engine.generate_poc(vuln, verification_result)
                    
                    results['exploited_vulnerabilities'].append({
                        'vulnerability': vuln,
                        'verification': verification_result,
                        'poc': poc,
                        'impact': await exploit_engine.assess_impact(vuln, verification_result)
                    })
                    results['proof_of_concepts'].append(poc)
                    
                    # Store exploitation results
                    if self.db_session:
                        from .db_interfaces import VulnerabilityManager
                        vuln_manager = VulnerabilityManager(self.db_session, self.logger)
                        vuln_manager.update_vulnerability_exploitation(
                            vuln['id'],
                            verification_result,
                            poc
                        )
                
            except Exception as e:
                self.logger.error(f"Failed to exploit vulnerability {vuln.get('id')}: {str(e)}")
                continue
        
        self.progress_tracker.update_task_progress('exploitation', 100)
        
        return results
    
    async def _handle_reporting(self) -> Dict[str, Any]:
        """
        Handle report generation phase.
        
        Returns:
            Reporting results
        """
        self.logger.info("Starting report generation")
        
        from .report_generator import ReportGenerator
        report_gen = ReportGenerator(
            scan_id=self.scan_context.scan_id,
            config=self.config.get('reporting', {}),
            db_session=self.db_session
        )
        
        results = {
            'phase': 'reporting',
            'timestamp': datetime.utcnow().isoformat(),
            'reports': []
        }
        
        # Generate technical report
        if self.config.get('reporting', {}).get('technical_report', True):
            tech_report = await report_gen.generate_technical_report(
                self.scan_context.results
            )
            results['reports'].append({
                'type': 'technical',
                'format': 'markdown',
                'content': tech_report,
                'path': f"{self.scan_context.metadata['work_dir']}/technical_report.md"
            })
        
        # Generate executive summary
        if self.config.get('reporting', {}).get('executive_summary', True):
            exec_summary = await report_gen.generate_executive_summary(
                self.scan_context.results
            )
            results['reports'].append({
                'type': 'executive',
                'format': 'pdf',
                'content': exec_summary,
                'path': f"{self.scan_context.metadata['work_dir']}/executive_summary.pdf"
            })
        
        # Generate bug bounty reports
        if self.config.get('reporting', {}).get('bug_bounty_format', False):
            exploited = self.scan_context.results.get('exploitation', {}).get('exploited_vulnerabilities', [])
            for vuln_data in exploited:
                bb_report = await report_gen.generate_bug_bounty_report(vuln_data)
                results['reports'].append({
                    'type': 'bug_bounty',
                    'format': 'markdown',
                    'vulnerability': vuln_data['vulnerability']['id'],
                    'content': bb_report,
                    'path': f"{self.scan_context.metadata['work_dir']}/bb_report_{vuln_data['vulnerability']['id']}.md"
                })
        
        # Store reports in database
        if self.db_session:
            from .db_interfaces import ReportManager
            report_manager = ReportManager(self.db_session, self.logger)
            for report in results['reports']:
                report_manager.store_report(
                    self.scan_context.scan_id,
                    report
                )
        
        self.progress_tracker.update_task_progress('reporting', 100)
        
        return results
    
    async def _handle_cleanup(self) -> Dict[str, Any]:
        """
        Handle cleanup phase.
        
        Returns:
            Cleanup results
        """
        self.logger.info("Starting cleanup phase")
        
        results = {
            'phase': 'cleanup',
            'timestamp': datetime.utcnow().isoformat(),
            'actions': []
        }
        
        # Clean up temporary files
        if self.config.get('cleanup', {}).get('remove_temp_files', True):
            import shutil
            work_dir = self.scan_context.metadata.get('work_dir')
            if work_dir and work_dir.startswith('/tmp/'):
                try:
                    shutil.rmtree(work_dir)
                    results['actions'].append(f"Removed temporary directory: {work_dir}")
                except Exception as e:
                    self.logger.error(f"Failed to remove temp directory: {str(e)}")
        
        # Close connections
        self.executor.shutdown(wait=True)
        results['actions'].append("Closed thread pool executor")
        
        # Final database updates
        if self.db_session:
            try:
                self.db_session.commit()
                results['actions'].append("Committed final database changes")
            except SQLAlchemyError as e:
                self.logger.error(f"Database commit failed: {str(e)}")
                self.db_session.rollback()
        
        return results
    
    def _gather_testing_targets(self) -> List[Dict[str, Any]]:
        """
        Gather all targets for vulnerability testing from recon results.
        
        Returns:
            List of testing targets
        """
        targets = []
        
        # Get passive recon results
        passive_results = self.scan_context.results.get('passive_recon', {})
        subdomains = passive_results.get('discoveries', {}).get('subdomains', [])
        
        # Get active recon results
        active_results = self.scan_context.results.get('active_recon', {})
        services = active_results.get('discoveries', {}).get('services', [])
        web_assets = active_results.get('discoveries', {}).get('web_assets', [])
        
        # Consolidate targets
        for subdomain in subdomains:
            targets.append({
                'type': 'domain',
                'value': subdomain,
                'source': 'passive_recon'
            })
        
        for service in services:
            targets.append({
                'type': 'service',
                'value': service,
                'source': 'active_recon'
            })
        
        for asset in web_assets:
            targets.append({
                'type': 'web_asset',
                'value': asset,
                'source': 'active_recon'
            })
        
        return targets
    
    def _deduplicate_vulnerabilities(self, vulnerabilities: List[Dict]) -> List[Dict]:
        """
        Deduplicate vulnerability findings.
        
        Args:
            vulnerabilities: List of vulnerability dictionaries
            
        Returns:
            Deduplicated list of vulnerabilities
        """
        seen = set()
        unique = []
        
        for vuln in vulnerabilities:
            # Create unique key based on vulnerability characteristics
            key = (
                vuln.get('type'),
                vuln.get('target'),
                vuln.get('parameter', ''),
                vuln.get('cwe_id', '')
            )
            
            if key not in seen:
                seen.add(key)
                unique.append(vuln)
            else:
                # Merge evidence if duplicate
                for existing in unique:
                    if (existing.get('type') == vuln.get('type') and
                        existing.get('target') == vuln.get('target')):
                        existing.setdefault('evidence', []).extend(
                            vuln.get('evidence', [])
                        )
                        break
        
        return unique
    
    def _calculate_cvss_score(self, vulnerability: Dict) -> float:
        """
        Calculate CVSS score for a vulnerability.
        
        Args:
            vulnerability: Vulnerability dictionary
            
        Returns:
            CVSS score
        """
        # Simplified CVSS calculation - should use proper CVSS library in production
        severity_scores = {
            'critical': 9.5,
            'high': 8.5,
            'medium': 5.5,
            'low': 3.0,
            'info': 0.0
        }
        
        severity = vulnerability.get('severity', 'medium').lower()
        base_score = severity_scores.get(severity, 5.0)
        
        # Adjust based on exploitability
        if vulnerability.get('exploitable'):
            base_score += 0.5
        
        # Adjust based on authentication required
        if not vulnerability.get('auth_required', True):
            base_score += 0.5
        
        return min(10.0, base_score)
    
    def _has_critical_errors(self) -> bool:
        """
        Check if there are critical errors that should stop the scan.
        
        Returns:
            True if critical errors exist
        """
        critical_error_types = [
            'scope_violation',
            'rate_limit_exceeded',
            'authentication_failed',
            'tool_execution_failed',
            'database_connection_lost'
        ]
        
        for error in self.scan_context.errors:
            if error.get('type') in critical_error_types:
                return True
            if error.get('severity') == 'critical':
                return True
        
        return False
    
    def _update_scan_session(self):
        """Update scan session in database."""
        if not self.db_session:
            return
        
        try:
            from .db_interfaces import ScanSessionManager
            session_manager = ScanSessionManager(self.db_session, self.logger)
            session_manager.update_scan_status(
                self.scan_context.scan_id,
                self.scan_context.status.value,
                self.scan_context.current_phase.value,
                self.scan_context.progress,
                self.scan_context.message
            )
        except Exception as e:
            self.logger.error(f"Failed to update scan session: {str(e)}")
    
    def _prepare_final_results(self) -> Dict[str, Any]:
        """
        Prepare final scan results for return.
        
        Returns:
            Dictionary containing all scan results
        """
        duration = None
        if self.scan_context.start_time and self.scan_context.end_time:
            duration = (self.scan_context.end_time - self.scan_context.start_time).total_seconds()
        
        return {
            'scan_id': self.scan_context.scan_id,
            'target_id': self.scan_context.target_id,
            'status': self.scan_context.status.value,
            'start_time': self.scan_context.start_time.isoformat() if self.scan_context.start_time else None,
            'end_time': self.scan_context.end_time.isoformat() if self.scan_context.end_time else None,
            'duration_seconds': duration,
            'phases_completed': [p.value for p in self.scan_context.phases if p.value in self.scan_context.results],
            'results': self.scan_context.results,
            'errors': self.scan_context.errors,
            'statistics': self._generate_statistics()
        }
    
    def _generate_statistics(self) -> Dict[str, Any]:
        """
        Generate scan statistics.
        
        Returns:
            Dictionary containing scan statistics
        """
        stats = {
            'total_subdomains': 0,
            'total_open_ports': 0,
            'total_services': 0,
            'total_vulnerabilities': 0,
            'vulnerabilities_by_severity': {},
            'exploited_vulnerabilities': 0,
            'reports_generated': 0
        }
        
        # Passive recon stats
        passive_results = self.scan_context.results.get('passive_recon', {})
        subdomains = passive_results.get('discoveries', {}).get('subdomains', [])
        stats['total_subdomains'] = len(subdomains)
        
        # Active recon stats
        active_results = self.scan_context.results.get('active_recon', {})
        ports = active_results.get('discoveries', {}).get('ports', [])
        services = active_results.get('discoveries', {}).get('services', [])
        stats['total_open_ports'] = sum(len(p.get('open_ports', [])) for p in ports)
        stats['total_services'] = len(services)
        
        # Vulnerability stats
        vuln_results = self.scan_context.results.get('vulnerability_testing', {})
        vulnerabilities = vuln_results.get('vulnerabilities', [])
        stats['total_vulnerabilities'] = len(vulnerabilities)
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'unknown')
            stats['vulnerabilities_by_severity'][severity] = \
                stats['vulnerabilities_by_severity'].get(severity, 0) + 1
        
        # Exploitation stats
        exploit_results = self.scan_context.results.get('exploitation', {})
        exploited = exploit_results.get('exploited_vulnerabilities', [])
        stats['exploited_vulnerabilities'] = len(exploited)
        
        # Reporting stats
        report_results = self.scan_context.results.get('reporting', {})
        reports = report_results.get('reports', [])
        stats['reports_generated'] = len(reports)
        
        return stats
    
    # Public methods for scan control
    
    def pause_scan(self):
        """Pause the current scan."""
        if self.scan_context.status == ScanStatus.RUNNING:
            self.scan_context.status = ScanStatus.PAUSED
            self.logger.info(f"Scan {self.scan_context.scan_id} paused")
            self._update_scan_session()
    
    def resume_scan(self):
        """Resume a paused scan."""
        if self.scan_context.status == ScanStatus.PAUSED:
            self.scan_context.status = ScanStatus.RUNNING
            self.logger.info(f"Scan {self.scan_context.scan_id} resumed")
            self._update_scan_session()
    
    def cancel_scan(self):
        """Cancel the current scan."""
        self.scan_context.status = ScanStatus.CANCELLED
        self.logger.info(f"Scan {self.scan_context.scan_id} cancelled")
        self._update_scan_session()
    
    def get_scan_status(self) -> Dict[str, Any]:
        """
        Get current scan status.
        
        Returns:
            Dictionary containing scan status information
        """
        return {
            'scan_id': self.scan_context.scan_id,
            'status': self.scan_context.status.value,
            'current_phase': self.scan_context.current_phase.value,
            'progress': self.scan_context.progress,
            'message': self.scan_context.message,
            'errors': len(self.scan_context.errors)
        }


class ProgressTracker:
    """Track and report scan progress."""
    
    def __init__(self, scan_context: ScanContext):
        """
        Initialize progress tracker.
        
        Args:
            scan_context: The scan context to track
        """
        self.scan_context = scan_context
        self.phase_weights = {
            ScanPhase.INITIALIZATION: 5,
            ScanPhase.PASSIVE_RECON: 15,
            ScanPhase.ACTIVE_RECON: 20,
            ScanPhase.VULNERABILITY_TESTING: 35,
            ScanPhase.EXPLOITATION: 15,
            ScanPhase.REPORTING: 8,
            ScanPhase.CLEANUP: 2
        }
        self.phase_progress = {phase: 0 for phase in ScanPhase}
        self.task_progress = {}
        self.logger = logging.getLogger(__name__)
    
    def update_phase_progress(self, phase: ScanPhase, progress: float):
        """
        Update progress for a specific phase.
        
        Args:
            phase: The scan phase
            progress: Progress percentage (0-100)
        """
        self.phase_progress[phase] = min(100, max(0, progress))
        self._calculate_overall_progress()
        self.logger.debug(f"Phase {phase.value} progress: {progress}%")
    
    def update_task_progress(self, task_name: str, progress: float):
        """
        Update progress for a specific task.
        
        Args:
            task_name: Name of the task
            progress: Progress percentage (0-100)
        """
        self.task_progress[task_name] = min(100, max(0, progress))
        self.logger.debug(f"Task {task_name} progress: {progress}%")
    
    def _calculate_overall_progress(self):
        """Calculate overall scan progress based on phase weights."""
        total_weight = sum(
            self.phase_weights.get(phase, 0)
            for phase in self.scan_context.phases
        )
        
        if total_weight == 0:
            return
        
        weighted_progress = sum(
            self.phase_weights.get(phase, 0) * self.phase_progress.get(phase, 0)
            for phase in self.scan_context.phases
        )
        
        self.scan_context.progress = weighted_progress / total_weight
        self.scan_context.message = f"Phase: {self.scan_context.current_phase.value}"
    
    def get_progress_report(self) -> Dict[str, Any]:
        """
        Get detailed progress report.
        
        Returns:
            Dictionary containing progress information
        """
        return {
            'overall_progress': self.scan_context.progress,
            'current_phase': self.scan_context.current_phase.value,
            'phase_progress': {
                phase.value: progress
                for phase, progress in self.phase_progress.items()
            },
            'task_progress': self.task_progress,
            'message': self.scan_context.message
        }


class RateLimiter:
    """Rate limiting for scan operations."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize rate limiter.
        
        Args:
            config: Rate limiting configuration
        """
        self.config = config
        self.requests_per_second = config.get('requests_per_second', 10)
        self.burst_size = config.get('burst_size', 20)
        self.cooldown_seconds = config.get('cooldown_seconds', 60)
        
        self.tokens = self.burst_size
        self.last_update = time.time()
        self.lock = threading.Lock()
        self.logger = logging.getLogger(__name__)
    
    async def acquire(self, tokens: int = 1) -> bool:
        """
        Acquire tokens for rate limiting.
        
        Args:
            tokens: Number of tokens to acquire
            
        Returns:
            True if tokens acquired, False otherwise
        """
        while True:
            with self.lock:
                now = time.time()
                elapsed = now - self.last_update
                
                # Refill tokens
                tokens_to_add = elapsed * self.requests_per_second
                self.tokens = min(self.burst_size, self.tokens + tokens_to_add)
                self.last_update = now
                
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
            
            # Wait before retry
            wait_time = (tokens - self.tokens) / self.requests_per_second
            await asyncio.sleep(min(wait_time, 0.1))
    
    def reset(self):
        """Reset the rate limiter."""
        with self.lock:
            self.tokens = self.burst_size
            self.last_update = time.time()


class WorkflowManager:
    """Manage scan workflow execution."""
    
    def __init__(self, scan_context: ScanContext, config: Dict[str, Any]):
        """
        Initialize workflow manager.
        
        Args:
            scan_context: The scan context
            config: Workflow configuration
        """
        self.scan_context = scan_context
        self.config = config
        self.workflows = self._load_workflows()
        self.logger = logging.getLogger(__name__)
    
    def _load_workflows(self) -> Dict[str, List[Dict]]:
        """
        Load workflow definitions.
        
        Returns:
            Dictionary of workflow definitions
        """
        return {
            'standard': [
                {'phase': 'passive_recon', 'parallel': False},
                {'phase': 'active_recon', 'parallel': False},
                {'phase': 'vulnerability_testing', 'parallel': True},
                {'phase': 'exploitation', 'parallel': False},
                {'phase': 'reporting', 'parallel': False}
            ],
            'quick': [
                {'phase': 'passive_recon', 'parallel': False},
                {'phase': 'vulnerability_testing', 'parallel': True},
                {'phase': 'reporting', 'parallel': False}
            ],
            'deep': [
                {'phase': 'passive_recon', 'parallel': False},
                {'phase': 'active_recon', 'parallel': False},
                {'phase': 'vulnerability_testing', 'parallel': True},
                {'phase': 'exploitation', 'parallel': True},
                {'phase': 'reporting', 'parallel': False}
            ]
        }
    
    def get_workflow(self, workflow_name: str) -> List[Dict]:
        """
        Get workflow definition by name.
        
        Args:
            workflow_name: Name of the workflow
            
        Returns:
            Workflow definition
        """
        return self.workflows.get(workflow_name, self.workflows['standard'])
    
    def validate_workflow(self, workflow: List[Dict]) -> bool:
        """
        Validate workflow definition.
        
        Args:
            workflow: Workflow definition
            
        Returns:
            True if valid, False otherwise
        """
        valid_phases = {phase.value for phase in ScanPhase}
        
        for step in workflow:
            if step.get('phase') not in valid_phases:
                self.logger.error(f"Invalid phase in workflow: {step.get('phase')}")
                return False
        
        return True


class ScanScheduler:
    """Schedule and manage multiple scans."""
    
    def __init__(self, orchestrator: ScanOrchestrator):
        """
        Initialize scan scheduler.
        
        Args:
            orchestrator: The scan orchestrator
        """
        self.orchestrator = orchestrator
        self.scan_queue = PriorityQueue()
        self.scheduled_scans = {}
        self.running_scans = {}
        self.max_concurrent_scans = orchestrator.config.get('max_concurrent_scans', 3)
        self.logger = logging.getLogger(__name__)
        
        # Start scheduler thread
        self.scheduler_thread = threading.Thread(target=self._scheduler_loop, daemon=True)
        self.scheduler_thread.start()
    
    def schedule_scan(self, scan_config: Dict[str, Any], priority: ScanPriority = ScanPriority.MEDIUM,
                      scheduled_time: Optional[datetime] = None) -> str:
        """
        Schedule a scan for execution.
        
        Args:
            scan_config: Scan configuration
            priority: Scan priority
            scheduled_time: Optional scheduled execution time
            
        Returns:
            Scheduled scan ID
        """
        scan_id = str(uuid.uuid4())
        
        scheduled_scan = {
            'id': scan_id,
            'config': scan_config,
            'priority': priority,
            'scheduled_time': scheduled_time or datetime.utcnow(),
            'status': 'scheduled'
        }
        
        self.scheduled_scans[scan_id] = scheduled_scan
        
        # Add to priority queue (negative priority for min-heap behavior)
        self.scan_queue.put((
            priority.value,
            scheduled_time or datetime.utcnow(),
            scan_id
        ))
        
        self.logger.info(f"Scheduled scan {scan_id} with priority {priority.value}")
        
        return scan_id
    
    def _scheduler_loop(self):
        """Main scheduler loop for executing scheduled scans."""
        while True:
            try:
                # Check if we can run more scans
                if len(self.running_scans) < self.max_concurrent_scans:
                    if not self.scan_queue.empty():
                        priority, scheduled_time, scan_id = self.scan_queue.get()
                        
                        # Check if it's time to run the scan
                        if scheduled_time <= datetime.utcnow():
                            self._execute_scheduled_scan(scan_id)
                        else:
                            # Put it back in the queue
                            self.scan_queue.put((priority, scheduled_time, scan_id))
                
                # Clean up completed scans
                completed = []
                for scan_id, scan_data in self.running_scans.items():
                    if scan_data['status'] in ['completed', 'failed', 'cancelled']:
                        completed.append(scan_id)
                
                for scan_id in completed:
                    del self.running_scans[scan_id]
                    self.logger.info(f"Removed completed scan {scan_id} from running scans")
                
                time.sleep(5)  # Check every 5 seconds
                
            except Exception as e:
                self.logger.error(f"Error in scheduler loop: {str(e)}", exc_info=True)
                time.sleep(10)
    
    def _execute_scheduled_scan(self, scan_id: str):
        """
        Execute a scheduled scan.
        
        Args:
            scan_id: ID of the scheduled scan
        """
        if scan_id not in self.scheduled_scans:
            self.logger.error(f"Scan {scan_id} not found in scheduled scans")
            return
        
        scan_data = self.scheduled_scans[scan_id]
        
        self.logger.info(f"Executing scheduled scan {scan_id}")
        
        # Create new orchestrator for this scan
        orchestrator = ScanOrchestrator(
            target_id=scan_data['config']['target_id'],
            config=scan_data['config'],
            db_session=self.orchestrator.db_session
        )
        
        # Run scan in separate thread
        scan_thread = threading.Thread(
            target=asyncio.run,
            args=(orchestrator.execute_scan(),),
            daemon=True
        )
        scan_thread.start()
        
        # Track running scan
        self.running_scans[scan_id] = {
            'orchestrator': orchestrator,
            'thread': scan_thread,
            'status': 'running',
            'start_time': datetime.utcnow()
        }
        
        # Update scheduled scan status
        self.scheduled_scans[scan_id]['status'] = 'running'
    
    def get_scheduler_status(self) -> Dict[str, Any]:
        """
        Get scheduler status.
        
        Returns:
            Dictionary containing scheduler status
        """
        return {
            'max_concurrent_scans': self.max_concurrent_scans,
            'running_scans': len(self.running_scans),
            'queued_scans': self.scan_queue.qsize(),
            'scheduled_scans': len(self.scheduled_scans),
            'scans': {
                scan_id: {
                    'status': data['status'],
                    'priority': data.get('priority', ScanPriority.MEDIUM).value,
                    'scheduled_time': data.get('scheduled_time', '').isoformat() if data.get('scheduled_time') else None
                }
                for scan_id, data in self.scheduled_scans.items()
            }
        }
        