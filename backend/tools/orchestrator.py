"""
Tool Orchestrator for Bug Bounty Automation Platform
backend/tools/orchestrator.py

Manages the orchestration of multiple tools in a coordinated penetration testing workflow.
"""

import logging
import os
import time
import threading
from typing import Dict, List, Any, Optional, Callable
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

from django.conf import settings

from .base import ToolConfig, ToolResult, ToolStatus, get_tool
from apps.targets.models import Target

logger = logging.getLogger(__name__)


class OrchestrationStrategy(Enum):
    """Different orchestration strategies"""
    SEQUENTIAL = "sequential"  # Run tools one after another
    PARALLEL = "parallel"     # Run tools in parallel where possible
    DEPENDENCY_BASED = "dependency_based"  # Run based on dependencies
    ADAPTIVE = "adaptive"     # Adapt based on results


@dataclass
class ToolStep:
    """Represents a single tool execution step in the orchestration"""
    tool_name: str
    target: str
    custom_params: Optional[Dict[str, Any]] = None
    depends_on: List[str] = field(default_factory=list)
    condition: Optional[Callable[[Dict[str, Any]], bool]] = None
    priority: int = 5  # 1-10, higher is more important
    timeout: Optional[int] = None
    retry_count: int = 0
    max_retries: int = 2


@dataclass
class OrchestrationPlan:
    """Complete orchestration plan for a scan session"""
    scan_session_id: str
    target: Target
    steps: List[ToolStep]
    strategy: OrchestrationStrategy = OrchestrationStrategy.DEPENDENCY_BASED
    max_concurrent_tools: int = 3
    global_timeout: Optional[int] = None
    stop_on_critical_failure: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)


class ToolOrchestrator:
    """
    Orchestrates the execution of multiple penetration testing tools
    based on a defined strategy and dependency graph.
    """

    def __init__(self, scan_session_id: str):
        self.scan_session_id = scan_session_id
        self.logger = logging.getLogger(f'orchestrator.{scan_session_id}')
        self.results: Dict[str, ToolResult] = {}
        self.execution_context: Dict[str, Any] = {}
        self.stop_requested = False
        self._lock = threading.Lock()

    def create_passive_recon_plan(self, target: Target) -> List[ToolStep]:
        """Create tool steps for passive reconnaissance phase"""
        steps = []

        # Subdomain enumeration - these can run in parallel
        subdomain_tools = [
            ('subfinder', {'all_sources': True}),
            ('assetfinder', {}),
            ('findomain', {})
        ]

        for tool_name, params in subdomain_tools:
            steps.append(ToolStep(
                tool_name=tool_name,
                target=self._extract_domain(target.main_url),
                custom_params=params,
                priority=8,
                timeout=600  # 10 minutes
            ))

        # Amass runs after other tools to consolidate results
        steps.append(ToolStep(
            tool_name='amass',
            target=self._extract_domain(target.main_url),
            custom_params={'passive': True},
            depends_on=['subfinder', 'assetfinder', 'findomain'],
            priority=7,
            timeout=1800  # 30 minutes
        ))

        return steps

    def create_active_recon_plan(
        self, target: Target, discovered_assets: List[str]
    ) -> List[ToolStep]:
        """Create tool steps for active reconnaissance phase"""
        steps = []

        # Port scanning - start with main target
        steps.append(ToolStep(
            tool_name='nmap',
            target=target.main_url,
            custom_params={
                'scan_type': 'quick',
                'service_detection': True
            },
            priority=9,
            timeout=1800  # 30 minutes
        ))

        # Port scan discovered subdomains (limit to top 10)
        top_subdomains = discovered_assets[:10]
        for i, subdomain in enumerate(top_subdomains):
            steps.append(ToolStep(
                tool_name='nmap',
                target=subdomain,
                custom_params={
                    'scan_type': 'quick',
                    'service_detection': True
                },
                depends_on=['nmap'] if i == 0 else [],  # First one depends on main scan
                priority=6,
                timeout=900  # 15 minutes
            ))

        return steps

    def create_vulnerability_testing_plan(
        self, target: Target, web_services: List[str]
    ) -> List[ToolStep]:
        """Create tool steps for vulnerability testing phase"""
        steps = []

        # Nuclei scans for web services
        for service_url in web_services[:5]:  # Limit to 5 targets
            steps.append(ToolStep(
                tool_name='nuclei',
                target=service_url,
                custom_params={
                    'severity': ['critical', 'high', 'medium'],
                    'tags': ['cve', 'owasp', 'tech']
                },
                priority=8,
                timeout=2400  # 40 minutes
            ))

        # Specialized Nuclei scans
        nuclei_variants = [
            ('nuclei-web-apps', {'tags': ['web-app', 'cms']}),
            ('nuclei-cves', {'severity': ['critical', 'high']}),
            ('nuclei-misconfigs', {'tags': ['config', 'exposure']})
        ]

        for tool_name, params in nuclei_variants:
            steps.append(ToolStep(
                tool_name=tool_name,
                target=target.main_url,
                custom_params=params,
                depends_on=['nuclei'],  # Run after main nuclei scan
                priority=6,
                timeout=1800  # 30 minutes
            ))

        return steps

    def execute_plan(self, plan: OrchestrationPlan) -> Dict[str, Any]:
        """Execute an orchestration plan"""
        self.logger.info("Starting orchestration with strategy: %s", plan.strategy.value)

        start_time = datetime.now()
        execution_summary = {
            'scan_session_id': plan.scan_session_id,
            'strategy': plan.strategy.value,
            'start_time': start_time,
            'total_steps': len(plan.steps),
            'completed_steps': 0,
            'failed_steps': 0,
            'skipped_steps': 0,
            'results': {},
            'errors': []
        }

        try:
            if plan.strategy == OrchestrationStrategy.SEQUENTIAL:
                self._execute_sequential(plan, execution_summary)
            elif plan.strategy == OrchestrationStrategy.PARALLEL:
                self._execute_parallel(plan, execution_summary)
            elif plan.strategy == OrchestrationStrategy.DEPENDENCY_BASED:
                self._execute_dependency_based(plan, execution_summary)
            elif plan.strategy == OrchestrationStrategy.ADAPTIVE:
                self._execute_adaptive(plan, execution_summary)

        except Exception as e:
            self.logger.error("Orchestration failed: %s", e)
            execution_summary['errors'].append(str(e))

        execution_summary['end_time'] = datetime.now()
        execution_summary['duration'] = (
            execution_summary['end_time'] - start_time
        ).total_seconds()

        self.logger.info(
            "Orchestration completed: {execution_summary['completed_steps']}/%s steps",
            execution_summary['total_steps']
        )

        return execution_summary

    def _execute_sequential(self, plan: OrchestrationPlan, summary: Dict[str, Any]):
        """Execute tools sequentially"""
        for step in plan.steps:
            if self.stop_requested:
                break

            result = self._execute_step(step, plan)
            self._update_summary(summary, step, result)

    def _execute_parallel(self, plan: OrchestrationPlan, summary: Dict[str, Any]):
        """Execute tools in parallel"""
        with ThreadPoolExecutor(max_workers=plan.max_concurrent_tools) as executor:
            # Submit all tasks
            future_to_step = {
                executor.submit(self._execute_step, step, plan): step
                for step in plan.steps
            }

            # Process completed tasks
            for future in as_completed(future_to_step):
                if self.stop_requested:
                    break

                step = future_to_step[future]
                try:
                    result = future.result()
                    self._update_summary(summary, step, result)
                except Exception as e:
                    self.logger.error("Step {step.tool_name} failed: %s", e)
                    summary['failed_steps'] += 1
                    summary['errors'].append(f"{step.tool_name}: {str(e)}")

    def _execute_dependency_based(self, plan: OrchestrationPlan, summary: Dict[str, Any]):
        """Execute tools based on dependency graph"""
        completed_tools = set()
        remaining_steps = plan.steps.copy()

        while remaining_steps and not self.stop_requested:
            # Find steps that can be executed (dependencies met)
            ready_steps = []
            for step in remaining_steps:
                if all(dep in completed_tools for dep in step.depends_on):
                    # Check condition if specified
                    if step.condition is None or step.condition(self.execution_context):
                        ready_steps.append(step)

            if not ready_steps:
                # No steps ready - check if we're deadlocked
                if remaining_steps:
                    self.logger.warning("Dependency deadlock detected, skipping remaining steps")
                    summary['skipped_steps'] += len(remaining_steps)
                break

            # Sort by priority
            ready_steps.sort(key=lambda x: x.priority, reverse=True)

            # Execute ready steps (up to max concurrent)
            batch_size = min(len(ready_steps), plan.max_concurrent_tools)
            batch_steps = ready_steps[:batch_size]

            if batch_size == 1:
                # Single step - execute directly
                step = batch_steps[0]
                result = self._execute_step(step, plan)
                self._update_summary(summary, step, result)

                if result.status == ToolStatus.COMPLETED:
                    completed_tools.add(step.tool_name)

                remaining_steps.remove(step)
            else:
                # Multiple steps - execute in parallel
                with ThreadPoolExecutor(max_workers=batch_size) as executor:
                    future_to_step = {
                        executor.submit(self._execute_step, step, plan): step
                        for step in batch_steps
                    }

                    for future in as_completed(future_to_step):
                        step = future_to_step[future]
                        try:
                            result = future.result()
                            self._update_summary(summary, step, result)

                            if result.status == ToolStatus.COMPLETED:
                                completed_tools.add(step.tool_name)

                            remaining_steps.remove(step)
                        except Exception as e:
                            self.logger.error("Step {step.tool_name} failed: %s", e)
                            summary['failed_steps'] += 1
                            summary['errors'].append(f"{step.tool_name}: {str(e)}")
                            remaining_steps.remove(step)

    def _execute_adaptive(self, plan: OrchestrationPlan, summary: Dict[str, Any]):
        """Execute tools adaptively based on results"""
        # Start with dependency-based execution
        self._execute_dependency_based(plan, summary)

        # Analyze results and potentially add more steps
        self._adaptive_analysis(plan, summary)

    def _execute_step(self, step: ToolStep, plan: OrchestrationPlan) -> ToolResult:
        """Execute a single tool step"""
        self.logger.info("Executing step: {step.tool_name} -> %s", step.target)

        # Get tool instance
        tool = get_tool(step.tool_name)
        if not tool:
            raise ValueError(f"Tool {step.tool_name} not found")

        if not tool.is_available():
            raise ValueError(f"Tool {step.tool_name} not available")

        # Prepare configuration
        evidence_dir = self._get_evidence_directory(plan.scan_session_id)

        config = ToolConfig(
            target=step.target,
            output_dir=evidence_dir,
            rate_limit=plan.target.requests_per_second,
            timeout=step.timeout or 3600,
            threads=plan.target.concurrent_requests,
            custom_params=step.custom_params,
            scope_urls=plan.target.in_scope_urls,
            out_of_scope_urls=plan.target.out_of_scope_urls
        )

        # Execute with retry logic
        last_result = None
        for attempt in range(step.max_retries + 1):
            try:
                result = tool.execute(config)

                # Store result
                with self._lock:
                    self.results[f"{step.tool_name}_{step.target}"] = result
                    self._update_execution_context(step, result)

                if result.status == ToolStatus.COMPLETED:
                    return result
                elif attempt < step.max_retries:
                    self.logger.warning("Step {step.tool_name} failed, retrying ({attempt + 1}/%s)", step.max_retries)
                    time.sleep(min(2 ** attempt, 30))  # Exponential backoff

                last_result = result

            except Exception as e:
                if attempt < step.max_retries:
                    self.logger.warning("Step {step.tool_name} exception, retrying: %s", e)
                    time.sleep(min(2 ** attempt, 30))
                else:
                    raise e

        return last_result or ToolResult(
            tool_name=step.tool_name,
            status=ToolStatus.FAILED,
            exit_code=-1,
            stdout="",
            stderr="Max retries exceeded",
            execution_time=0,
            output_files=[],
            parsed_results=[],
            error_message="Max retries exceeded"
        )

    def _update_summary(self, summary: Dict[str, Any], step: ToolStep, result: ToolResult):
        """Update execution summary with step result"""
        summary['results'][f"{step.tool_name}_{step.target}"] = {
            'status': result.status.value,
            'execution_time': result.execution_time,
            'results_count': len(result.parsed_results),
            'error': result.error_message
        }

        if result.status == ToolStatus.COMPLETED:
            summary['completed_steps'] += 1
        else:
            summary['failed_steps'] += 1
            if result.error_message:
                summary['errors'].append(f"{step.tool_name}: {result.error_message}")

    def _update_execution_context(self, step: ToolStep, result: ToolResult):
        """Update execution context with results for future steps"""
        context_key = f"{step.tool_name}_results"
        self.execution_context[context_key] = result.parsed_results

        # Extract common data types
        if result.parsed_results:
            subdomains = [r.get('subdomain') for r in result.parsed_results
                         if r.get('type') == 'subdomain' and r.get('subdomain')]
            if subdomains:
                self.execution_context.setdefault('discovered_subdomains', []).extend(subdomains)

            services = [r for r in result.parsed_results if r.get('type') == 'port']
            if services:
                self.execution_context.setdefault('discovered_services', []).extend(services)

            vulnerabilities = [r for r in result.parsed_results if r.get('type') == 'vulnerability']
            if vulnerabilities:
                self.execution_context.setdefault('discovered_vulnerabilities', []).extend(vulnerabilities)

    def _adaptive_analysis(self, plan: OrchestrationPlan, summary: Dict[str, Any]):
        """Analyze results and adapt the plan"""
        # Check if we found interesting results that warrant additional scanning
        discovered_subdomains = self.execution_context.get('discovered_subdomains', [])
        discovered_services = self.execution_context.get('discovered_services', [])

        # If we found many subdomains, might want to do deeper port scanning
        if len(discovered_subdomains) > 10:
            self.logger.info("Found %s subdomains, considering additional scans", len(discovered_subdomains))

        # If we found critical vulnerabilities, might want to do exploitation
        critical_vulns = [v for v in self.execution_context.get('discovered_vulnerabilities', [])
                         if v.get('severity') == 'critical']

        if critical_vulns:
            self.logger.info("Found %s critical vulnerabilities", len(critical_vulns))

    def _get_evidence_directory(self, scan_session_id: str) -> str:
        """Get evidence directory for the scan session"""
        evidence_dir = os.path.join(settings.EVIDENCE_ROOT, str(scan_session_id))
        os.makedirs(evidence_dir, exist_ok=True)
        return evidence_dir

    def _extract_domain(self, url: str) -> str:
        """Extract domain from URL"""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else f'http://{url}')
            return parsed.netloc
        except Exception:
            return url

    def stop(self):
        """Stop orchestration"""
        self.stop_requested = True
        self.logger.info("Orchestration stop requested")


def create_full_scan_plan(scan_session_id: str, target: Target) -> OrchestrationPlan:
    """Create a complete scan plan for a target"""
    orchestrator = ToolOrchestrator(scan_session_id)

    # Build comprehensive plan
    steps = []

    # Phase 1: Passive reconnaissance
    passive_steps = orchestrator.create_passive_recon_plan(target)
    steps.extend(passive_steps)

    # Phase 2: Active reconnaissance (depends on passive results)
    active_steps = orchestrator.create_active_recon_plan(target, [])
    # Make active recon depend on passive recon completion
    for step in active_steps:
        step.depends_on.extend(['subfinder', 'assetfinder'])
    steps.extend(active_steps)

    # Phase 3: Vulnerability testing (depends on active recon)
    vuln_steps = orchestrator.create_vulnerability_testing_plan(target, [target.main_url])
    for step in vuln_steps:
        step.depends_on.extend(['nmap'])
    steps.extend(vuln_steps)

    return OrchestrationPlan(
        scan_session_id=scan_session_id,
        target=target,
        steps=steps,
        strategy=OrchestrationStrategy.DEPENDENCY_BASED,
        max_concurrent_tools=3,
        global_timeout=14400,  # 4 hours
        stop_on_critical_failure=False
    )
