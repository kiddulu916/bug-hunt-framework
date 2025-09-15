# Celery tasks for scanning app
from celery import shared_task
from django.utils import timezone
from django.conf import settings
from datetime import timedelta
import logging
import os
from typing import Dict, Any

from .models import ScanSession, ToolExecution, ScanStatus, ToolStatus
from apps.reconnaissance.models import ReconResult, ReconResultType, DiscoveryMethod
from apps.vulnerabilities.models import Vulnerability
from tools.base import get_tool, ToolConfig, ToolStatus as BaseToolStatus

logger = logging.getLogger(__name__)


@shared_task(bind=True)
def start_scan_session(self, scan_session_id: str):
    """Start a scan session asynchronously"""
    try:
        scan_session = ScanSession.objects.get(id=scan_session_id)

        # Update scan status
        scan_session.status = ScanStatus.RUNNING
        scan_session.started_at = timezone.now()
        scan_session.save(update_fields=['status', 'started_at'])

        logger.info("Starting scan session: %s", scan_session.session_name)

        # Execute the scan phases
        execute_scan_session.delay(scan_session_id)

        return f"Started scan session {scan_session_id}"

    except ScanSession.DoesNotExist:
        logger.error("Scan session %s not found", scan_session_id)
        return f"Scan session {scan_session_id} not found"
    except Exception as e:
        logger.error("Error starting scan session {scan_session_id}: %s", e)
        return f"Error starting scan session: {e}"


@shared_task(bind=True)
def execute_scan_session(self, scan_session_id: str):
    """Execute all phases of a scan session"""
    try:
        scan_session = ScanSession.objects.get(id=scan_session_id)

        # Get methodology phases
        phases = scan_session.methodology_phases or [
            'passive_recon', 'active_recon', 'vulnerability_testing'
        ]

        logger.info("Executing scan session {scan_session.session_name} with phases: %s", phases)

        total_phases = len(phases)
        completed_phases = 0

        for phase_index, phase in enumerate(phases):
            # Update current phase
            scan_session.current_phase = phase
            scan_session.total_progress = (completed_phases / total_phases) * 100
            scan_session.save(update_fields=['current_phase', 'total_progress'])

            logger.info("Starting phase: %s", phase)

            # Execute phase
            try:
                if phase == 'passive_recon':
                    execute_passive_reconnaissance.delay(scan_session_id)
                elif phase == 'active_recon':
                    execute_active_reconnaissance.delay(scan_session_id)
                elif phase == 'vulnerability_testing':
                    execute_vulnerability_testing.delay(scan_session_id)
                elif phase == 'exploitation':
                    execute_exploitation_phase.delay(scan_session_id)

                completed_phases += 1

            except Exception as e:
                logger.error("Error in phase {phase}: %s", e)
                scan_session.status = ScanStatus.FAILED
                scan_session.completed_at = timezone.now()
                scan_session.save(update_fields=['status', 'completed_at'])
                return f"Scan failed in phase {phase}: {e}"

        # Mark scan as completed
        scan_session.status = ScanStatus.COMPLETED
        scan_session.completed_at = timezone.now()
        scan_session.total_progress = 100.0
        scan_session.save(update_fields=['status', 'completed_at', 'total_progress'])

        # Generate summary statistics
        update_scan_statistics.delay(scan_session_id)

        logger.info("Completed scan session: %s", scan_session.session_name)
        return f"Completed scan session {scan_session_id}"

    except ScanSession.DoesNotExist:
        logger.error("Scan session %s not found", scan_session_id)
        return f"Scan session {scan_session_id} not found"
    except Exception as e:
        logger.error("Error executing scan session {scan_session_id}: %s", e)
        try:
            scan_session = ScanSession.objects.get(id=scan_session_id)
            scan_session.status = ScanStatus.FAILED
            scan_session.completed_at = timezone.now()
            scan_session.save(update_fields=['status', 'completed_at'])
        except Exception:
            pass
        return f"Error executing scan session: {e}"


@shared_task(bind=True)
def execute_passive_reconnaissance(self, scan_session_id: str):
    """Execute passive reconnaissance phase"""
    try:
        scan_session = ScanSession.objects.get(id=scan_session_id)
        target = scan_session.target

        logger.info("Starting passive reconnaissance for %s", target.target_name)

        # Subdomain enumeration tools
        subdomain_tools = ['subfinder', 'assetfinder', 'amass']

        for tool_name in subdomain_tools:
            execute_tool.delay(scan_session_id, tool_name, target.main_url)

        return f"Passive reconnaissance started for {scan_session_id}"

    except Exception as e:
        logger.error("Error in passive reconnaissance: %s", e)
        return f"Error in passive reconnaissance: {e}"


@shared_task(bind=True)
def execute_active_reconnaissance(self, scan_session_id: str):
    """Execute active reconnaissance phase"""
    try:
        scan_session = ScanSession.objects.get(id=scan_session_id)
        target = scan_session.target

        logger.info("Starting active reconnaissance for %s", target.target_name)

        # Get discovered subdomains from passive recon
        subdomains = ReconResult.objects.filter(
            scan_session=scan_session,
            result_type=ReconResultType.SUBDOMAIN,
            is_in_scope=True
        ).values_list('discovered_asset', flat=True)

        # Port scanning
        targets_to_scan = [target.main_url] + list(subdomains)

        for scan_target in targets_to_scan[:10]:  # Limit to avoid overwhelming
            execute_tool.delay(scan_session_id, 'nmap', scan_target)

        return f"Active reconnaissance started for {scan_session_id}"

    except Exception as e:
        logger.error("Error in active reconnaissance: %s", e)
        return f"Error in active reconnaissance: {e}"


@shared_task(bind=True)
def execute_vulnerability_testing(self, scan_session_id: str):
    """Execute vulnerability testing phase"""
    try:
        scan_session = ScanSession.objects.get(id=scan_session_id)
        target = scan_session.target

        logger.info("Starting vulnerability testing for %s", target.target_name)

        # Get discovered web services
        web_services = ReconResult.objects.filter(
            scan_session=scan_session,
            result_type=ReconResultType.SERVICE,
            protocol__in=['http', 'https'],
            is_in_scope=True
        )

        # Run Nuclei scans
        targets_to_scan = [target.main_url]

        for service in web_services[:5]:  # Limit targets
            if service.discovered_asset.startswith('http'):
                targets_to_scan.append(service.discovered_asset)

        for scan_target in targets_to_scan:
            execute_tool.delay(scan_session_id, 'nuclei', scan_target)

        return f"Vulnerability testing started for {scan_session_id}"

    except Exception as e:
        logger.error("Error in vulnerability testing: %s", e)
        return f"Error in vulnerability testing: {e}"


@shared_task(bind=True)
def execute_exploitation_phase(self, scan_session_id: str):
    """Execute exploitation phase"""
    try:
        scan_session = ScanSession.objects.get(id=scan_session_id)

        logger.info("Starting exploitation phase for %s", scan_session.session_name)

        # Get high-severity vulnerabilities for exploitation attempts
        high_severity_vulns = Vulnerability.objects.filter(
            scan_session=scan_session,
            severity__in=['critical', 'high']
        )

        for vuln in high_severity_vulns[:3]:  # Limit exploitation attempts
            # This would trigger specific exploitation tools based on vulnerability type
            logger.info("Would attempt exploitation of %s", vuln.vulnerability_name)

        return f"Exploitation phase completed for {scan_session_id}"

    except Exception as e:
        logger.error("Error in exploitation phase: %s", e)
        return f"Error in exploitation phase: {e}"


@shared_task(bind=True, time_limit=3600)  # 1 hour timeout
def execute_tool(self, scan_session_id: str, tool_name: str, target: str, custom_params: Dict = None):
    """Execute a specific tool against a target"""
    tool_execution = None

    try:
        # Get scan session
        scan_session = ScanSession.objects.get(id=scan_session_id)

        # Get tool instance
        tool = get_tool(tool_name)
        if not tool:
            raise ValueError(f"Tool {tool_name} not found")

        if not tool.is_available():
            raise ValueError(f"Tool {tool_name} is not available")

        # Create tool execution record
        tool_execution = ToolExecution.objects.create(
            scan_session=scan_session,
            tool_name=tool_name,
            tool_category=tool.category.value,
            status=ToolStatus.RUNNING,
            started_at=timezone.now(),
            tool_parameters=custom_params or {}
        )

        logger.info("Starting tool execution: {tool_name} against %s", target)

        # Prepare tool configuration
        evidence_dir = os.path.join(settings.EVIDENCE_ROOT, str(scan_session.id))
        os.makedirs(evidence_dir, exist_ok=True)

        config = ToolConfig(
            target=target,
            output_dir=evidence_dir,
            rate_limit=scan_session.target.requests_per_second,
            timeout=3000,  # 50 minutes
            threads=scan_session.target.concurrent_requests,
            custom_params=custom_params,
            scope_urls=scan_session.target.in_scope_urls,
            out_of_scope_urls=scan_session.target.out_of_scope_urls
        )

        # Execute tool
        result = tool.execute(config)

        # Update tool execution record
        tool_execution.completed_at = timezone.now()
        tool_execution.execution_time_seconds = result.execution_time
        tool_execution.raw_output = result.stdout[:10000]  # Limit size
        tool_execution.error_message = result.error_message
        tool_execution.parsed_results_count = len(result.parsed_results)
        tool_execution.output_file_path = ','.join(result.output_files)

        # Map tool status to Django model status
        if result.status == BaseToolStatus.COMPLETED:
            tool_execution.status = ToolStatus.COMPLETED
        elif result.status == BaseToolStatus.FAILED:
            tool_execution.status = ToolStatus.FAILED
        elif result.status == BaseToolStatus.TIMEOUT:
            tool_execution.status = ToolStatus.FAILED
            tool_execution.error_message = "Tool execution timed out"
        else:
            tool_execution.status = ToolStatus.FAILED

        tool_execution.save()

        # Process results
        if result.parsed_results:
            process_tool_results.delay(tool_execution.id, result.to_dict())

        logger.info("Tool execution completed: {tool_name} - %s results", len(result.parsed_results))
        return f"Tool {tool_name} completed with {len(result.parsed_results)} results"

    except Exception as e:
        logger.error("Error executing tool {tool_name}: %s", e)

        if tool_execution:
            tool_execution.status = ToolStatus.FAILED
            tool_execution.completed_at = timezone.now()
            tool_execution.error_message = str(e)
            tool_execution.save()

        return f"Tool {tool_name} failed: {e}"


@shared_task
def process_tool_results(tool_execution_id: str, tool_result_dict: Dict[str, Any]):
    """Process and store tool results in the database"""
    try:
        tool_execution = ToolExecution.objects.get(id=tool_execution_id)
        scan_session = tool_execution.scan_session

        results = tool_result_dict.get('parsed_results', [])
        logger.info("Processing {len(results)} results from %s", tool_execution.tool_name)

        for result in results:
            result_type = result.get('type', 'unknown')

            if result_type == 'subdomain':
                # Store as reconnaissance result
                ReconResult.objects.get_or_create(
                    scan_session=scan_session,
                    discovered_asset=result.get('subdomain', ''),
                    result_type=ReconResultType.SUBDOMAIN,
                    defaults={
                        'discovered_by_tool': tool_execution.tool_name,
                        'discovery_method': DiscoveryMethod.DNS_ENUM,
                        'confidence_score': 0.9,
                        'is_in_scope': True,  # Will be validated later
                        'additional_info': {
                            'source': result.get('source', ''),
                            'ip': result.get('ip', '')
                        }
                    }
                )

            elif result_type == 'port':
                # Store as service discovery result
                service_name = result.get('service', '')
                if service_name:
                    asset_name = f"{result.get('host', '')}:{result.get('port', '')}"
                    ReconResult.objects.get_or_create(
                        scan_session=scan_session,
                        discovered_asset=asset_name,
                        result_type=ReconResultType.SERVICE,
                        defaults={
                            'discovered_by_tool': tool_execution.tool_name,
                            'discovery_method': DiscoveryMethod.PORT_SCAN,
                            'ip_address': result.get('host', ''),
                            'port': result.get('port', 0),
                            'protocol': result.get('protocol', ''),
                            'service_name': service_name,
                            'service_version': result.get('version', ''),
                            'confidence_score': 0.8,
                            'is_in_scope': True,
                            'additional_info': result
                        }
                    )

            elif result_type == 'vulnerability':
                # Store as vulnerability
                severity = normalize_severity(result.get('severity', 'info'))

                Vulnerability.objects.get_or_create(
                    scan_session=scan_session,
                    vulnerability_name=result.get('name', 'Unknown'),
                    affected_url=result.get('url', ''),
                    vulnerability_type=result.get('template_id', 'unknown'),
                    defaults={
                        'severity': severity,
                        'description': result.get('description', ''),
                        'owasp_category': result.get('owasp', ''),
                        'cwe_id': result.get('cwe_id', ''),
                        'cvss_score': result.get('cvss_score', None),
                        'impact_description': result.get('description', ''),
                        'discovered_by_tool': tool_execution.tool_name,
                        'discovery_method': 'Automated Vulnerability Scanner',
                        'confidence_level': 0.8,
                        'request_data': result.get('request', ''),
                        'response_data': result.get('response', ''),
                        'payload_used': result.get('matched_line', ''),
                        'additional_evidence': result
                    }
                )

        logger.info("Processed {len(results)} results from %s", tool_execution.tool_name)

    except Exception as e:
        logger.error("Error processing tool results: %s", e)


@shared_task
def update_scan_statistics(scan_session_id: str):
    """Update scan session statistics"""
    try:
        scan_session = ScanSession.objects.get(id=scan_session_id)

        # Count results
        scan_session.total_subdomains_found = ReconResult.objects.filter(
            scan_session=scan_session,
            result_type=ReconResultType.SUBDOMAIN
        ).count()

        scan_session.total_endpoints_found = ReconResult.objects.filter(
            scan_session=scan_session,
            result_type=ReconResultType.ENDPOINT
        ).count()

        vulnerabilities = Vulnerability.objects.filter(scan_session=scan_session)
        scan_session.total_vulnerabilities = vulnerabilities.count()
        scan_session.critical_vulnerabilities = vulnerabilities.filter(severity='critical').count()
        scan_session.high_vulnerabilities = vulnerabilities.filter(severity='high').count()

        scan_session.save(update_fields=[
            'total_subdomains_found', 'total_endpoints_found', 'total_vulnerabilities',
            'critical_vulnerabilities', 'high_vulnerabilities'
        ])

        logger.info("Updated statistics for scan session %s", scan_session.session_name)

    except Exception as e:
        logger.error("Error updating scan statistics: %s", e)


@shared_task
def pause_scan_session(scan_session_id: str):
    """Pause a running scan session"""
    try:
        scan_session = ScanSession.objects.get(id=scan_session_id)

        # Update running tool executions
        ToolExecution.objects.filter(
            scan_session=scan_session,
            status=ToolStatus.RUNNING
        ).update(status=ToolStatus.FAILED, error_message="Scan paused by user")

        logger.info("Paused scan session: %s", scan_session.session_name)
        return f"Paused scan session {scan_session_id}"

    except Exception as e:
        logger.error("Error pausing scan session: %s", e)
        return f"Error pausing scan session: {e}"


@shared_task
def resume_scan_session(scan_session_id: str):
    """Resume a paused scan session"""
    try:
        scan_session = ScanSession.objects.get(id=scan_session_id)

        # Resume from current phase
        execute_scan_session.delay(scan_session_id)

        logger.info("Resumed scan session: %s", scan_session.session_name)
        return f"Resumed scan session {scan_session_id}"

    except Exception as e:
        logger.error("Error resuming scan session: %s", e)
        return f"Error resuming scan session: {e}"


@shared_task
def cancel_scan_session(scan_session_id: str):
    """Cancel a scan session"""
    try:
        scan_session = ScanSession.objects.get(id=scan_session_id)

        # Cancel running tool executions
        ToolExecution.objects.filter(
            scan_session=scan_session,
            status=ToolStatus.RUNNING
        ).update(status=ToolStatus.FAILED, error_message="Scan cancelled by user")

        logger.info("Cancelled scan session: %s", scan_session.session_name)
        return f"Cancelled scan session {scan_session_id}"

    except Exception as e:
        logger.error("Error cancelling scan session: %s", e)
        return f"Error cancelling scan session: {e}"


@shared_task
def cleanup_old_scan_data():
    """Clean up old scan data"""
    try:
        # Remove scan sessions older than retention period
        retention_days = settings.PENTEST_CONFIG.get('EVIDENCE_RETENTION_DAYS', 90)
        cutoff_date = timezone.now() - timedelta(days=retention_days)

        old_sessions = ScanSession.objects.filter(created_at__lt=cutoff_date)
        count = old_sessions.count()

        old_sessions.delete()

        logger.info("Cleaned up %s old scan sessions", count)
        return f"Cleaned up {count} old scan sessions"

    except Exception as e:
        logger.error("Error cleaning up old scan data: %s", e)
        return f"Error cleaning up old scan data: {e}"


@shared_task
def check_stuck_scan_sessions():
    """Check for stuck scan sessions and mark them as failed"""
    try:
        # Find scans that have been running for more than 24 hours
        stuck_cutoff = timezone.now() - timedelta(hours=24)

        stuck_sessions = ScanSession.objects.filter(
            status=ScanStatus.RUNNING,
            started_at__lt=stuck_cutoff
        )

        count = stuck_sessions.count()

        stuck_sessions.update(
            status=ScanStatus.FAILED,
            completed_at=timezone.now()
        )

        # Also update stuck tool executions
        stuck_tools = ToolExecution.objects.filter(
            status=ToolStatus.RUNNING,
            started_at__lt=stuck_cutoff
        )

        stuck_tools.update(
            status=ToolStatus.FAILED,
            completed_at=timezone.now(),
            error_message="Tool execution stuck - marked as failed"
        )

        logger.info("Marked %s stuck scan sessions as failed", count)
        return f"Marked {count} stuck scan sessions as failed"

    except Exception as e:
        logger.error("Error checking stuck scan sessions: %s", e)
        return f"Error checking stuck scan sessions: {e}"


@shared_task
def update_nuclei_templates():
    """Update Nuclei templates"""
    try:
        from tools.vulnerability_testing.nuclei_scanner import NucleiTemplateTool

        tool = NucleiTemplateTool()
        if tool.is_available():
            config = ToolConfig(
                target="",  # Not needed for template updates
                output_dir="/tmp/nuclei_update"
            )

            result = tool.execute(config)
            logger.info("Nuclei template update: %s", result.status)
            return f"Nuclei templates updated: {result.status}"
        else:
            logger.warning("Nuclei not available for template update")
            return "Nuclei not available"

    except Exception as e:
        logger.error("Error updating nuclei templates: %s", e)
        return f"Error updating nuclei templates: {e}"


@shared_task
def generate_daily_statistics():
    """Generate daily scan statistics"""
    try:
        today = timezone.now().date()

        # Count today's activities
        stats = {
            'date': today.isoformat(),
            'scans_started': ScanSession.objects.filter(created_at__date=today).count(),
            'scans_completed': ScanSession.objects.filter(
                completed_at__date=today,
                status=ScanStatus.COMPLETED
            ).count(),
            'vulnerabilities_found': Vulnerability.objects.filter(
                discovered_at__date=today
            ).count(),
            'critical_vulns_found': Vulnerability.objects.filter(
                discovered_at__date=today,
                severity='critical'
            ).count()
        }

        logger.info("Daily stats: %s", stats)
        return stats

    except Exception as e:
        logger.error("Error generating daily statistics: %s", e)
        return f"Error generating daily statistics: {e}"


def normalize_severity(severity: str) -> str:
    """Normalize severity levels"""
    severity_map = {
        'critical': 'critical',
        'high': 'high',
        'medium': 'medium',
        'low': 'low',
        'info': 'info',
        'informational': 'info'
    }

    return severity_map.get(severity.lower(), 'info')
