"""
WebSocket consumers for vulnerability updates
backend/apps/vulnerabilities/consumers.py
"""

import json
import logging
from typing import Dict, Any, List
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.core.exceptions import ObjectDoesNotExist

from .models import Vulnerability, ExploitationChain
from apps.scanning.models import ScanSession

logger = logging.getLogger(__name__)


class VulnerabilityConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for vulnerability discovery updates"""

    async def connect(self):
        """Handle WebSocket connection"""
        self.scan_id = self.scope['url_route']['kwargs']['scan_id']
        self.vuln_group_name = f'vulnerabilities_{self.scan_id}'

        # Verify scan exists
        scan_exists = await self.verify_scan_exists(self.scan_id)
        if not scan_exists:
            await self.close(code=4004)
            return

        # Join vulnerability group
        await self.channel_layer.group_add(
            self.vuln_group_name,
            self.channel_name
        )

        await self.accept()

        # Send initial vulnerability data
        await self.send_vulnerability_summary()

        logger.info("WebSocket connected for vulnerabilities in scan %s", self.scan_id)

    async def disconnect(self, close_code):
        """Handle WebSocket disconnection"""
        await self.channel_layer.group_discard(
            self.vuln_group_name,
            self.channel_name
        )

        logger.info("WebSocket disconnected from vulnerabilities (code: %s)", close_code)

    async def receive(self, text_data):
        """Handle messages from WebSocket"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')

            if message_type == 'get_summary':
                await self.send_vulnerability_summary()
            elif message_type == 'get_vulnerabilities':
                await self.send_vulnerabilities()
            elif message_type == 'get_vulnerability_details':
                vuln_id = data.get('vulnerability_id')
                if vuln_id:
                    await self.send_vulnerability_details(vuln_id)
            else:
                await self.send(text_data=json.dumps({
                    'type': 'error',
                    'message': f'Unknown message type: {message_type}'
                }))

        except json.JSONDecodeError:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Invalid JSON format'
            }))
        except Exception as e:
            logger.error("Error handling WebSocket message: %s", e)
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Internal server error'
            }))

    async def vulnerability_found(self, event):
        """Handle new vulnerability discovery"""
        await self.send(text_data=json.dumps({
            'type': 'vulnerability_found',
            'data': event['data']
        }))

    async def vulnerability_updated(self, event):
        """Handle vulnerability update"""
        await self.send(text_data=json.dumps({
            'type': 'vulnerability_updated',
            'data': event['data']
        }))

    async def exploitation_attempt(self, event):
        """Handle exploitation attempt"""
        await self.send(text_data=json.dumps({
            'type': 'exploitation_attempt',
            'data': event['data']
        }))

    @database_sync_to_async
    def verify_scan_exists(self, scan_id: str) -> bool:
        """Verify that the scan session exists"""
        try:
            ScanSession.objects.get(id=scan_id)
            return True
        except ObjectDoesNotExist:
            return False

    @database_sync_to_async
    def get_vulnerability_summary(self) -> Dict[str, Any]:
        """Get vulnerability summary for the scan"""
        try:
            scan = ScanSession.objects.get(id=self.scan_id)
            vulnerabilities = Vulnerability.objects.filter(scan_session=scan)

            summary = {
                'scan_id': str(scan.id),
                'scan_name': scan.session_name,
                'total_vulnerabilities': vulnerabilities.count(),
                'by_severity': {
                    'critical': vulnerabilities.filter(severity='critical').count(),
                    'high': vulnerabilities.filter(severity='high').count(),
                    'medium': vulnerabilities.filter(severity='medium').count(),
                    'low': vulnerabilities.filter(severity='low').count(),
                    'info': vulnerabilities.filter(severity='info').count(),
                },
                'verified_count': vulnerabilities.filter(manually_verified=True).count(),
                'exploitable_count': vulnerabilities.filter(is_exploitable=True).count(),
                'latest_vulnerability': None
            }

            # Get latest vulnerability
            latest = vulnerabilities.order_by('-discovered_at').first()
            if latest:
                summary['latest_vulnerability'] = {
                    'id': str(latest.id),
                    'name': latest.vulnerability_name,
                    'severity': latest.severity,
                    'url': latest.affected_url,
                    'discovered_at': latest.discovered_at.isoformat()
                }

            return summary

        except ObjectDoesNotExist:
            return {}

    @database_sync_to_async
    def get_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get all vulnerabilities for the scan"""
        try:
            scan = ScanSession.objects.get(id=self.scan_id)
            vulnerabilities = Vulnerability.objects.filter(scan_session=scan).order_by('-discovered_at')

            return [{
                'id': str(vuln.id),
                'name': vuln.vulnerability_name,
                'type': vuln.vulnerability_type,
                'severity': vuln.severity,
                'cvss_score': vuln.cvss_score,
                'url': vuln.affected_url,
                'parameter': vuln.affected_parameter,
                'owasp_category': vuln.owasp_category,
                'cwe_id': vuln.cwe_id,
                'discovered_by': vuln.discovered_by_tool,
                'discovered_at': vuln.discovered_at.isoformat(),
                'manually_verified': vuln.manually_verified,
                'is_exploitable': vuln.is_exploitable,
                'confidence_level': vuln.confidence_level,
                'false_positive_likelihood': vuln.false_positive_likelihood
            } for vuln in vulnerabilities]

        except ObjectDoesNotExist:
            return []

    @database_sync_to_async
    def get_vulnerability_details(self, vuln_id: str) -> Dict[str, Any]:
        """Get detailed information for a specific vulnerability"""
        try:
            vuln = Vulnerability.objects.select_related('scan_session').get(id=vuln_id)

            # Get exploitation chains
            chains = ExploitationChain.objects.filter(vulnerability=vuln).order_by('step_number')

            chain_data = []
            for chain in chains:
                chain_data.append({
                    'id': str(chain.id),
                    'chain_name': chain.chain_name,
                    'step_number': chain.step_number,
                    'total_steps': chain.total_steps,
                    'step_description': chain.step_description,
                    'payload': chain.payload,
                    'expected_result': chain.expected_result,
                    'actual_result': chain.actual_result,
                    'step_successful': chain.step_successful,
                    'chain_successful': chain.chain_successful,
                    'executed_at': chain.executed_at.isoformat()
                })

            return {
                'id': str(vuln.id),
                'name': vuln.vulnerability_name,
                'type': vuln.vulnerability_type,
                'severity': vuln.severity,
                'cvss_score': vuln.cvss_score,
                'description': vuln.impact_description,
                'url': vuln.affected_url,
                'parameter': vuln.affected_parameter,
                'http_method': vuln.http_method,
                'owasp_category': vuln.owasp_category,
                'cwe_id': vuln.cwe_id,
                'discovered_by': vuln.discovered_by_tool,
                'discovery_method': vuln.discovery_method,
                'discovered_at': vuln.discovered_at.isoformat(),
                'payload_used': vuln.payload_used,
                'request_data': vuln.request_data,
                'response_data': vuln.response_data,
                'screenshot_paths': vuln.screenshot_paths,
                'additional_evidence': vuln.additional_evidence,
                'manually_verified': vuln.manually_verified,
                'verification_notes': vuln.verification_notes,
                'is_exploitable': vuln.is_exploitable,
                'exploitation_difficulty': vuln.exploitation_difficulty,
                'exploitation_notes': vuln.exploitation_notes,
                'remediation_suggestion': vuln.remediation_suggestion,
                'remediation_priority': vuln.remediation_priority,
                'confidence_level': vuln.confidence_level,
                'false_positive_likelihood': vuln.false_positive_likelihood,
                'exploitation_chains': chain_data,
                'scan_session': {
                    'id': str(vuln.scan_session.id),
                    'name': vuln.scan_session.session_name
                }
            }

        except ObjectDoesNotExist:
            return {}

    async def send_vulnerability_summary(self):
        """Send vulnerability summary to client"""
        summary = await self.get_vulnerability_summary()
        if summary:
            await self.send(text_data=json.dumps({
                'type': 'vulnerability_summary',
                'data': summary
            }))

    async def send_vulnerabilities(self):
        """Send all vulnerabilities to client"""
        vulnerabilities = await self.get_vulnerabilities()
        await self.send(text_data=json.dumps({
            'type': 'vulnerabilities',
            'data': vulnerabilities
        }))

    async def send_vulnerability_details(self, vuln_id: str):
        """Send detailed vulnerability information to client"""
        details = await self.get_vulnerability_details(vuln_id)
        if details:
            await self.send(text_data=json.dumps({
                'type': 'vulnerability_details',
                'data': details
            }))
        else:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Vulnerability not found'
            }))
