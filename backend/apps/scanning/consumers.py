"""
WebSocket consumers for real-time scan updates
backend/apps/scanning/consumers.py
"""

import json
import logging
from typing import Dict, Any
from channels.generic.websocket import AsyncWebsocketConsumer
from channels.db import database_sync_to_async
from django.core.exceptions import ObjectDoesNotExist

from .models import ScanSession, ToolExecution

logger = logging.getLogger(__name__)


class ScanProgressConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for scan progress updates"""
    
    async def connect(self):
        """Handle WebSocket connection"""
        self.scan_id = self.scope['url_route']['kwargs']['scan_id']
        self.scan_group_name = f'scan_{self.scan_id}'
        
        # Verify scan exists
        scan_exists = await self.verify_scan_exists(self.scan_id)
        if not scan_exists:
            await self.close(code=4004)
            return
        
        # Join scan group
        await self.channel_layer.group_add(
            self.scan_group_name,
            self.channel_name
        )
        
        await self.accept()
        
        # Send initial scan status
        await self.send_scan_status()
        
        logger.info(f"WebSocket connected for scan {self.scan_id}")
    
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection"""
        await self.channel_layer.group_discard(
            self.scan_group_name,
            self.channel_name
        )
        
        logger.info(f"WebSocket disconnected for scan {self.scan_id} (code: {close_code})")
    
    async def receive(self, text_data):
        """Handle messages from WebSocket"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'get_status':
                await self.send_scan_status()
            elif message_type == 'get_tools':
                await self.send_tool_status()
            elif message_type == 'pause_scan':
                await self.pause_scan()
            elif message_type == 'resume_scan':
                await self.resume_scan()
            elif message_type == 'cancel_scan':
                await self.cancel_scan()
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
            logger.error(f"Error handling WebSocket message: {e}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Internal server error'
            }))
    
    async def scan_update(self, event):
        """Handle scan update from group"""
        await self.send(text_data=json.dumps({
            'type': 'scan_update',
            'data': event['data']
        }))
    
    async def tool_update(self, event):
        """Handle tool execution update from group"""
        await self.send(text_data=json.dumps({
            'type': 'tool_update',
            'data': event['data']
        }))
    
    async def scan_completed(self, event):
        """Handle scan completion"""
        await self.send(text_data=json.dumps({
            'type': 'scan_completed',
            'data': event['data']
        }))
    
    async def scan_failed(self, event):
        """Handle scan failure"""
        await self.send(text_data=json.dumps({
            'type': 'scan_failed',
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
    def get_scan_data(self) -> Dict[str, Any]:
        """Get current scan session data"""
        try:
            scan = ScanSession.objects.select_related('target').get(id=self.scan_id)
            return {
                'id': str(scan.id),
                'session_name': scan.session_name,
                'status': scan.status,
                'current_phase': scan.current_phase,
                'total_progress': scan.total_progress,
                'phase_progress': scan.phase_progress,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'estimated_completion': scan.estimated_completion.isoformat() if scan.estimated_completion else None,
                'target': {
                    'name': scan.target.target_name,
                    'url': scan.target.main_url
                },
                'statistics': {
                    'subdomains_found': scan.total_subdomains_found,
                    'endpoints_found': scan.total_endpoints_found,
                    'vulnerabilities_found': scan.total_vulnerabilities,
                    'critical_vulnerabilities': scan.critical_vulnerabilities,
                    'high_vulnerabilities': scan.high_vulnerabilities
                }
            }
        except ObjectDoesNotExist:
            return {}
    
    @database_sync_to_async
    def get_tool_executions(self) -> List[Dict[str, Any]]:
        """Get tool execution data for the scan"""
        try:
            scan = ScanSession.objects.get(id=self.scan_id)
            tools = scan.tool_executions.all().order_by('-created_at')
            
            return [{
                'id': str(tool.id),
                'tool_name': tool.tool_name,
                'tool_category': tool.tool_category,
                'status': tool.status,
                'started_at': tool.started_at.isoformat() if tool.started_at else None,
                'completed_at': tool.completed_at.isoformat() if tool.completed_at else None,
                'execution_time': tool.execution_time_seconds,
                'results_count': tool.parsed_results_count,
                'error_message': tool.error_message
            } for tool in tools]
            
        except ObjectDoesNotExist:
            return []
    
    async def send_scan_status(self):
        """Send current scan status to client"""
        scan_data = await self.get_scan_data()
        if scan_data:
            await self.send(text_data=json.dumps({
                'type': 'scan_status',
                'data': scan_data
            }))
    
    async def send_tool_status(self):
        """Send tool execution status to client"""
        tool_data = await self.get_tool_executions()
        await self.send(text_data=json.dumps({
            'type': 'tool_status',
            'data': tool_data
        }))
    
    async def pause_scan(self):
        """Pause the scan session"""
        try:
            from .tasks import pause_scan_session
            pause_scan_session.delay(str(self.scan_id))
            
            await self.send(text_data=json.dumps({
                'type': 'scan_paused',
                'message': 'Scan pause initiated'
            }))
        except Exception as e:
            logger.error(f"Error pausing scan: {e}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Failed to pause scan'
            }))
    
    async def resume_scan(self):
        """Resume the scan session"""
        try:
            from .tasks import resume_scan_session
            resume_scan_session.delay(str(self.scan_id))
            
            await self.send(text_data=json.dumps({
                'type': 'scan_resumed',
                'message': 'Scan resume initiated'
            }))
        except Exception as e:
            logger.error(f"Error resuming scan: {e}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Failed to resume scan'
            }))
    
    async def cancel_scan(self):
        """Cancel the scan session"""
        try:
            from .tasks import cancel_scan_session
            cancel_scan_session.delay(str(self.scan_id))
            
            await self.send(text_data=json.dumps({
                'type': 'scan_cancelled',
                'message': 'Scan cancellation initiated'
            }))
        except Exception as e:
            logger.error(f"Error cancelling scan: {e}")
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Failed to cancel scan'
            }))


class ToolExecutionConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for individual tool execution updates"""
    
    async def connect(self):
        """Handle WebSocket connection"""
        self.execution_id = self.scope['url_route']['kwargs']['execution_id']
        self.execution_group_name = f'tool_{self.execution_id}'
        
        # Verify tool execution exists
        execution_exists = await self.verify_execution_exists(self.execution_id)
        if not execution_exists:
            await self.close(code=4004)
            return
        
        # Join execution group
        await self.channel_layer.group_add(
            self.execution_group_name,
            self.channel_name
        )
        
        await self.accept()
        
        # Send initial execution status
        await self.send_execution_status()
        
        logger.info(f"WebSocket connected for tool execution {self.execution_id}")
    
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection"""
        await self.channel_layer.group_discard(
            self.execution_group_name,
            self.channel_name
        )
        
        logger.info(f"WebSocket disconnected for tool execution {self.execution_id}")
    
    async def receive(self, text_data):
        """Handle messages from WebSocket"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'get_status':
                await self.send_execution_status()
            elif message_type == 'get_output':
                await self.send_tool_output()
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
    
    async def execution_update(self, event):
        """Handle execution update from group"""
        await self.send(text_data=json.dumps({
            'type': 'execution_update',
            'data': event['data']
        }))
    
    async def execution_completed(self, event):
        """Handle execution completion"""
        await self.send(text_data=json.dumps({
            'type': 'execution_completed',
            'data': event['data']
        }))
    
    @database_sync_to_async
    def verify_execution_exists(self, execution_id: str) -> bool:
        """Verify that the tool execution exists"""
        try:
            ToolExecution.objects.get(id=execution_id)
            return True
        except ObjectDoesNotExist:
            return False
    
    @database_sync_to_async
    def get_execution_data(self) -> Dict[str, Any]:
        """Get current tool execution data"""
        try:
            execution = ToolExecution.objects.select_related('scan_session').get(id=self.execution_id)
            return {
                'id': str(execution.id),
                'tool_name': execution.tool_name,
                'tool_category': execution.tool_category,
                'command_executed': execution.command_executed,
                'status': execution.status,
                'started_at': execution.started_at.isoformat() if execution.started_at else None,
                'completed_at': execution.completed_at.isoformat() if execution.completed_at else None,
                'execution_time': execution.execution_time_seconds,
                'results_count': execution.parsed_results_count,
                'error_message': execution.error_message,
                'scan_session': {
                    'id': str(execution.scan_session.id),
                    'name': execution.scan_session.session_name
                }
            }
        except ObjectDoesNotExist:
            return {}
    
    async def send_execution_status(self):
        """Send current execution status to client"""
        execution_data = await self.get_execution_data()
        if execution_data:
            await self.send(text_data=json.dumps({
                'type': 'execution_status',
                'data': execution_data
            }))
    
    async def send_tool_output(self):
        """Send tool output to client"""
        try:
            execution = await database_sync_to_async(ToolExecution.objects.get)(id=self.execution_id)
            await self.send(text_data=json.dumps({
                'type': 'tool_output',
                'data': {
                    'stdout': execution.raw_output[:5000] if execution.raw_output else '',  # Limit output size
                    'stderr': execution.error_message or '',
                    'command': execution.command_executed
                }
            }))
        except ObjectDoesNotExist:
            await self.send(text_data=json.dumps({
                'type': 'error',
                'message': 'Tool execution not found'
            }))


class NotificationConsumer(AsyncWebsocketConsumer):
    """WebSocket consumer for general notifications"""
    
    async def connect(self):
        """Handle WebSocket connection"""
        self.notification_group_name = 'notifications'
        
        # Join notification group
        await self.channel_layer.group_add(
            self.notification_group_name,
            self.channel_name
        )
        
        await self.accept()
        logger.info("WebSocket connected for notifications")
    
    async def disconnect(self, close_code):
        """Handle WebSocket disconnection"""
        await self.channel_layer.group_discard(
            self.notification_group_name,
            self.channel_name
        )
        logger.info(f"WebSocket disconnected from notifications (code: {close_code})")
    
    async def receive(self, text_data):
        """Handle messages from WebSocket"""
        try:
            data = json.loads(text_data)
            message_type = data.get('type')
            
            if message_type == 'ping':
                await self.send(text_data=json.dumps({
                    'type': 'pong',
                    'timestamp': data.get('timestamp')
                }))
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
    
    async def notification(self, event):
        """Handle notification from group"""
        await self.send(text_data=json.dumps({
            'type': 'notification',
            'data': event['data']
        }))
    
    async def scan_started(self, event):
        """Handle scan started notification"""
        await self.send(text_data=json.dumps({
            'type': 'scan_started',
            'data': event['data']
        }))
    
    async def scan_completed(self, event):
        """Handle scan completed notification"""
        await self.send(text_data=json.dumps({
            'type': 'scan_completed',
            'data': event['data']
        }))
    
    async def vulnerability_found(self, event):
        """Handle vulnerability found notification"""
        await self.send(text_data=json.dumps({
            'type': 'vulnerability_found',
            'data': event['data']
        }))
