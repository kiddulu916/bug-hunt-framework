"""
Scanning Management Views
backend/apps/scanning/views.py
"""

from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.filters import SearchFilter, OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from django.utils import timezone
from django.conf import settings
import logging

from .models import ScanSession, ToolExecution
from .serializers import ScanSessionSerializer, ToolExecutionSerializer
from .filters import ScanSessionFilter, ToolExecutionFilter
from .tasks import start_scan_session, execute_tool
from tools.base import list_tools, get_tool
from tools.orchestrator import create_full_scan_plan, ToolOrchestrator
from tools import get_tool_status

logger = logging.getLogger(__name__)


class ScanSessionViewSet(viewsets.ModelViewSet):
    """ViewSet for managing scan sessions"""
    
    queryset = ScanSession.objects.all()
    serializer_class = ScanSessionSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ScanSessionFilter
    search_fields = ['session_name', 'target__target_name']
    ordering_fields = ['created_at', 'started_at', 'completed_at']
    ordering = ['-created_at']
    
    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        """Start a scan session"""
        try:
            scan_session = self.get_object()
            
            if scan_session.status != 'pending':
                return Response(
                    {'error': 'Scan session is not in pending state'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Start the scan asynchronously
            task = start_scan_session.delay(str(scan_session.id))
            
            return Response({
                'message': 'Scan session started',
                'task_id': task.id,
                'scan_id': str(scan_session.id)
            })
            
        except Exception as e:
            logger.error(f"Error starting scan session: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'])
    def pause(self, request, pk=None):
        """Pause a running scan session"""
        try:
            scan_session = self.get_object()
            
            if scan_session.status != 'running':
                return Response(
                    {'error': 'Scan session is not running'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            from .tasks import pause_scan_session
            task = pause_scan_session.delay(str(scan_session.id))
            
            return Response({
                'message': 'Scan session pause initiated',
                'task_id': task.id
            })
            
        except Exception as e:
            logger.error(f"Error pausing scan session: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'])
    def resume(self, request, pk=None):
        """Resume a paused scan session"""
        try:
            scan_session = self.get_object()
            
            if scan_session.status != 'paused':
                return Response(
                    {'error': 'Scan session is not paused'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            from .tasks import resume_scan_session
            task = resume_scan_session.delay(str(scan_session.id))
            
            return Response({
                'message': 'Scan session resume initiated',
                'task_id': task.id
            })
            
        except Exception as e:
            logger.error(f"Error resuming scan session: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        """Cancel a scan session"""
        try:
            scan_session = self.get_object()
            
            if scan_session.status not in ['running', 'paused']:
                return Response(
                    {'error': 'Scan session cannot be cancelled'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            from .tasks import cancel_scan_session
            task = cancel_scan_session.delay(str(scan_session.id))
            
            return Response({
                'message': 'Scan session cancellation initiated',
                'task_id': task.id
            })
            
        except Exception as e:
            logger.error(f"Error cancelling scan session: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['get'])
    def tools(self, request, pk=None):
        """Get tool executions for a scan session"""
        try:
            scan_session = self.get_object()
            tools = scan_session.tool_executions.all().order_by('-created_at')
            serializer = ToolExecutionSerializer(tools, many=True)
            return Response(serializer.data)
            
        except Exception as e:
            logger.error(f"Error getting scan tools: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'])
    def execute_tool(self, request, pk=None):
        """Execute a specific tool against the scan target"""
        try:
            scan_session = self.get_object()
            tool_name = request.data.get('tool_name')
            target = request.data.get('target', scan_session.target.main_url)
            custom_params = request.data.get('custom_params', {})
            
            if not tool_name:
                return Response(
                    {'error': 'tool_name is required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Verify tool exists
            tool = get_tool(tool_name)
            if not tool:
                return Response(
                    {'error': f'Tool {tool_name} not found'},
                    status=status.HTTP_404_NOT_FOUND
                )
            
            if not tool.is_available():
                return Response(
                    {'error': f'Tool {tool_name} is not available'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Execute tool
            task = execute_tool.delay(
                str(scan_session.id),
                tool_name,
                target,
                custom_params
            )
            
            return Response({
                'message': f'Tool {tool_name} execution started',
                'task_id': task.id,
                'tool_name': tool_name,
                'target': target
            })
            
        except Exception as e:
            logger.error(f"Error executing tool: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['get'])
    def available_tools(self, request):
        """Get list of available tools"""
        try:
            tools = list_tools()
            tool_status = get_tool_status()
            
            return Response({
                'tools_by_category': tools,
                'tool_details': tool_status,
                'total_tools': sum(len(category_tools) for category_tools in tools.values())
            })
            
        except Exception as e:
            logger.error(f"Error getting available tools: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=False, methods=['post'])
    def create_orchestrated_scan(self, request):
        """Create and start an orchestrated scan session"""
        try:
            target_id = request.data.get('target_id')
            scan_name = request.data.get('scan_name')
            methodology_phases = request.data.get('methodology_phases', [
                'passive_recon', 'active_recon', 'vulnerability_testing'
            ])
            
            if not target_id or not scan_name:
                return Response(
                    {'error': 'target_id and scan_name are required'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            from apps.targets.models import Target
            target = Target.objects.get(id=target_id)
            
            # Create scan session
            scan_session = ScanSession.objects.create(
                session_name=scan_name,
                target=target,
                methodology_phases=methodology_phases,
                scan_type='comprehensive',
                created_by_user='system'  # TODO: Get from request.user
            )
            
            # Create orchestration plan
            plan = create_full_scan_plan(str(scan_session.id), target)
            
            # Start orchestrated scan
            from .tasks import execute_orchestrated_scan
            task = execute_orchestrated_scan.delay(str(scan_session.id), plan.__dict__)
            
            serializer = self.get_serializer(scan_session)
            
            return Response({
                'scan_session': serializer.data,
                'orchestration_plan': {
                    'total_steps': len(plan.steps),
                    'strategy': plan.strategy.value,
                    'max_concurrent_tools': plan.max_concurrent_tools
                },
                'task_id': task.id,
                'message': 'Orchestrated scan started'
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Error creating orchestrated scan: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ToolExecutionViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for viewing tool executions"""
    
    queryset = ToolExecution.objects.all()
    serializer_class = ToolExecutionSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = ToolExecutionFilter
    search_fields = ['tool_name', 'scan_session__session_name']
    ordering_fields = ['created_at', 'started_at', 'completed_at', 'execution_time_seconds']
    ordering = ['-created_at']
    
    @action(detail=True, methods=['get'])
    def output(self, request, pk=None):
        """Get tool execution output"""
        try:
            tool_execution = self.get_object()
            
            return Response({
                'tool_name': tool_execution.tool_name,
                'command_executed': tool_execution.command_executed,
                'raw_output': tool_execution.raw_output,
                'error_message': tool_execution.error_message,
                'output_file_path': tool_execution.output_file_path,
                'execution_time': tool_execution.execution_time_seconds
            })
            
        except Exception as e:
            logger.error(f"Error getting tool output: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )
    
    @action(detail=True, methods=['post'])
    def retry(self, request, pk=None):
        """Retry a failed tool execution"""
        try:
            tool_execution = self.get_object()
            
            if tool_execution.status not in ['failed', 'timeout']:
                return Response(
                    {'error': 'Only failed or timed out executions can be retried'},
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Get original parameters
            custom_params = tool_execution.tool_parameters
            
            # Execute tool again
            task = execute_tool.delay(
                str(tool_execution.scan_session.id),
                tool_execution.tool_name,
                custom_params.get('target', tool_execution.scan_session.target.main_url),
                custom_params
            )
            
            return Response({
                'message': f'Tool {tool_execution.tool_name} retry initiated',
                'task_id': task.id
            })
            
        except Exception as e:
            logger.error(f"Error retrying tool execution: {e}")
            return Response(
                {'error': str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )