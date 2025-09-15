"""
Scanning Management Serializers
backend/apps/scanning/serializers.py
"""

from rest_framework import serializers
from django.utils import timezone
from .models import ScanSession, ToolExecution, ScanStatus, ToolStatus
from apps.targets.serializers import TargetSummarySerializer

class ToolExecutionSerializer(serializers.ModelSerializer):
    """Serializer for tool execution tracking"""

    duration = serializers.SerializerMethodField()
    success_rate = serializers.SerializerMethodField()

    class Meta:
        model = ToolExecution
        fields = [
            'id', 'tool_name', 'tool_category', 'command_executed',
            'status', 'started_at', 'completed_at', 'execution_time_seconds',
            'output_file_path', 'parsed_results_count', 'error_message',
            'tool_parameters', 'created_at', 'duration', 'success_rate'
        ]
        read_only_fields = ['id', 'created_at', 'duration', 'success_rate']

    def get_duration(self, obj):
        """Get execution duration in human-readable format"""
        duration = obj.duration
        if duration:
            total_seconds = int(duration.total_seconds())
            minutes, seconds = divmod(total_seconds, 60)
            if minutes > 0:
                return f"{minutes}m {seconds}s"
            return f"{seconds}s"
        return None

    def get_success_rate(self, obj):
        """Get success rate for this tool"""
        return round(obj.success_rate, 2)

class ToolExecutionCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating tool executions"""

    class Meta:
        model = ToolExecution
        fields = [
            'scan_session', 'tool_name', 'tool_category',
            'command_executed', 'tool_parameters'
        ]

class ToolExecutionUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating tool execution status and results"""

    class Meta:
        model = ToolExecution
        fields = [
            'status', 'started_at', 'completed_at', 'execution_time_seconds',
            'output_file_path', 'raw_output', 'parsed_results_count',
            'error_message'
        ]

class ScanSessionSerializer(serializers.ModelSerializer):
    """Comprehensive serializer for scan sessions"""

    target = TargetSummarySerializer(read_only=True)
    target_id = serializers.UUIDField(write_only=True)
    duration = serializers.SerializerMethodField()
    vulnerability_summary = serializers.SerializerMethodField()
    tool_executions = ToolExecutionSerializer(many=True, read_only=True)
    progress_percentage = serializers.SerializerMethodField()

    class Meta:
        model = ScanSession
        fields = [
            'id', 'target', 'target_id', 'session_name', 'status',
            'scan_config', 'methodology_phases', 'current_phase',
            'phase_progress', 'total_progress', 'started_at', 'completed_at',
            'estimated_completion', 'total_subdomains_found', 'total_endpoints_found',
            'total_vulnerabilities', 'critical_vulnerabilities', 'high_vulnerabilities',
            'created_at', 'updated_at', 'duration', 'vulnerability_summary',
            'tool_executions', 'progress_percentage'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at', 'duration',
                           'vulnerability_summary', 'progress_percentage']

    def get_duration(self, obj):
        """Get scan duration"""
        duration = obj.duration
        if duration:
            total_seconds = int(duration.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            if hours > 0:
                return f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                return f"{minutes}m {seconds}s"
            return f"{seconds}s"
        return None

    def get_vulnerability_summary(self, obj):
        """Get vulnerability summary for this scan"""
        return obj.vulnerability_summary

    def get_progress_percentage(self, obj):
        """Get progress as percentage"""
        return round(obj.total_progress, 2)

    def validate_session_name(self, value):
        """Validate session name"""
        if len(value.strip()) < 3:
            raise serializers.ValidationError("Session name must be at least 3 characters")
        return value.strip()

    def validate_methodology_phases(self, value):
        """Validate methodology phases"""
        valid_phases = [
            'passive_recon', 'active_recon', 'vulnerability_testing',
            'exploitation', 'reporting'
        ]

        for phase in value:
            if phase not in valid_phases:
                raise serializers.ValidationError(f"Invalid phase: {phase}")

        return value

    def validate_scan_config(self, value):
        """Validate scan configuration"""
        if not isinstance(value, dict):
            raise serializers.ValidationError("Scan config must be a dictionary")

        # Validate required config sections
        required_sections = ['tools', 'rate_limiting']
        for section in required_sections:
            if section not in value:
                value[section] = {}

        return value

class ScanSessionCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating new scan sessions"""

    class Meta:
        model = ScanSession
        fields = [
            'target_id', 'session_name', 'scan_config', 'methodology_phases'
        ]

    def validate_target_id(self, value):
        """Validate target exists and is active"""
        from apps.targets.models import Target

        try:
            target = Target.objects.get(id=value)
            if not target.is_active:
                raise serializers.ValidationError("Cannot create scan for inactive target")
        except Target.DoesNotExist:
            raise serializers.ValidationError("Target does not exist")

        return value

class ScanSessionUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating scan sessions"""

    class Meta:
        model = ScanSession
        fields = [
            'session_name', 'status', 'current_phase', 'phase_progress',
            'total_progress', 'started_at', 'completed_at', 'estimated_completion',
            'total_subdomains_found', 'total_endpoints_found', 'total_vulnerabilities',
            'critical_vulnerabilities', 'high_vulnerabilities'
        ]

    def validate_status(self, value):
        """Validate status transitions"""
        if self.instance:
            current_status = self.instance.status

            # Define valid status transitions
            valid_transitions = {
                ScanStatus.QUEUED: [ScanStatus.RUNNING, ScanStatus.CANCELLED],
                ScanStatus.RUNNING: [ScanStatus.PAUSED, ScanStatus.COMPLETED,
                                   ScanStatus.FAILED, ScanStatus.CANCELLED],
                ScanStatus.PAUSED: [ScanStatus.RUNNING, ScanStatus.CANCELLED],
                ScanStatus.COMPLETED: [],  # No transitions from completed
                ScanStatus.FAILED: [ScanStatus.QUEUED],  # Can retry failed scans
                ScanStatus.CANCELLED: [ScanStatus.QUEUED],  # Can restart cancelled scans
            }

            if value not in valid_transitions.get(current_status, []):
                raise serializers.ValidationError(
                    f"Cannot transition from {current_status} to {value}"
                )

        return value

    def validate_total_progress(self, value):
        """Validate progress percentage"""
        if not 0 <= value <= 100:
            raise serializers.ValidationError("Progress must be between 0 and 100")
        return value

class ScanSessionSummarySerializer(serializers.ModelSerializer):
    """Lightweight serializer for scan session summaries"""

    target_name = serializers.CharField(source='target.target_name', read_only=True)
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    duration = serializers.SerializerMethodField()

    class Meta:
        model = ScanSession
        fields = [
            'id', 'session_name', 'target_name', 'status', 'status_display',
            'total_progress', 'created_at', 'started_at', 'completed_at',
            'total_vulnerabilities', 'critical_vulnerabilities', 'duration'
        ]

    def get_duration(self, obj):
        """Get scan duration"""
        duration = obj.duration
        if duration:
            total_seconds = int(duration.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            if hours > 0:
                return f"{hours}h {minutes}m"
            elif minutes > 0:
                return f"{minutes}m"
            return f"{seconds}s"
        elif obj.started_at and obj.status == ScanStatus.RUNNING:
            # Calculate running time
            running_time = timezone.now() - obj.started_at
            total_seconds = int(running_time.total_seconds())
            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)
            if hours > 0:
                return f"{hours}h {minutes}m (running)"
            elif minutes > 0:
                return f"{minutes}m (running)"
            return f"{seconds}s (running)"
        return None

class ScanSessionProgressSerializer(serializers.ModelSerializer):
    """Serializer for scan progress updates (WebSocket)"""

    class Meta:
        model = ScanSession
        fields = [
            'id', 'current_phase', 'phase_progress', 'total_progress',
            'status', 'total_subdomains_found', 'total_endpoints_found',
            'total_vulnerabilities', 'critical_vulnerabilities'
        ]
