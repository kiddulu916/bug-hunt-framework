"""
Scanning Management Filters
backend/apps/scanning/filters.py
"""

import django_filters
from django.db.models import Q
from .models import ScanSession, ToolExecution, ScanStatus, ToolStatus

class ScanSessionFilter(django_filters.FilterSet):
    """Advanced filtering for scan sessions"""
    
    # Status filtering
    status = django_filters.ChoiceFilter(
        choices=ScanStatus.choices,
        help_text="Filter by scan status"
    )
    
    # Target filtering
    target = django_filters.UUIDFilter(
        field_name='target__id',
        help_text="Filter by target ID"
    )
    target_name = django_filters.CharFilter(
        field_name='target__target_name',
        lookup_expr='icontains',
        help_text="Filter by target name (case-insensitive)"
    )
    
    # Date range filtering
    created_after = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='gte',
        help_text="Filter sessions created after this date"
    )
    created_before = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='lte',
        help_text="Filter sessions created before this date"
    )
    started_after = django_filters.DateTimeFilter(
        field_name='started_at',
        lookup_expr='gte',
        help_text="Filter sessions started after this date"
    )
    started_before = django_filters.DateTimeFilter(
        field_name='started_at',
        lookup_expr='lte',
        help_text="Filter sessions started before this date"
    )
    
    # Progress filtering
    min_progress = django_filters.NumberFilter(
        field_name='total_progress',
        lookup_expr='gte',
        help_text="Filter by minimum progress percentage"
    )
    max_progress = django_filters.NumberFilter(
        field_name='total_progress',
        lookup_expr='lte',
        help_text="Filter by maximum progress percentage"
    )
    
    # Vulnerability filtering
    has_vulnerabilities = django_filters.BooleanFilter(
        method='filter_has_vulnerabilities',
        help_text="Filter sessions with/without vulnerabilities"
    )
    min_vulnerabilities = django_filters.NumberFilter(
        field_name='total_vulnerabilities',
        lookup_expr='gte',
        help_text="Filter by minimum vulnerability count"
    )
    has_critical = django_filters.BooleanFilter(
        method='filter_has_critical',
        help_text="Filter sessions with/without critical vulnerabilities"
    )
    
    # Duration filtering
    duration_range = django_filters.ChoiceFilter(
        method='filter_duration_range',
        choices=[
            ('short', 'Short (< 1 hour)'),
            ('medium', 'Medium (1-6 hours)'),
            ('long', 'Long (> 6 hours)')
        ],
        help_text="Filter by scan duration"
    )
    
    # Active scans
    is_active = django_filters.BooleanFilter(
        method='filter_is_active',
        help_text="Filter active (running/queued) scans"
    )
    
    class Meta:
        model = ScanSession
        fields = [
            'status', 'target', 'target_name', 'created_after', 'created_before',
            'started_after', 'started_before', 'min_progress', 'max_progress',
            'has_vulnerabilities', 'min_vulnerabilities', 'has_critical',
            'duration_range', 'is_active'
        ]
    
    def filter_has_vulnerabilities(self, queryset, name, value):
        """Filter sessions with or without vulnerabilities"""
        if value is True:
            return queryset.filter(total_vulnerabilities__gt=0)
        elif value is False:
            return queryset.filter(total_vulnerabilities=0)
        return queryset
    
    def filter_has_critical(self, queryset, name, value):
        """Filter sessions with or without critical vulnerabilities"""
        if value is True:
            return queryset.filter(critical_vulnerabilities__gt=0)
        elif value is False:
            return queryset.filter(critical_vulnerabilities=0)
        return queryset
    
    def filter_duration_range(self, queryset, name, value):
        """Filter by scan duration ranges"""
        if not value:
            return queryset
        
        # Only consider completed scans for duration filtering
        completed_scans = queryset.filter(
            status=ScanStatus.COMPLETED,
            started_at__isnull=False,
            completed_at__isnull=False
        )
        
        if value == 'short':
            # Less than 1 hour (3600 seconds)
            return completed_scans.extra(
                where=["EXTRACT(EPOCH FROM (completed_at - started_at)) < 3600"]
            )
        elif value == 'medium':
            # 1-6 hours
            return completed_scans.extra(
                where=[
                    "EXTRACT(EPOCH FROM (completed_at - started_at)) >= 3600",
                    "EXTRACT(EPOCH FROM (completed_at - started_at)) <= 21600"
                ]
            )
        elif value == 'long':
            # More than 6 hours
            return completed_scans.extra(
                where=["EXTRACT(EPOCH FROM (completed_at - started_at)) > 21600"]
            )
        
        return queryset
    
    def filter_is_active(self, queryset, name, value):
        """Filter active (running or queued) scans"""
        if value is True:
            return queryset.filter(status__in=[ScanStatus.RUNNING, ScanStatus.QUEUED])
        elif value is False:
            return queryset.exclude(status__in=[ScanStatus.RUNNING, ScanStatus.QUEUED])
        return queryset

class ToolExecutionFilter(django_filters.FilterSet):
    """Advanced filtering for tool executions"""
    
    # Status filtering
    status = django_filters.ChoiceFilter(
        choices=ToolStatus.choices,
        help_text="Filter by tool execution status"
    )
    
    # Tool filtering
    tool_name = django_filters.CharFilter(
        lookup_expr='icontains',
        help_text="Filter by tool name (case-insensitive)"
    )
    tool_category = django_filters.CharFilter(
        lookup_expr='icontains',
        help_text="Filter by tool category"
    )
    
    # Scan session filtering
    scan_session = django_filters.UUIDFilter(
        field_name='scan_session__id',
        help_text="Filter by scan session ID"
    )
    target = django_filters.UUIDFilter(
        field_name='scan_session__target__id',
        help_text="Filter by target ID"
    )
    
    # Date range filtering
    created_after = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='gte',
        help_text="Filter executions created after this date"
    )
    created_before = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='lte',
        help_text="Filter executions created before this date"
    )
    
    # Execution time filtering
    min_execution_time = django_filters.NumberFilter(
        field_name='execution_time_seconds',
        lookup_expr='gte',
        help_text="Filter by minimum execution time (seconds)"
    )
    max_execution_time = django_filters.NumberFilter(
        field_name='execution_time_seconds',
        lookup_expr='lte',
        help_text="Filter by maximum execution time (seconds)"
    )
    
    # Results filtering
    has_results = django_filters.BooleanFilter(
        method='filter_has_results',
        help_text="Filter executions with/without results"
    )
    min_results = django_filters.NumberFilter(
        field_name='parsed_results_count',
        lookup_expr='gte',
        help_text="Filter by minimum results count"
    )
    
    # Error filtering
    has_errors = django_filters.BooleanFilter(
        method='filter_has_errors',
        help_text="Filter executions with/without errors"
    )
    
    class Meta:
        model = ToolExecution
        fields = [
            'status', 'tool_name', 'tool_category', 'scan_session', 'target',
            'created_after', 'created_before', 'min_execution_time', 'max_execution_time',
            'has_results', 'min_results', 'has_errors'
        ]
    
    def filter_has_results(self, queryset, name, value):
        """Filter executions with or without results"""
        if value is True:
            return queryset.filter(parsed_results_count__gt=0)
        elif value is False:
            return queryset.filter(parsed_results_count=0)
        return queryset
    
    def filter_has_errors(self, queryset, name, value):
        """Filter executions with or without errors"""
        if value is True:
            return queryset.filter(error_message__isnull=False).exclude(error_message='')
        elif value is False:
            return queryset.filter(Q(error_message__isnull=True) | Q(error_message=''))
        return queryset
      