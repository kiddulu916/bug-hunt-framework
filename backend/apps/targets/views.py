"""
Target Management API Views
backend/apps/targets/views.py
"""

import logging
from datetime import timedelta
from rest_framework import viewsets, status, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.filters import SearchFilter, OrderingFilter
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Count
from django.utils import timezone

from .models import Target
from .serializers import (
    TargetSerializer, TargetCreateSerializer, TargetUpdateSerializer,
    TargetSummarySerializer, TargetScopeSerializer, TargetConfigSerializer
)
from .filters import TargetFilter
from .permissions import TargetPermissions


class TargetViewSet(viewsets.ModelViewSet):
    """
    ViewSet for managing penetration testing targets

    Provides CRUD operations for targets with additional actions for:
    - Scope management
    - Configuration updates
    - Statistics and analytics
    - Target validation
    """

    queryset = Target.objects.select_related().prefetch_related(
        'scan_sessions'
    )
    permission_classes = [permissions.IsAuthenticated, TargetPermissions]
    filter_backends = [DjangoFilterBackend, SearchFilter, OrderingFilter]
    filterset_class = TargetFilter
    search_fields = ['target_name', 'main_url', 'researcher_username']
    ordering_fields = ['created_at', 'updated_at', 'target_name']
    ordering = ['-created_at']

    def get_serializer_class(self):
        """Return appropriate serializer based on action"""
        if self.action == 'create':
            return TargetCreateSerializer
        elif self.action in ['update', 'partial_update']:
            return TargetUpdateSerializer
        elif self.action == 'list':
            return TargetSummarySerializer
        elif self.action == 'scope':
            return TargetScopeSerializer
        elif self.action == 'config':
            return TargetConfigSerializer
        return TargetSerializer

    def get_queryset(self):
        """Filter queryset based on user permissions and query parameters"""
        queryset = super().get_queryset()

        # Annotate with scan session count
        queryset = queryset.annotate(
            total_scan_sessions=Count('scan_sessions')
        )

        # Filter by active status if specified
        active_only = self.request.query_params.get('active_only', None)
        if active_only and active_only.lower() == 'true':
            queryset = queryset.filter(is_active=True)

        # Filter by platform
        platform = self.request.query_params.get('platform', None)
        if platform:
            queryset = queryset.filter(platform=platform)

        # Filter by recent activity
        recent_days = self.request.query_params.get('recent_days', None)
        if recent_days:
            try:
                days = int(recent_days)
                since_date = timezone.now() - timedelta(days=days)
                queryset = queryset.filter(updated_at__gte=since_date)
            except ValueError:
                pass

        return queryset

    def create(self, request, *args, **kwargs):
        """Create a new target with validation"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        # Additional business logic validation
        target_name = serializer.validated_data['target_name']
        if Target.objects.filter(target_name__iexact=target_name).exists():
            return Response(
                {'error': 'A target with this name already exists'},
                status=status.HTTP_400_BAD_REQUEST
            )

        target = serializer.save()

        # Return full target data
        response_serializer = TargetSerializer(target)
        return Response(response_serializer.data, status=status.HTTP_201_CREATED)

    def update(self, request, *args, **kwargs):
        """Update target with change tracking"""
        partial = kwargs.pop('partial', False)
        instance = self.get_object()

        # Track changes for audit logging
        old_data = TargetSerializer(instance).data

        serializer = self.get_serializer(
            instance, data=request.data, partial=partial
        )
        serializer.is_valid(raise_exception=True)

        target = serializer.save()

        # Log significant changes
        new_data = TargetSerializer(target).data
        self._log_target_changes(old_data, new_data, request.user)

        return Response(TargetSerializer(target).data)

    @action(detail=True, methods=['get', 'patch'])
    def scope(self, request, pk=None):
        """Manage target scope (in-scope and out-of-scope assets)"""
        target = self.get_object()

        if request.method == 'GET':
            serializer = TargetScopeSerializer(target)
            return Response(serializer.data)

        elif request.method == 'PATCH':
            serializer = TargetScopeSerializer(
                target, data=request.data, partial=True
            )
            serializer.is_valid(raise_exception=True)
            target = serializer.save()

            return Response({
                'message': 'Scope updated successfully',
                'scope': TargetScopeSerializer(target).data
            })

    @action(detail=True, methods=['get', 'patch'])
    def config(self, request, pk=None):
        """Manage target configuration (rate limiting, headers, etc.)"""
        target = self.get_object()

        if request.method == 'GET':
            serializer = TargetConfigSerializer(target)
            return Response(serializer.data)

        elif request.method == 'PATCH':
            serializer = TargetConfigSerializer(
                target, data=request.data, partial=True
            )
            serializer.is_valid(raise_exception=True)
            target = serializer.save()

            return Response({
                'message': 'Configuration updated successfully',
                'config': TargetConfigSerializer(target).data
            })

    @action(detail=True, methods=['post'])
    def validate_scope(self, request, pk=None):
        """Validate target scope against provided URLs/assets"""
        target = self.get_object()

        urls_to_check = request.data.get('urls', [])
        if not urls_to_check:
            return Response(
                {'error': 'No URLs provided for validation'},
                status=status.HTTP_400_BAD_REQUEST
            )

        results = []
        for url in urls_to_check:
            is_in_scope = self._check_url_scope(url, target)
            results.append({
                'url': url,
                'in_scope': is_in_scope,
                'reason': self._get_scope_reason(url, target, is_in_scope)
            })

        return Response({
            'target': target.target_name,
            'validation_results': results,
            'total_checked': len(urls_to_check),
            'in_scope_count': sum(1 for r in results if r['in_scope']),
            'out_of_scope_count': sum(1 for r in results if not r['in_scope'])
        })

    @action(detail=True, methods=['get'])
    def statistics(self, request, pk=None):
        """Get detailed statistics for a target"""
        target = self.get_object()

        # Get scan session statistics
        scan_sessions = target.scan_sessions.all()

        stats = {
            'target_info': {
                'name': target.target_name,
                'platform': target.get_platform_display(),
                'created_at': target.created_at,
                'last_updated': target.updated_at,
            },
            'scope_statistics': target.get_scope_summary(),
            'scan_statistics': {
                'total_sessions': scan_sessions.count(),
                'completed_sessions': scan_sessions.filter(
                    status='completed'
                ).count(),
                'running_sessions': scan_sessions.filter(
                    status='running'
                ).count(),
                'failed_sessions': scan_sessions.filter(
                    status='failed'
                ).count(),
            },
            'recent_activity': {
                'last_scan': None,
                'scans_last_30_days': 0,
                'total_vulnerabilities': 0,
                'critical_vulnerabilities': 0,
            }
        }

        # Get recent scan data
        latest_scan = scan_sessions.order_by('-created_at').first()
        if latest_scan:
            stats['recent_activity']['last_scan'] = {
                'id': str(latest_scan.id),
                'name': latest_scan.session_name,
                'status': latest_scan.status,
                'created_at': latest_scan.created_at,
                'progress': latest_scan.total_progress
            }

        # Count recent scans
        thirty_days_ago = timezone.now() - timedelta(days=30)
        stats['recent_activity']['scans_last_30_days'] = scan_sessions.filter(
            created_at__gte=thirty_days_ago
        ).count()

        # Get vulnerability statistics
        from apps.vulnerabilities.models import Vulnerability
        vulnerabilities = Vulnerability.objects.filter(
            scan_session__target=target
        )
        stats['recent_activity']['total_vulnerabilities'] = vulnerabilities.count()
        stats['recent_activity']['critical_vulnerabilities'] = vulnerabilities.filter(
            severity='critical'
        ).count()

        return Response(stats)

    @action(detail=False, methods=['get'])
    def summary(self, request):
        """Get summary statistics for all targets"""
        queryset = self.get_queryset()

        summary = {
            'total_targets': queryset.count(),
            'active_targets': queryset.filter(is_active=True).count(),
            'by_platform': {},
            'recent_targets': queryset.order_by('-created_at')[:5].values(
                'id', 'target_name', 'platform', 'created_at'
            ),
            'most_scanned': queryset.order_by('-total_scan_sessions')[:5].values(
                'id', 'target_name', 'total_scan_sessions'
            )
        }

        # Count by platform
        from .models import BugBountyPlatform
        for platform in BugBountyPlatform:
            count = queryset.filter(platform=platform.value).count()
            summary['by_platform'][platform.label] = count

        return Response(summary)

    @action(detail=True, methods=['post'])
    def toggle_active(self, request, pk=None):
        """Toggle target active status"""
        target = self.get_object()
        target.is_active = not target.is_active
        target.save(update_fields=['is_active', 'updated_at'])

        return Response({
            'message': f"Target {'activated' if target.is_active else 'deactivated'}",
            'is_active': target.is_active
        })

    def _check_url_scope(self, url, target):
        """Check if a URL is in scope for the target"""
        # Check exact matches first
        if url in target.out_of_scope_urls:
            return False
        if url in target.in_scope_urls:
            return True

        # Check domain-level scope
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # Check wildcard URL
            if target.wildcard_url:
                wildcard_domain = target.wildcard_url.replace('*.', '').lower()
                if domain.endswith(wildcard_domain):
                    return True

            # Check main URL domain
            main_parsed = urlparse(target.main_url)
            if domain == main_parsed.netloc.lower():
                return True

        except Exception:
            pass

        return False

    def _get_scope_reason(self, url, target, is_in_scope):
        """Get reason why URL is in or out of scope"""
        if url in target.out_of_scope_urls:
            return "Explicitly listed in out-of-scope URLs"
        if url in target.in_scope_urls:
            return "Explicitly listed in in-scope URLs"

        if is_in_scope:
            return "Matches target domain or wildcard"
        else:
            return "Does not match any in-scope domains"

    def _log_target_changes(self, old_data, new_data, user):
        """Log significant changes to targets"""
        logger = logging.getLogger('apps.targets')

        # Compare key fields
        key_fields = ['target_name', 'main_url', 'platform', 'is_active']
        changes = []

        for field in key_fields:
            if old_data.get(field) != new_data.get(field):
                changes.append(
                    f"{field}: {old_data.get(field)} -> {new_data.get(field)}"
                )

        if changes:
            logger.info(
                f"Target {new_data['target_name']} updated by {user}: "
                f"{', '.join(changes)}"
            )
