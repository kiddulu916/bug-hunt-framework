"""
Target Management Filters
backend/apps/targets/filters.py
"""

import django_filters
from django.db.models import Q
from .models import Target, BugBountyPlatform

class TargetFilter(django_filters.FilterSet):
    """Advanced filtering for targets"""
    
    # Platform filtering
    platform = django_filters.ChoiceFilter(
        choices=BugBountyPlatform.choices,
        help_text="Filter by bug bounty platform"
    )
    
    # Status filtering
    is_active = django_filters.BooleanFilter(
        help_text="Filter by active status"
    )
    
    # Date range filtering
    created_after = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='gte',
        help_text="Filter targets created after this date"
    )
    created_before = django_filters.DateTimeFilter(
        field_name='created_at',
        lookup_expr='lte',
        help_text="Filter targets created before this date"
    )
    
    # Text search
    search = django_filters.CharFilter(
        method='filter_search',
        help_text="Search in target name, URL, or researcher username"
    )
    
    # Rate limiting filters
    max_rps = django_filters.NumberFilter(
        field_name='requests_per_second',
        lookup_expr='lte',
        help_text="Filter by maximum requests per second"
    )
    min_rps = django_filters.NumberFilter(
        field_name='requests_per_second',
        lookup_expr='gte',
        help_text="Filter by minimum requests per second"
    )
    
    # Scope complexity filters
    has_wildcard = django_filters.BooleanFilter(
        method='filter_has_wildcard',
        help_text="Filter targets with/without wildcard URLs"
    )
    
    scope_complexity = django_filters.ChoiceFilter(
        method='filter_scope_complexity',
        choices=[
            ('simple', 'Simple (<=5 scope items)'),
            ('medium', 'Medium (6-20 scope items)'),
            ('complex', 'Complex (>20 scope items)')
        ],
        help_text="Filter by scope complexity"
    )
    
    class Meta:
        model = Target
        fields = [
            'platform', 'is_active', 'created_after', 'created_before',
            'search', 'max_rps', 'min_rps', 'has_wildcard', 'scope_complexity'
        ]
    
    def filter_search(self, queryset, name, value):
        """Full-text search across multiple fields"""
        if not value:
            return queryset
        
        return queryset.filter(
            Q(target_name__icontains=value) |
            Q(main_url__icontains=value) |
            Q(researcher_username__icontains=value) |
            Q(program_notes__icontains=value)
        )
    
    def filter_has_wildcard(self, queryset, name, value):
        """Filter targets with or without wildcard URLs"""
        if value is True:
            return queryset.filter(wildcard_url__isnull=False).exclude(wildcard_url='')
        elif value is False:
            return queryset.filter(Q(wildcard_url__isnull=True) | Q(wildcard_url=''))
        return queryset
    
    def filter_scope_complexity(self, queryset, name, value):
        """Filter by scope complexity based on number of scope items"""
        if not value:
            return queryset
        
        # Annotate with total scope items count
        from django.db.models import Case, When, IntegerField
        from django.contrib.postgres.fields import ArrayField
        from django.db.models.functions import Coalesce, Least
        
        # This is a simplified approach - in production you might want to use raw SQL
        if value == 'simple':
            # Targets with few scope items (this is a simplified filter)
            return queryset.extra(
                where=["array_length(in_scope_urls, 1) + array_length(out_of_scope_urls, 1) <= 5"]
            )
        elif value == 'medium':
            return queryset.extra(
                where=["array_length(in_scope_urls, 1) + array_length(out_of_scope_urls, 1) BETWEEN 6 AND 20"]
            )
        elif value == 'complex':
            return queryset.extra(
                where=["array_length(in_scope_urls, 1) + array_length(out_of_scope_urls, 1) > 20"]
            )
        
        return queryset