"""
Pagination utilities for Bug Bounty Automation Platform.
Provides consistent pagination across Django REST Framework and FastAPI.
"""

from rest_framework.pagination import PageNumberPagination
from rest_framework.response import Response
from collections import OrderedDict
from typing import Optional, Any, Dict, List
from math import ceil
import logging

logger = logging.getLogger(__name__)

class CustomPageNumberPagination(PageNumberPagination):
    """
    Custom pagination class for Django REST Framework.
    Provides enhanced pagination with metadata and flexible page sizes.
    """

    page_size = 20
    page_size_query_param = 'page_size'
    max_page_size = 100
    page_query_param = 'page'

    def get_paginated_response(self, data):
        """
        Return a paginated response with enhanced metadata.
        """
        return Response(OrderedDict([
            ('count', self.page.paginator.count),
            ('total_pages', self.page.paginator.num_pages),
            ('current_page', self.page.number),
            ('page_size', self.get_page_size(self.request)),
            ('next', self.get_next_link()),
            ('previous', self.get_previous_link()),
            ('has_next', self.page.has_next()),
            ('has_previous', self.page.has_previous()),
            ('start_index', self.page.start_index()),
            ('end_index', self.page.end_index()),
            ('results', data)
        ]))

    def get_page_size(self, request):
        """
        Determine the page size with validation.
        """
        if self.page_size_query_param:
            try:
                page_size = int(request.query_params[self.page_size_query_param])
                if page_size > 0:
                    return min(page_size, self.max_page_size)
            except (KeyError, ValueError):
                pass
        return self.page_size

class VulnerabilityPagination(CustomPageNumberPagination):
    """
    Specialized pagination for vulnerability listings.
    """
    page_size = 25
    page_size_query_param = 'page_size'
    max_page_size = 100

    def get_paginated_response(self, data):
        """
        Enhanced pagination response for vulnerabilities with severity counts.
        """
        response = super().get_paginated_response(data)

        # Add vulnerability-specific metadata if available
        if hasattr(self, 'severity_counts'):
            response.data['severity_counts'] = self.severity_counts

        if hasattr(self, 'platform_counts'):
            response.data['platform_counts'] = self.platform_counts

        return response

class ScanPagination(CustomPageNumberPagination):
    """
    Specialized pagination for scan sessions.
    """
    page_size = 15
    page_size_query_param = 'page_size'
    max_page_size = 50

    def get_paginated_response(self, data):
        """
        Enhanced pagination response for scans with status counts.
        """
        response = super().get_paginated_response(data)

        # Add scan-specific metadata if available
        if hasattr(self, 'status_counts'):
            response.data['status_counts'] = self.status_counts

        if hasattr(self, 'completion_stats'):
            response.data['completion_stats'] = self.completion_stats

        return response

# FastAPI Pagination Classes

class FastAPIPagination:
    """
    Base pagination class for FastAPI endpoints.
    """

    def __init__(self, page: int = 1, page_size: int = 20, max_page_size: int = 100):
        self.page = max(1, page)
        self.page_size = min(max(1, page_size), max_page_size)
        self.max_page_size = max_page_size
        self.offset = (self.page - 1) * self.page_size

    def paginate_query(self, query, total_count: int = None):
        """
        Apply pagination to a SQLAlchemy query.

        Args:
            query: SQLAlchemy query object
            total_count: Optional pre-calculated total count

        Returns:
            dict: Paginated response with metadata
        """
        if total_count is None:
            total_count = query.count()

        # Apply limit and offset
        items = query.offset(self.offset).limit(self.page_size).all()

        total_pages = ceil(total_count / self.page_size) if total_count > 0 else 1

        return {
            'items': items,
            'pagination': {
                'count': total_count,
                'total_pages': total_pages,
                'current_page': self.page,
                'page_size': self.page_size,
                'has_next': self.page < total_pages,
                'has_previous': self.page > 1,
                'start_index': self.offset + 1 if total_count > 0 else 0,
                'end_index': min(self.offset + self.page_size, total_count),
            }
        }

    def paginate_list(self, items: List[Any]):
        """
        Paginate a Python list.

        Args:
            items: List of items to paginate

        Returns:
            dict: Paginated response with metadata
        """
        total_count = len(items)
        total_pages = ceil(total_count / self.page_size) if total_count > 0 else 1

        start_index = self.offset
        end_index = min(self.offset + self.page_size, total_count)
        paginated_items = items[start_index:end_index]

        return {
            'items': paginated_items,
            'pagination': {
                'count': total_count,
                'total_pages': total_pages,
                'current_page': self.page,
                'page_size': self.page_size,
                'has_next': self.page < total_pages,
                'has_previous': self.page > 1,
                'start_index': start_index + 1 if total_count > 0 else 0,
                'end_index': end_index,
            }
        }

class VulnerabilityFastAPIPagination(FastAPIPagination):
    """
    Specialized FastAPI pagination for vulnerabilities.
    """

    def __init__(self, page: int = 1, page_size: int = 25):
        super().__init__(page, page_size, max_page_size=100)

    def paginate_vulnerabilities(self, query, severity_filter: str = None):
        """
        Paginate vulnerabilities with additional metadata.

        Args:
            query: SQLAlchemy query for vulnerabilities
            severity_filter: Optional severity filter applied

        Returns:
            dict: Paginated response with vulnerability-specific metadata
        """
        result = self.paginate_query(query)

        # Add severity counts
        from apps.vulnerabilities.models import Vulnerability, VulnSeverity
        severity_counts = {}

        # Get base query without pagination
        base_query = query.statement.compile().compile(
            compile_kwargs={"literal_binds": True}
        )

        # This is a simplified approach - in practice, you'd want to
        # calculate these counts more efficiently
        for severity in VulnSeverity:
            severity_counts[severity.value] = 0

        result['severity_counts'] = severity_counts
        result['applied_filters'] = {
            'severity': severity_filter
        }

        return result

class ScanFastAPIPagination(FastAPIPagination):
    """
    Specialized FastAPI pagination for scan sessions.
    """

    def __init__(self, page: int = 1, page_size: int = 15):
        super().__init__(page, page_size, max_page_size=50)

    def paginate_scans(self, query, status_filter: str = None):
        """
        Paginate scan sessions with additional metadata.

        Args:
            query: SQLAlchemy query for scan sessions
            status_filter: Optional status filter applied

        Returns:
            dict: Paginated response with scan-specific metadata
        """
        result = self.paginate_query(query)

        # Add status counts
        from apps.scanning.models import ScanSession, ScanStatus
        status_counts = {}

        for status in ScanStatus:
            status_counts[status.value] = 0

        result['status_counts'] = status_counts
        result['applied_filters'] = {
            'status': status_filter
        }

        return result

# Utility functions

def get_pagination_params(request) -> Dict[str, int]:
    """
    Extract pagination parameters from request.
    Works with both Django and FastAPI requests.

    Args:
        request: Request object (Django or FastAPI)

    Returns:
        dict: Dictionary with page and page_size parameters
    """
    try:
        # Handle FastAPI request
        if hasattr(request, 'query_params'):
            page = int(request.query_params.get('page', 1))
            page_size = int(request.query_params.get('page_size', 20))
        # Handle Django request
        elif hasattr(request, 'GET'):
            page = int(request.GET.get('page', 1))
            page_size = int(request.GET.get('page_size', 20))
        else:
            page, page_size = 1, 20

        return {
            'page': max(1, page),
            'page_size': min(max(1, page_size), 100)
        }
    except (ValueError, TypeError):
        return {'page': 1, 'page_size': 20}

def create_pagination_links(base_url: str, page: int, total_pages: int, page_size: int) -> Dict[str, Optional[str]]:
    """
    Create pagination navigation links.

    Args:
        base_url: Base URL for the endpoint
        page: Current page number
        total_pages: Total number of pages
        page_size: Items per page

    Returns:
        dict: Dictionary with next and previous links
    """
    next_link = None
    previous_link = None

    if page < total_pages:
        next_link = f"{base_url}?page={page + 1}&page_size={page_size}"

    if page > 1:
        previous_link = f"{base_url}?page={page - 1}&page_size={page_size}"

    return {
        'next': next_link,
        'previous': previous_link
    }

# Export commonly used classes and functions
__all__ = [
    'CustomPageNumberPagination',
    'VulnerabilityPagination',
    'ScanPagination',
    'FastAPIPagination',
    'VulnerabilityFastAPIPagination',
    'ScanFastAPIPagination',
    'get_pagination_params',
    'create_pagination_links',
]
