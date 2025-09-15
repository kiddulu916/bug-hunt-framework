"""
Scanning Management URL Configuration
backend/apps/scanning/urls.py
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import ScanSessionViewSet, ToolExecutionViewSet

# Create router and register viewsets
router = DefaultRouter()
router.register(r'sessions', ScanSessionViewSet, basename='scan-session')
router.register(r'tools', ToolExecutionViewSet, basename='tool-execution')

app_name = 'scanning'

urlpatterns = [
    path('', include(router.urls)),
]

# Available endpoints:
# 
# Scan Sessions:
# GET    /api/scans/sessions/                    - List all scan sessions
# POST   /api/scans/sessions/                    - Create new scan session
# GET    /api/scans/sessions/{id}/               - Get scan session details
# PUT    /api/scans/sessions/{id}/               - Update scan session (full)
# PATCH  /api/scans/sessions/{id}/               - Update scan session (partial)
# DELETE /api/scans/sessions/{id}/               - Delete scan session
# 
# Scan Session Actions:
# POST   /api/scans/sessions/{id}/start/         - Start a queued scan
# POST   /api/scans/sessions/{id}/pause/         - Pause a running scan
# POST   /api/scans/sessions/{id}/resume/        - Resume a paused scan
# POST   /api/scans/sessions/{id}/cancel/        - Cancel a scan
# GET    /api/scans/sessions/{id}/progress/      - Get detailed progress
# GET    /api/scans/sessions/{id}/tools/         - Get tool execution status
# GET    /api/scans/sessions/statistics/         - Get scanning statistics
# 
# Tool Executions:
# GET    /api/scans/tools/                       - List all tool executions
# POST   /api/scans/tools/                       - Create new tool execution
# GET    /api/scans/tools/{id}/                  - Get tool execution details
# PUT    /api/scans/tools/{id}/                  - Update tool execution (full)
# PATCH  /api/scans/tools/{id}/                  - Update tool execution (partial)
# DELETE /api/scans/tools/{id}/                  - Delete tool execution
# GET    /api/scans/tools/statistics/            - Get tool execution statistics