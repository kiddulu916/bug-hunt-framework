"""
Target Management URL Configuration
backend/apps/targets/urls.py
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import TargetViewSet

# Create router and register viewsets
router = DefaultRouter()
router.register(r'', TargetViewSet, basename='target')

app_name = 'targets'

urlpatterns = [
    path('', include(router.urls)),
]

# Available endpoints:
# GET    /api/targets/              - List all targets
# POST   /api/targets/              - Create new target
# GET    /api/targets/{id}/         - Get target details
# PUT    /api/targets/{id}/         - Update target (full)
# PATCH  /api/targets/{id}/         - Update target (partial)
# DELETE /api/targets/{id}/         - Delete target
# 
# Custom endpoints:
# GET    /api/targets/summary/              - Get targets summary
# GET    /api/targets/{id}/scope/           - Get target scope
# PATCH  /api/targets/{id}/scope/           - Update target scope
# GET    /api/targets/{id}/config/          - Get target config
# PATCH  /api/targets/{id}/config/          - Update target config
# POST   /api/targets/{id}/validate_scope/  - Validate URLs against scope
# GET    /api/targets/{id}/statistics/      - Get target statistics
# POST   /api/targets/{id}/toggle_active/   - Toggle target active status