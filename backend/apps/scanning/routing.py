"""
WebSocket URL routing for scanning app
backend/apps/scanning/routing.py
"""

from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/scans/<uuid:scan_id>/', consumers.ScanProgressConsumer.as_asgi()),
    path('ws/tools/<uuid:execution_id>/', consumers.ToolExecutionConsumer.as_asgi()),
    path('ws/notifications/', consumers.NotificationConsumer.as_asgi()),
]
