"""
WebSocket URL routing for vulnerabilities app
backend/apps/vulnerabilities/routing.py
"""

from django.urls import path
from . import consumers

websocket_urlpatterns = [
    path('ws/vulnerabilities/<uuid:scan_id>/', consumers.VulnerabilityConsumer.as_asgi()),
]
