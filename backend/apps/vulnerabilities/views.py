"""
Vulnerability Management API Views
backend/apps/vulnerabilities/views.py
"""

from rest_framework import viewsets, permissions
from .models import Vulnerability, ExploitationChain
from .serializers import VulnerabilitySerializer, ExploitationChainSerializer

class VulnerabilityViewSet(viewsets.ModelViewSet):
    """ViewSet for managing discovered vulnerabilities"""
    
    queryset = Vulnerability.objects.all()
    serializer_class = VulnerabilitySerializer
    permission_classes = [permissions.IsAuthenticated]

class ExploitationChainViewSet(viewsets.ModelViewSet):
    """ViewSet for managing exploitation chains"""
    
    queryset = ExploitationChain.objects.all()
    serializer_class = ExploitationChainSerializer
    permission_classes = [permissions.IsAuthenticated]
