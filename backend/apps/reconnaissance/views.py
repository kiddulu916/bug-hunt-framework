from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from .models import ReconResult
from .serializers import ReconResultSerializer


class ReconResultViewSet(viewsets.ModelViewSet):
    queryset = ReconResult.objects.all()
    serializer_class = ReconResultSerializer
    permission_classes = [IsAuthenticated]
