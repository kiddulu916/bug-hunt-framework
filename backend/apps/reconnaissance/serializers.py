from rest_framework import serializers
from .models import ReconResult


class ReconResultSerializer(serializers.ModelSerializer):
    class Meta:
        model = ReconResult
        fields = '__all__'
