"""
Target Management Serializers
backend/apps/targets/serializers.py
"""

from rest_framework import serializers
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from .models import Target, BugBountyPlatform
import re

class TargetSerializer(serializers.ModelSerializer):
    """Serializer for Target model with validation"""

    # Read-only computed fields
    total_scan_sessions = serializers.IntegerField(read_only=True)
    latest_scan_session = serializers.SerializerMethodField()
    scope_summary = serializers.SerializerMethodField()

    class Meta:
        model = Target
        fields = [
            'id', 'target_name', 'platform', 'researcher_username',
            'main_url', 'wildcard_url', 'in_scope_urls', 'out_of_scope_urls',
            'in_scope_assets', 'out_of_scope_assets', 'requests_per_second',
            'concurrent_requests', 'request_delay_ms', 'required_headers',
            'authentication_headers', 'user_agents', 'program_notes',
            'special_requirements', 'pii_redaction_rules', 'created_at',
            'updated_at', 'is_active', 'total_scan_sessions',
            'latest_scan_session', 'scope_summary'
        ]
        read_only_fields = ['id', 'created_at', 'updated_at']

    def get_latest_scan_session(self, obj):
        """Get latest scan session summary"""
        latest = obj.latest_scan_session
        if latest:
            return {
                'id': str(latest.id),
                'session_name': latest.session_name,
                'status': latest.status,
                'created_at': latest.created_at,
                'total_progress': latest.total_progress
            }
        return None

    def get_scope_summary(self, obj):
        """Get scope summary statistics"""
        return obj.get_scope_summary()

    def validate_target_name(self, value):
        """Validate target name"""
        if len(value.strip()) < 2:
            raise serializers.ValidationError("Target name must be at least 2 characters")

        # Check for invalid characters
        if not re.match(r'^[a-zA-Z0-9\s\-_.]+$', value):
            raise serializers.ValidationError(
                "Target name can only contain letters, numbers, spaces, hyphens, underscores, and periods"
            )

        return value.strip()

    def validate_main_url(self, value):
        """Validate main URL format"""
        url_validator = URLValidator()
        try:
            url_validator(value)
        except ValidationError:
            raise serializers.ValidationError("Invalid URL format")

        # Ensure URL has scheme
        if not value.startswith(('http://', 'https://')):
            raise serializers.ValidationError("URL must start with http:// or https://")

        return value

    def validate_wildcard_url(self, value):
        """Validate wildcard URL if provided"""
        if value:
            # Allow wildcard domains like *.example.com
            if value.startswith('*.'):
                domain_part = value[2:]
                if not re.match(r'^[a-zA-Z0-9.-]+$', domain_part):
                    raise serializers.ValidationError("Invalid wildcard domain format")
            else:
                # Regular URL validation
                url_validator = URLValidator()
                try:
                    url_validator(value)
                except ValidationError:
                    raise serializers.ValidationError("Invalid wildcard URL format")

        return value

    def validate_requests_per_second(self, value):
        """Validate rate limiting configuration"""
        if value <= 0:
            raise serializers.ValidationError("Requests per second must be positive")
        if value > 100:
            raise serializers.ValidationError("Requests per second should not exceed 100")
        return value

    def validate_concurrent_requests(self, value):
        """Validate concurrent requests limit"""
        if value <= 0:
            raise serializers.ValidationError("Concurrent requests must be positive")
        if value > 50:
            raise serializers.ValidationError("Concurrent requests should not exceed 50")
        return value

    def validate_in_scope_urls(self, value):
        """Validate in-scope URLs"""
        if not isinstance(value, list):
            raise serializers.ValidationError("Must be a list of URLs")

        url_validator = URLValidator()
        for url in value:
            try:
                url_validator(url)
            except ValidationError:
                raise serializers.ValidationError(f"Invalid URL in scope: {url}")

        return value

    def validate_out_of_scope_urls(self, value):
        """Validate out-of-scope URLs"""
        if not isinstance(value, list):
            raise serializers.ValidationError("Must be a list of URLs")

        url_validator = URLValidator()
        for url in value:
            try:
                url_validator(url)
            except ValidationError:
                raise serializers.ValidationError(f"Invalid URL in out-of-scope: {url}")

        return value

    def validate_user_agents(self, value):
        """Validate user agent strings"""
        if not isinstance(value, list):
            raise serializers.ValidationError("Must be a list of user agent strings")

        for ua in value:
            if not isinstance(ua, str) or len(ua.strip()) == 0:
                raise serializers.ValidationError("Each user agent must be a non-empty string")
            if len(ua) > 500:
                raise serializers.ValidationError("User agent string too long (max 500 characters)")

        return value

    def validate(self, data):
        """Cross-field validation"""
        # Check for overlapping in-scope and out-of-scope URLs
        in_scope = set(data.get('in_scope_urls', []))
        out_of_scope = set(data.get('out_of_scope_urls', []))

        overlap = in_scope.intersection(out_of_scope)
        if overlap:
            raise serializers.ValidationError({
                'non_field_errors': [f"URLs cannot be both in-scope and out-of-scope: {', '.join(overlap)}"]
            })

        # Validate rate limiting makes sense
        rps = data.get('requests_per_second', 1)
        concurrent = data.get('concurrent_requests', 1)
        delay_ms = data.get('request_delay_ms', 0)

        # Calculate theoretical maximum RPS
        max_theoretical_rps = concurrent * (1000 / max(delay_ms, 1))
        if rps > max_theoretical_rps:
            raise serializers.ValidationError({
                'requests_per_second': [
                    f"Requests per second ({rps}) is too high for given delay ({delay_ms}ms) "
                    f"and concurrent requests ({concurrent}). Maximum theoretical: {max_theoretical_rps:.2f}"
                ]
            })

        return data

class TargetCreateSerializer(TargetSerializer):
    """Serializer for creating targets with required fields"""

    class Meta(TargetSerializer.Meta):
        fields = [
            'target_name', 'platform', 'researcher_username', 'main_url',
            'wildcard_url', 'in_scope_urls', 'out_of_scope_urls',
            'in_scope_assets', 'out_of_scope_assets', 'requests_per_second',
            'concurrent_requests', 'request_delay_ms', 'required_headers',
            'authentication_headers', 'user_agents', 'program_notes',
            'special_requirements', 'pii_redaction_rules', 'is_active'
        ]

class TargetUpdateSerializer(TargetSerializer):
    """Serializer for updating targets (partial updates allowed)"""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Make all fields optional for partial updates
        for field in self.fields.values():
            field.required = False

class TargetSummarySerializer(serializers.ModelSerializer):
    """Lightweight serializer for target summaries"""

    platform_display = serializers.CharField(source='get_platform_display', read_only=True)
    scan_count = serializers.IntegerField(source='total_scan_sessions', read_only=True)

    class Meta:
        model = Target
        fields = [
            'id', 'target_name', 'platform', 'platform_display',
            'main_url', 'is_active', 'created_at', 'scan_count'
        ]

class TargetScopeSerializer(serializers.ModelSerializer):
    """Serializer focused on scope management"""

    scope_summary = serializers.SerializerMethodField()

    class Meta:
        model = Target
        fields = [
            'id', 'target_name', 'in_scope_urls', 'out_of_scope_urls',
            'in_scope_assets', 'out_of_scope_assets', 'scope_summary'
        ]

    def get_scope_summary(self, obj):
        return obj.get_scope_summary()

class TargetConfigSerializer(serializers.ModelSerializer):
    """Serializer for target configuration settings"""

    class Meta:
        model = Target
        fields = [
            'id', 'target_name', 'requests_per_second', 'concurrent_requests',
            'request_delay_ms', 'required_headers', 'authentication_headers',
            'user_agents', 'pii_redaction_rules'
        ]
