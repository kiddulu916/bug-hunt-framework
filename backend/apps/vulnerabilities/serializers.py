"""
Vulnerability Management Serializers
backend/apps/vulnerabilities/serializers.py
"""

from rest_framework import serializers
from django.core.validators import URLValidator
from django.core.exceptions import ValidationError
from .models import Vulnerability, ExploitationChain, VulnSeverity
from apps.scanning.serializers import ScanSessionSummarySerializer

class ExploitationChainSerializer(serializers.ModelSerializer):
    """Serializer for exploitation chains"""

    is_final_step = serializers.SerializerMethodField()
    success_percentage = serializers.SerializerMethodField()

    class Meta:
        model = ExploitationChain
        fields = [
            'id', 'chain_name', 'chain_description', 'step_number', 'total_steps',
            'step_description', 'payload', 'expected_result', 'actual_result',
            'screenshot_path', 'request_response_log', 'step_successful',
            'chain_successful', 'impact_increase', 'final_impact_description',
            'executed_at', 'is_final_step', 'success_percentage'
        ]
        read_only_fields = ['id', 'executed_at', 'is_final_step', 'success_percentage']

    def get_is_final_step(self, obj):
        return obj.is_final_step

    def get_success_percentage(self, obj):
        return round(obj.success_percentage, 2)

    def validate_step_number(self, value):
        """Validate step number is positive and within range"""
        if value <= 0:
            raise serializers.ValidationError("Step number must be positive")
        return value

    def validate_total_steps(self, value):
        """Validate total steps is positive"""
        if value <= 0:
            raise serializers.ValidationError("Total steps must be positive")
        return value

    def validate(self, data):
        """Cross-field validation"""
        step_number = data.get('step_number')
        total_steps = data.get('total_steps')

        if step_number and total_steps and step_number > total_steps:
            raise serializers.ValidationError(
                "Step number cannot be greater than total steps"
            )

        return data

class VulnerabilitySerializer(serializers.ModelSerializer):
    """Comprehensive serializer for vulnerabilities"""

    scan_session = ScanSessionSummarySerializer(read_only=True)
    scan_session_id = serializers.UUIDField(write_only=True)
    exploitation_chains = ExploitationChainSerializer(many=True, read_only=True)
    severity_score = serializers.SerializerMethodField()
    has_evidence = serializers.SerializerMethodField()
    owasp_description = serializers.SerializerMethodField()

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'scan_session', 'scan_session_id', 'vulnerability_name',
            'vulnerability_type', 'owasp_category', 'cwe_id', 'severity',
            'cvss_score', 'impact_description', 'affected_url', 'affected_parameter',
            'http_method', 'payload_used', 'request_data', 'response_data',
            'discovered_by_tool', 'discovery_method', 'confidence_level',
            'false_positive_likelihood', 'screenshot_paths', 'additional_evidence',
            'is_exploitable', 'exploitation_difficulty', 'exploitation_notes',
            'remediation_suggestion', 'remediation_priority', 'manually_verified',
            'verification_notes', 'discovered_at', 'updated_at', 'exploitation_chains',
            'severity_score', 'has_evidence', 'owasp_description'
        ]
        read_only_fields = [
            'id', 'discovered_at', 'updated_at', 'severity_score',
            'has_evidence', 'owasp_description'
        ]

    def get_severity_score(self, obj):
        return obj.severity_score

    def get_has_evidence(self, obj):
        return obj.has_evidence

    def get_owasp_description(self, obj):
        return obj.get_owasp_description()

    def validate_vulnerability_name(self, value):
        """Validate vulnerability name"""
        if len(value.strip()) < 3:
            raise serializers.ValidationError("Vulnerability name must be at least 3 characters")
        return value.strip()

    def validate_affected_url(self, value):
        """Validate affected URL"""
        url_validator = URLValidator()
        try:
            url_validator(value)
        except ValidationError:
            raise serializers.ValidationError("Invalid URL format")
        return value

    def validate_cvss_score(self, value):
        """Validate CVSS score range"""
        if value is not None and not (0.0 <= value <= 10.0):
            raise serializers.ValidationError("CVSS score must be between 0.0 and 10.0")
        return value

    def validate_confidence_level(self, value):
        """Validate confidence level range"""
        if not (0.0 <= value <= 1.0):
            raise serializers.ValidationError("Confidence level must be between 0.0 and 1.0")
        return value

    def validate_false_positive_likelihood(self, value):
        """Validate false positive likelihood range"""
        if not (0.0 <= value <= 1.0):
            raise serializers.ValidationError("False positive likelihood must be between 0.0 and 1.0")
        return value

    def validate_screenshot_paths(self, value):
        """Validate screenshot paths"""
        if not isinstance(value, list):
            raise serializers.ValidationError("Screenshot paths must be a list")

        for path in value:
            if not isinstance(path, str) or len(path.strip()) == 0:
                raise serializers.ValidationError("Each screenshot path must be a non-empty string")

        return value

class VulnerabilityCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating vulnerabilities"""

    class Meta:
        model = Vulnerability
        fields = [
            'scan_session_id', 'vulnerability_name', 'vulnerability_type',
            'owasp_category', 'cwe_id', 'severity', 'cvss_score',
            'impact_description', 'affected_url', 'affected_parameter',
            'http_method', 'payload_used', 'request_data', 'response_data',
            'discovered_by_tool', 'discovery_method', 'confidence_level',
            'false_positive_likelihood', 'screenshot_paths', 'additional_evidence',
            'is_exploitable', 'exploitation_difficulty', 'exploitation_notes',
            'remediation_suggestion', 'remediation_priority'
        ]

class VulnerabilityUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating vulnerabilities"""

    class Meta:
        model = Vulnerability
        fields = [
            'vulnerability_name', 'vulnerability_type', 'owasp_category',
            'cwe_id', 'severity', 'cvss_score', 'impact_description',
            'affected_parameter', 'payload_used', 'request_data', 'response_data',
            'confidence_level', 'false_positive_likelihood', 'screenshot_paths',
            'additional_evidence', 'is_exploitable', 'exploitation_difficulty',
            'exploitation_notes', 'remediation_suggestion', 'remediation_priority',
            'manually_verified', 'verification_notes'
        ]

class VulnerabilitySummarySerializer(serializers.ModelSerializer):
    """Lightweight serializer for vulnerability summaries"""

    target_name = serializers.CharField(source='scan_session.target.target_name', read_only=True)
    scan_session_name = serializers.CharField(source='scan_session.session_name', read_only=True)
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    has_evidence = serializers.SerializerMethodField()

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'vulnerability_name', 'vulnerability_type', 'severity',
            'severity_display', 'cvss_score', 'affected_url', 'discovered_by_tool',
            'confidence_level', 'is_exploitable', 'manually_verified',
            'discovered_at', 'target_name', 'scan_session_name', 'has_evidence'
        ]

    def get_has_evidence(self, obj):
        return obj.has_evidence

class VulnerabilityVerificationSerializer(serializers.ModelSerializer):
    """Serializer for vulnerability verification"""

    class Meta:
        model = Vulnerability
        fields = [
            'id', 'vulnerability_name', 'manually_verified', 'verification_notes',
            'confidence_level', 'false_positive_likelihood'
        ]

class VulnerabilityStatsSerializer(serializers.Serializer):
    """Serializer for vulnerability statistics"""

    total = serializers.IntegerField()
    critical = serializers.IntegerField()
    high = serializers.IntegerField()
    medium = serializers.IntegerField()
    low = serializers.IntegerField()
    info = serializers.IntegerField()
    verified = serializers.IntegerField()
    exploitable = serializers.IntegerField()

    # Additional stats
    by_tool = serializers.DictField(child=serializers.IntegerField(), required=False)
    by_type = serializers.DictField(child=serializers.IntegerField(), required=False)
    by_owasp = serializers.DictField(child=serializers.IntegerField(), required=False)

class ExploitationChainCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating exploitation chains"""

    class Meta:
        model = ExploitationChain
        fields = [
            'vulnerability_id', 'chain_name', 'chain_description', 'step_number',
            'total_steps', 'step_description', 'payload', 'expected_result'
        ]

class ExploitationChainUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating exploitation chain results"""

    class Meta:
        model = ExploitationChain
        fields = [
            'actual_result', 'screenshot_path', 'request_response_log',
            'step_successful', 'chain_successful', 'impact_increase',
            'final_impact_description'
        ]
