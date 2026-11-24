from rest_framework import serializers

from .models import ComplianceAssessment, ComplianceControl, ControlResult


class ComplianceControlSerializer(serializers.ModelSerializer):
    class Meta:
        model = ComplianceControl
        fields = (
            "id",
            "framework",
            "control_id",
            "title",
            "description",
            "severity",
            "rule_ids",
            "enabled",
        )
        read_only_fields = fields


class ControlResultSerializer(serializers.ModelSerializer):
    control = ComplianceControlSerializer(read_only=True)

    class Meta:
        model = ControlResult
        fields = ("id", "control", "status", "evidence")
        read_only_fields = fields


class ComplianceAssessmentSerializer(serializers.ModelSerializer):
    results = ControlResultSerializer(many=True, read_only=True)

    class Meta:
        model = ComplianceAssessment
        fields = (
            "id",
            "organization",
            "scan_run",
            "score",
            "passed",
            "failed",
            "total",
            "summary",
            "created_at",
            "results",
        )
        read_only_fields = fields
