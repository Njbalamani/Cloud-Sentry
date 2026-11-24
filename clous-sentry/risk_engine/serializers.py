from rest_framework import serializers

from .models import RiskAssessment


class RiskAssessmentSerializer(serializers.ModelSerializer):
    organization = serializers.IntegerField(source="finding.organization.id", read_only=True)
    finding_title = serializers.CharField(source="finding.title", read_only=True)

    class Meta:
        model = RiskAssessment
        fields = (
            "id",
            "organization",
            "finding",
            "finding_title",
            "score",
            "severity_band",
            "model_version",
            "factors",
            "explanation",
            "remediation_summary",
            "source",
            "created_at",
        )
        read_only_fields = fields
