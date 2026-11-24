from rest_framework import serializers

from .models import IAMAnalysis


class IAMAnalysisSerializer(serializers.ModelSerializer):
    organization = serializers.IntegerField(source="cloud_account.organization_id", read_only=True)
    cloud_account_name = serializers.CharField(source="cloud_account.name", read_only=True)

    class Meta:
        model = IAMAnalysis
        fields = (
            "id",
            "organization",
            "cloud_account",
            "cloud_account_name",
            "scan_run",
            "principal_arn",
            "policy_name",
            "policy_document",
            "findings",
            "recommendations",
            "risk_score",
            "is_demo",
            "analyzed_at",
        )
        read_only_fields = fields
