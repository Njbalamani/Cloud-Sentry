from rest_framework import serializers

from .models import Finding, RemediationReview, ScanRun


class ScanRunSerializer(serializers.ModelSerializer):
    cloud_account_name = serializers.CharField(source="cloud_account.name", read_only=True)
    duration_seconds = serializers.IntegerField(read_only=True)

    class Meta:
        model = ScanRun
        fields = (
            "id",
            "organization",
            "cloud_account",
            "cloud_account_name",
            "initiated_by",
            "status",
            "scan_mode",
            "started_at",
            "finished_at",
            "duration_seconds",
            "resources_scanned",
            "findings_count",
            "summary",
            "error_message",
        )
        read_only_fields = fields


class ScanRunCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = ScanRun
        fields = ("cloud_account", "scan_mode")

    def validate_cloud_account(self, value):
        organization = self.context["view"].get_organization()
        if value.organization_id != organization.id:
            raise serializers.ValidationError("The cloud account does not belong to the active organization.")
        return value

    def create(self, validated_data):
        from .services import create_scan_run

        return create_scan_run(
            cloud_account=validated_data["cloud_account"],
            initiated_by=self.context["request"].user,
            mode=validated_data.get("scan_mode", ScanRun.Mode.LIVE),
        )


class FindingSerializer(serializers.ModelSerializer):
    organization = serializers.IntegerField(source="cloud_account.organization_id", read_only=True)
    resource_name = serializers.CharField(read_only=True)
    rule_id = serializers.CharField(source="rule.rule_id", read_only=True)

    class Meta:
        model = Finding
        fields = (
            "id",
            "organization",
            "scan_run",
            "cloud_account",
            "resource",
            "resource_name",
            "rule",
            "rule_id",
            "title",
            "description",
            "severity",
            "status",
            "risk_score",
            "evidence",
            "remediation",
            "is_demo",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields


class RemediationReviewSerializer(serializers.ModelSerializer):
    class Meta:
        model = RemediationReview
        fields = ("id", "finding", "reviewer", "decision", "notes", "proposed_action", "reviewed_at")
        read_only_fields = ("reviewer", "reviewed_at")

    def validate_finding(self, value):
        organization = self.context["view"].get_organization()
        if value.organization_id != organization.id:
            raise serializers.ValidationError("The finding does not belong to the active organization.")
        return value

    def create(self, validated_data):
        from .services import review_remediation

        return review_remediation(
            finding=validated_data["finding"],
            reviewer=self.context["request"].user,
            decision=validated_data["decision"],
            notes=validated_data.get("notes", ""),
        )
