import re

from rest_framework import serializers

from .models import CloudAccount, CloudResource


class CloudAccountSerializer(serializers.ModelSerializer):
    resource_count = serializers.IntegerField(read_only=True)
    credential_hint = serializers.CharField(read_only=True)

    class Meta:
        model = CloudAccount
        fields = (
            "id",
            "organization",
            "name",
            "provider",
            "account_identifier",
            "region",
            "credential_type",
            "role_arn",
            "is_read_only",
            "scan_enabled",
            "status",
            "notes",
            "credential_hint",
            "resource_count",
            "last_checked_at",
            "created_at",
            "updated_at",
        )
        read_only_fields = ("organization", "status", "last_checked_at", "created_at", "updated_at")


class CloudAccountWriteSerializer(CloudAccountSerializer):
    credentials = serializers.JSONField(write_only=True)

    class Meta(CloudAccountSerializer.Meta):
        fields = CloudAccountSerializer.Meta.fields + ("credentials",)

    def validate_account_identifier(self, value):
        if not re.fullmatch(r"\d{12}", value):
            raise serializers.ValidationError("Enter the 12-digit AWS account identifier.")
        return value

    def validate_credentials(self, value):
        required = {"access_key_id", "secret_access_key"}
        if not isinstance(value, dict) or not required.issubset(value):
            raise serializers.ValidationError("AWS access key ID and secret access key are required.")
        if not all(isinstance(value[key], str) and value[key] for key in required):
            raise serializers.ValidationError("AWS credentials must be non-empty strings.")
        return value

    def validate(self, attrs):
        if attrs.get("credential_type") == CloudAccount.CredentialType.ASSUME_ROLE and not attrs.get("role_arn"):
            raise serializers.ValidationError({"role_arn": "A role ARN is required for role-based access."})
        if not attrs.get("is_read_only", True):
            raise serializers.ValidationError("CloudSentry only supports read-only assessment credentials.")
        return attrs

    def create(self, validated_data):
        credentials = validated_data.pop("credentials")
        validated_data["organization"] = self.context["view"].get_organization()
        validated_data["created_by"] = self.context["request"].user
        validated_data["is_read_only"] = True
        account = CloudAccount(**validated_data)
        account.set_credentials(credentials)
        account.save()
        return account

    def update(self, instance, validated_data):
        credentials = validated_data.pop("credentials", None)
        for field, value in validated_data.items():
            setattr(instance, field, value)
        if credentials:
            instance.set_credentials(credentials)
        instance.is_read_only = True
        instance.save()
        return instance


class CloudResourceSerializer(serializers.ModelSerializer):
    organization = serializers.IntegerField(source="cloud_account.organization_id", read_only=True)

    class Meta:
        model = CloudResource
        fields = (
            "id",
            "organization",
            "cloud_account",
            "resource_id",
            "resource_type",
            "name",
            "region",
            "metadata",
            "tags",
            "risk_level",
            "is_demo",
            "discovered_at",
            "last_seen_at",
        )
        read_only_fields = fields
