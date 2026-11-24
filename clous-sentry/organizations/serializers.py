from rest_framework import serializers

from .models import Organization, OrganizationMembership


class OrganizationSerializer(serializers.ModelSerializer):
    member_count = serializers.IntegerField(read_only=True)

    class Meta:
        model = Organization
        fields = ("id", "name", "slug", "description", "is_active", "member_count", "created_at")
        read_only_fields = fields


class OrganizationMembershipSerializer(serializers.ModelSerializer):
    user_email = serializers.CharField(source="user.email", read_only=True)

    class Meta:
        model = OrganizationMembership
        fields = ("id", "organization", "user", "user_email", "role", "is_active", "joined_at")
        read_only_fields = fields
