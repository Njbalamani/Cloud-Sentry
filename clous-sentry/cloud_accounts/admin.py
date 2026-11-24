from django.contrib import admin

from .models import CloudAccount, CloudResource


@admin.register(CloudAccount)
class CloudAccountAdmin(admin.ModelAdmin):
    list_display = ("name", "organization", "account_identifier", "region", "credential_type", "is_read_only", "status")
    list_filter = ("provider", "credential_type", "is_read_only", "status", "region")
    search_fields = ("name", "account_identifier", "role_arn")
    readonly_fields = ("encrypted_credentials", "credential_version", "created_at", "updated_at")


@admin.register(CloudResource)
class CloudResourceAdmin(admin.ModelAdmin):
    list_display = ("name", "resource_type", "cloud_account", "region", "risk_level", "is_demo")
    list_filter = ("resource_type", "risk_level", "is_demo")
    search_fields = ("name", "resource_id")
