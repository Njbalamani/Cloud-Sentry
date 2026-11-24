from django.contrib import admin

from .models import Finding, RemediationReview, ScanRule, ScanRun


@admin.register(ScanRule)
class ScanRuleAdmin(admin.ModelAdmin):
    list_display = ("rule_id", "title", "service", "severity", "cis_control", "enabled")
    list_filter = ("provider", "service", "severity", "enabled")
    search_fields = ("rule_id", "title", "description")


@admin.register(ScanRun)
class ScanRunAdmin(admin.ModelAdmin):
    list_display = ("id", "cloud_account", "organization", "status", "scan_mode", "findings_count", "started_at")
    list_filter = ("status", "scan_mode", "started_at")
    readonly_fields = ("summary", "started_at", "finished_at")


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "status", "risk_score", "cloud_account", "is_demo")
    list_filter = ("severity", "status", "is_demo")
    search_fields = ("title", "description")
    readonly_fields = ("evidence", "remediation")


@admin.register(RemediationReview)
class RemediationReviewAdmin(admin.ModelAdmin):
    list_display = ("finding", "reviewer", "decision", "reviewed_at")
    list_filter = ("decision", "reviewed_at")
