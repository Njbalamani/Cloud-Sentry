from django.contrib import admin

from .models import ComplianceAssessment, ComplianceControl, ControlResult


@admin.register(ComplianceControl)
class ComplianceControlAdmin(admin.ModelAdmin):
    list_display = ("control_id", "title", "framework", "severity", "enabled")
    list_filter = ("framework", "severity", "enabled")
    search_fields = ("control_id", "title")


@admin.register(ComplianceAssessment)
class ComplianceAssessmentAdmin(admin.ModelAdmin):
    list_display = ("organization", "score", "passed", "failed", "total", "created_at")
    list_filter = ("created_at",)
    readonly_fields = ("summary",)


@admin.register(ControlResult)
class ControlResultAdmin(admin.ModelAdmin):
    list_display = ("assessment", "control", "status")
    list_filter = ("status",)
    readonly_fields = ("evidence",)
