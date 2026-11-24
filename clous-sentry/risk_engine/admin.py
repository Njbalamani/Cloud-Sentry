from django.contrib import admin

from .models import RiskAssessment


@admin.register(RiskAssessment)
class RiskAssessmentAdmin(admin.ModelAdmin):
    list_display = ("finding", "score", "severity_band", "model_version", "source", "created_at")
    list_filter = ("severity_band", "source", "model_version")
    search_fields = ("finding__title",)
    readonly_fields = ("factors", "explanation", "remediation_summary")
