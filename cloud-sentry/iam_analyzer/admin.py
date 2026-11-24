from django.contrib import admin

from .models import IAMAnalysis


@admin.register(IAMAnalysis)
class IAMAnalysisAdmin(admin.ModelAdmin):
    list_display = ("policy_name", "cloud_account", "risk_score", "is_demo", "analyzed_at")
    list_filter = ("is_demo", "analyzed_at")
    search_fields = ("policy_name", "principal_arn")
    readonly_fields = ("policy_document", "findings", "recommendations")
