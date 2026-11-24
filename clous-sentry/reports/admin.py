from django.contrib import admin

from .models import Report


@admin.register(Report)
class ReportAdmin(admin.ModelAdmin):
    list_display = ("report_type", "organization", "file_format", "status", "created_at")
    list_filter = ("report_type", "file_format", "status")
    search_fields = ("organization__name",)
    readonly_fields = ("parameters", "created_at")
