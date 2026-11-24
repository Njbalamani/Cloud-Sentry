from django.urls import reverse
from rest_framework import serializers

from .models import Report


class ReportSerializer(serializers.ModelSerializer):
    download_url = serializers.SerializerMethodField()

    def get_download_url(self, obj):
        return reverse("reports:download", args=[obj.pk])

    class Meta:
        model = Report
        fields = (
            "id",
            "organization",
            "created_by",
            "report_type",
            "file_format",
            "status",
            "parameters",
            "created_at",
            "download_url",
        )
        read_only_fields = fields
