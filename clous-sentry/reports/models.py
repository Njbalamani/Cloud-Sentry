from django.conf import settings
from django.db import models


class Report(models.Model):
    class ReportType(models.TextChoices):
        SECURITY_ASSESSMENT = "security_assessment", "Cloud security assessment"
        FINDINGS = "findings", "Security findings"
        COMPLIANCE = "compliance", "Compliance report"
        IAM_RISK = "iam_risk", "IAM risk report"

    class FileFormat(models.TextChoices):
        PDF = "pdf", "PDF"
        CSV = "csv", "CSV"

    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="reports")
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="reports",
    )
    report_type = models.CharField(max_length=32, choices=ReportType.choices)
    file_format = models.CharField(max_length=8, choices=FileFormat.choices, default=FileFormat.PDF)
    file = models.FileField(upload_to="reports/")
    status = models.CharField(max_length=16, default="completed")
    parameters = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "report"
        verbose_name_plural = "reports"
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.get_report_type_display()} ({self.file_format.upper()})"

    def delete(self, *args, **kwargs):
        file_name = self.file.name
        result = super().delete(*args, **kwargs)
        if file_name:
            self.file.storage.delete(file_name)
        return result
