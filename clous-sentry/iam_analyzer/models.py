from django.conf import settings
from django.db import models


class IAMAnalysis(models.Model):
    cloud_account = models.ForeignKey(
        "cloud_accounts.CloudAccount",
        on_delete=models.CASCADE,
        related_name="iam_analyses",
    )
    scan_run = models.ForeignKey(
        "cloud_scanner.ScanRun",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="iam_analyses",
    )
    principal_arn = models.CharField(max_length=400)
    policy_name = models.CharField(max_length=255)
    policy_document = models.JSONField(default=dict)
    findings = models.JSONField(default=list)
    recommendations = models.JSONField(default=list)
    risk_score = models.FloatField(default=0)
    is_demo = models.BooleanField(default=False)
    analyzed_at = models.DateTimeField(auto_now_add=True)
    analyzed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="iam_analyses",
    )

    class Meta:
        verbose_name = "IAM analysis"
        verbose_name_plural = "IAM analyses"
        ordering = ["-analyzed_at"]
        indexes = [models.Index(fields=["cloud_account", "risk_score"])]

    def __str__(self):
        return f"{self.policy_name} - {self.principal_arn}"

    @property
    def organization(self):
        return self.cloud_account.organization
