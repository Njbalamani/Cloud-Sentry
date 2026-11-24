from django.db import models


class ComplianceControl(models.Model):
    framework = models.CharField(max_length=80, default="CIS AWS Foundations Benchmark v2.0")
    control_id = models.CharField(max_length=32)
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=16, default="medium")
    rule_ids = models.JSONField(default=list)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "compliance control"
        verbose_name_plural = "compliance controls"
        ordering = ["framework", "control_id"]
        constraints = [
            models.UniqueConstraint(fields=["framework", "control_id"], name="unique_framework_control"),
        ]

    def __str__(self):
        return f"{self.control_id} - {self.title}"


class ComplianceAssessment(models.Model):
    organization = models.ForeignKey(
        "organizations.Organization",
        on_delete=models.CASCADE,
        related_name="compliance_assessments",
    )
    scan_run = models.ForeignKey(
        "cloud_scanner.ScanRun",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="compliance_assessments",
    )
    score = models.FloatField(default=0)
    passed = models.PositiveIntegerField(default=0)
    failed = models.PositiveIntegerField(default=0)
    total = models.PositiveIntegerField(default=0)
    summary = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "compliance assessment"
        verbose_name_plural = "compliance assessments"
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["organization", "created_at"])]

    def __str__(self):
        return f"{self.organization.name} compliance {self.score:.1f}%"


class ControlResult(models.Model):
    class Status(models.TextChoices):
        PASSED = "passed", "Passed"
        FAILED = "failed", "Failed"
        NOT_APPLICABLE = "not_applicable", "Not applicable"

    assessment = models.ForeignKey(ComplianceAssessment, on_delete=models.CASCADE, related_name="results")
    control = models.ForeignKey(ComplianceControl, on_delete=models.CASCADE, related_name="results")
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PASSED)
    evidence = models.JSONField(default=dict)

    class Meta:
        verbose_name = "control result"
        verbose_name_plural = "control results"
        ordering = ["control__control_id"]
        constraints = [
            models.UniqueConstraint(fields=["assessment", "control"], name="unique_control_per_assessment"),
        ]

    def __str__(self):
        return f"{self.control.control_id} - {self.status}"
