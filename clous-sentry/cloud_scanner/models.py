from django.conf import settings
from django.db import models


class ScanRule(models.Model):
    class Severity(models.TextChoices):
        INFO = "info", "Informational"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    rule_id = models.CharField(max_length=80, unique=True)
    title = models.CharField(max_length=200)
    description = models.TextField(blank=True)
    provider = models.CharField(max_length=16, default="aws")
    service = models.CharField(max_length=48)
    category = models.CharField(max_length=64)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MEDIUM)
    cis_control = models.CharField(max_length=32, blank=True)
    benchmark = models.CharField(max_length=64, default="CIS AWS Foundations v2.0")
    remediation = models.JSONField(default=dict)
    enabled = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "scan rule"
        verbose_name_plural = "scan rules"
        ordering = ["rule_id"]
        indexes = [models.Index(fields=["provider", "service", "enabled"])]

    def __str__(self):
        return f"{self.rule_id} - {self.title}"


class ScanRun(models.Model):
    class Status(models.TextChoices):
        PENDING = "pending", "Pending"
        RUNNING = "running", "Running"
        COMPLETED = "completed", "Completed"
        FAILED = "failed", "Failed"
        CANCELLED = "cancelled", "Cancelled"

    class Mode(models.TextChoices):
        LIVE = "live", "Live read-only AWS assessment"
        DEMO = "demo", "Synthetic demo assessment"
        PROWLER = "prowler", "Prowler assessment"

    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="scans")
    cloud_account = models.ForeignKey(
        "cloud_accounts.CloudAccount",
        on_delete=models.CASCADE,
        related_name="scans",
    )
    initiated_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="scans",
    )
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.PENDING)
    scan_mode = models.CharField(max_length=16, choices=Mode.choices, default=Mode.LIVE)
    started_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    resources_scanned = models.PositiveIntegerField(default=0)
    findings_count = models.PositiveIntegerField(default=0)
    summary = models.JSONField(default=dict)
    error_message = models.TextField(blank=True)

    class Meta:
        verbose_name = "scan run"
        verbose_name_plural = "scan runs"
        ordering = ["-started_at"]
        indexes = [models.Index(fields=["organization", "status"])]

    def __str__(self):
        return f"Scan {self.id} - {self.cloud_account.name}"

    @property
    def duration_seconds(self):
        if not self.finished_at:
            return None
        return int((self.finished_at - self.started_at).total_seconds())

    @property
    def is_demo(self):
        return self.scan_mode == self.Mode.DEMO


class Finding(models.Model):
    class Severity(models.TextChoices):
        INFO = "info", "Informational"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    class Status(models.TextChoices):
        OPEN = "open", "Open"
        IN_REVIEW = "in_review", "In review"
        ACCEPTED = "accepted", "Risk accepted"
        REMEDIATED = "remediated", "Remediated"

    scan_run = models.ForeignKey(ScanRun, on_delete=models.CASCADE, related_name="findings")
    cloud_account = models.ForeignKey("cloud_accounts.CloudAccount", on_delete=models.CASCADE, related_name="findings")
    resource = models.ForeignKey(
        "cloud_accounts.CloudResource",
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="findings",
    )
    rule = models.ForeignKey(ScanRule, on_delete=models.SET_NULL, null=True, related_name="findings")
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    severity = models.CharField(max_length=16, choices=Severity.choices, default=Severity.MEDIUM)
    status = models.CharField(max_length=16, choices=Status.choices, default=Status.OPEN)
    evidence = models.JSONField(default=dict)
    remediation = models.JSONField(default=dict)
    risk_score = models.FloatField(default=0)
    is_demo = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "security finding"
        verbose_name_plural = "security findings"
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["cloud_account", "severity"]),
            models.Index(fields=["status", "severity"]),
        ]

    def __str__(self):
        return self.title

    @property
    def organization(self):
        return self.cloud_account.organization

    @property
    def resource_name(self):
        return self.resource.name if self.resource else self.evidence.get("resource", "Unknown resource")


class RemediationReview(models.Model):
    class Decision(models.TextChoices):
        PENDING = "pending", "Pending"
        APPROVED = "approved", "Approved for administrator action"
        REJECTED = "rejected", "Rejected"
        COMPLETED = "completed", "Completed out of band"

    finding = models.ForeignKey(Finding, on_delete=models.CASCADE, related_name="reviews")
    reviewer = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True)
    decision = models.CharField(max_length=16, choices=Decision.choices, default=Decision.PENDING)
    notes = models.TextField(blank=True)
    proposed_action = models.JSONField(default=dict)
    reviewed_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "remediation review"
        verbose_name_plural = "remediation reviews"
        ordering = ["-reviewed_at"]

    def __str__(self):
        return f"{self.finding.title} - {self.decision}"
