from django.db import models


class RiskAssessment(models.Model):
    class Source(models.TextChoices):
        LOCAL = "local", "Local model"
        GEMINI = "gemini", "Gemini explanation"

    finding = models.ForeignKey("cloud_scanner.Finding", on_delete=models.CASCADE, related_name="risk_assessments")
    score = models.FloatField()
    severity_band = models.CharField(max_length=16)
    model_version = models.CharField(max_length=64)
    factors = models.JSONField(default=dict)
    explanation = models.TextField(blank=True)
    remediation_summary = models.TextField(blank=True)
    source = models.CharField(max_length=16, choices=Source.choices, default=Source.LOCAL)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "risk assessment"
        verbose_name_plural = "risk assessments"
        ordering = ["-created_at"]
        indexes = [models.Index(fields=["finding", "score"])]

    def __str__(self):
        return f"{self.finding.title} - {self.score:.1f}"

    @property
    def organization(self):
        return self.finding.organization
