import uuid

from django.conf import settings
from django.db import models
from django.urls import reverse
from django.utils.text import slugify


class Organization(models.Model):
    name = models.CharField(max_length=150)
    slug = models.SlugField(max_length=170, unique=True, blank=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="created_organizations",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "organization"
        verbose_name_plural = "organizations"
        ordering = ["name"]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        if not self.slug:
            base = slugify(self.name) or "organization"
            candidate = base
            while Organization.objects.filter(slug=candidate).exists():
                candidate = f"{base}-{uuid.uuid4().hex[:6]}"
            self.slug = candidate
        super().save(*args, **kwargs)

    def get_absolute_url(self):
        return reverse("organizations:detail", args=[self.slug])

    @property
    def member_count(self):
        return self.memberships.filter(is_active=True).count()


class OrganizationMembership(models.Model):
    class Role(models.TextChoices):
        OWNER = "owner", "Owner"
        ADMIN = "admin", "Security Administrator"
        ANALYST = "analyst", "Security Analyst"
        VIEWER = "viewer", "Viewer"

    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="memberships")
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, related_name="memberships")
    role = models.CharField(max_length=24, choices=Role.choices, default=Role.ANALYST)
    is_active = models.BooleanField(default=True)
    joined_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "organization membership"
        verbose_name_plural = "organization memberships"
        ordering = ["organization__name", "user__email"]
        constraints = [
            models.UniqueConstraint(fields=["user", "organization"], name="unique_user_organization"),
        ]

    def __str__(self):
        return f"{self.user.email} - {self.organization.name} ({self.role})"

    @property
    def can_manage(self):
        return self.role in {self.Role.OWNER, self.Role.ADMIN}

    @property
    def can_scan(self):
        return self.role in {self.Role.OWNER, self.Role.ADMIN, self.Role.ANALYST}
