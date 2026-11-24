import base64
import hashlib
import json
import uuid

import boto3
from botocore.config import Config
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.db import models
from django.urls import reverse


def fernet_cipher():
    configured_key = settings.CLOUDSENTRY.get("FIELD_ENCRYPTION_KEY", "")
    if configured_key:
        key = configured_key.encode("utf-8")
    else:
        key = base64.urlsafe_b64encode(hashlib.sha256(settings.SECRET_KEY.encode("utf-8")).digest())
    return Fernet(key)


AWS_REGIONS = [
    ("us-east-1", "US East (N. Virginia)"),
    ("us-east-2", "US East (Ohio)"),
    ("us-west-1", "US West (N. California)"),
    ("us-west-2", "US West (Oregon)"),
    ("eu-west-1", "EU (Ireland)"),
    ("eu-west-2", "EU (London)"),
    ("eu-central-1", "EU (Frankfurt)"),
    ("ap-southeast-1", "Asia Pacific (Singapore)"),
    ("ap-southeast-2", "Asia Pacific (Sydney)"),
    ("ap-northeast-1", "Asia Pacific (Tokyo)"),
    ("ca-central-1", "Canada (Central)"),
]


class CloudAccount(models.Model):
    class Provider(models.TextChoices):
        AWS = "aws", "Amazon Web Services"

    class CredentialType(models.TextChoices):
        ACCESS_KEY = "access_key", "Access key"
        ASSUME_ROLE = "assume_role", "Assume role"

    class Status(models.TextChoices):
        PENDING = "pending", "Pending verification"
        ACTIVE = "active", "Active"
        ERROR = "error", "Connection error"
        DISCONNECTED = "disconnected", "Disconnected"

    organization = models.ForeignKey("organizations.Organization", on_delete=models.CASCADE, related_name="cloud_accounts")
    name = models.CharField(max_length=150)
    provider = models.CharField(max_length=16, choices=Provider.choices, default=Provider.AWS)
    account_identifier = models.CharField(max_length=32)
    region = models.CharField(max_length=32, default="us-east-1", choices=AWS_REGIONS)
    credential_type = models.CharField(max_length=24, choices=CredentialType.choices, default=CredentialType.ASSUME_ROLE)
    role_arn = models.CharField(max_length=300, blank=True)
    encrypted_credentials = models.TextField(blank=True)
    credential_version = models.PositiveIntegerField(default=0)
    is_read_only = models.BooleanField(default=True)
    scan_enabled = models.BooleanField(default=True)
    status = models.CharField(max_length=24, choices=Status.choices, default=Status.PENDING)
    notes = models.TextField(blank=True)
    last_checked_at = models.DateTimeField(null=True, blank=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name="cloud_accounts",
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "cloud account"
        verbose_name_plural = "cloud accounts"
        ordering = ["name"]
        constraints = [
            models.UniqueConstraint(
                fields=["organization", "provider", "account_identifier"],
                name="unique_cloud_account_per_organization",
            ),
        ]

    def __str__(self):
        return f"{self.name} ({self.account_identifier})"

    def get_absolute_url(self):
        return reverse("cloud_accounts:detail", args=[self.pk])

    def set_credentials(self, credentials):
        payload = json.dumps(credentials, separators=(",", ":"))
        self.encrypted_credentials = fernet_cipher().encrypt(payload.encode("utf-8")).decode("utf-8")
        self.credential_version += 1

    def get_credentials(self):
        if not self.encrypted_credentials:
            return {}
        try:
            payload = fernet_cipher().decrypt(self.encrypted_credentials.encode("utf-8"))
            return json.loads(payload.decode("utf-8"))
        except (InvalidToken, ValueError, json.JSONDecodeError):
            return {}

    def get_boto3_session(self):
        credentials = self.get_credentials()
        config = Config(retries={"max_attempts": 3, "mode": "standard"})
        if self.credential_type == self.CredentialType.ACCESS_KEY:
            return boto3.Session(
                aws_access_key_id=credentials.get("access_key_id"),
                aws_secret_access_key=credentials.get("secret_access_key"),
                aws_session_token=credentials.get("session_token") or None,
                region_name=self.region,
            )
        base_session = boto3.Session(
            aws_access_key_id=credentials.get("access_key_id"),
            aws_secret_access_key=credentials.get("secret_access_key"),
            region_name=self.region,
        )
        sts = base_session.client("sts", config=config)
        assume_args = {
            "RoleArn": self.role_arn,
            "RoleSessionName": "CloudSentryReadOnlyAssessment",
            "DurationSeconds": 3600,
        }
        if credentials.get("external_id"):
            assume_args["ExternalId"] = credentials["external_id"]
        assumed = sts.assume_role(**assume_args)
        temporary = assumed["Credentials"]
        return boto3.Session(
            aws_access_key_id=temporary["AccessKeyId"],
            aws_secret_access_key=temporary["SecretAccessKey"],
            aws_session_token=temporary["SessionToken"],
            region_name=self.region,
        )

    @property
    def credential_hint(self):
        return f"v{self.credential_version}" if self.credential_version else "not configured"

    def clear_credentials(self):
        self.encrypted_credentials = ""
        self.credential_version = 0
        self.status = self.Status.DISCONNECTED


class CloudResource(models.Model):
    class RiskLevel(models.TextChoices):
        NONE = "none", "None"
        LOW = "low", "Low"
        MEDIUM = "medium", "Medium"
        HIGH = "high", "High"
        CRITICAL = "critical", "Critical"

    cloud_account = models.ForeignKey(CloudAccount, on_delete=models.CASCADE, related_name="resources")
    resource_id = models.CharField(max_length=300)
    resource_type = models.CharField(max_length=80, db_index=True)
    name = models.CharField(max_length=255, blank=True)
    region = models.CharField(max_length=32, blank=True)
    metadata = models.JSONField(default=dict)
    tags = models.JSONField(default=dict)
    risk_level = models.CharField(max_length=16, choices=RiskLevel.choices, default=RiskLevel.NONE, db_index=True)
    is_demo = models.BooleanField(default=False)
    discovered_at = models.DateTimeField(auto_now_add=True)
    last_seen_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "cloud resource"
        verbose_name_plural = "cloud resources"
        ordering = ["resource_type", "name"]
        constraints = [
            models.UniqueConstraint(fields=["cloud_account", "resource_id"], name="unique_resource_per_account"),
        ]
        indexes = [models.Index(fields=["cloud_account", "resource_type"])]

    def __str__(self):
        return self.name or self.resource_id

    @property
    def organization(self):
        return self.cloud_account.organization

    @property
    def kind(self):
        return uuid.uuid5(uuid.NAMESPACE_DNS, f"{self.resource_type}:{self.resource_id}").hex[:8]
