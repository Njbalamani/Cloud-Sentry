import re

from django import forms

from .models import AWS_REGIONS, CloudAccount


class CloudAccountForm(forms.ModelForm):
    access_key_id = forms.CharField(max_length=120, required=False, label="AWS access key ID")
    secret_access_key = forms.CharField(
        max_length=300,
        required=False,
        widget=forms.PasswordInput(render_value=False),
        label="AWS secret access key",
    )
    external_id = forms.CharField(max_length=200, required=False, widget=forms.PasswordInput(render_value=False))
    read_only_ack = forms.BooleanField(required=True, label="I confirm these credentials are read-only")

    class Meta:
        model = CloudAccount
        fields = (
            "name",
            "account_identifier",
            "region",
            "credential_type",
            "role_arn",
            "notes",
            "access_key_id",
            "secret_access_key",
            "external_id",
        )
        widgets = {
            "notes": forms.Textarea(attrs={"rows": 3}),
            "region": forms.Select(choices=AWS_REGIONS),
        }

    def clean_account_identifier(self):
        value = self.cleaned_data["account_identifier"].strip()
        if not re.fullmatch(r"\d{12}", value):
            raise forms.ValidationError("Enter the 12-digit AWS account identifier.")
        return value

    def clean_role_arn(self):
        value = self.cleaned_data.get("role_arn", "").strip()
        if value and not re.fullmatch(r"arn:aws:iam::\d{12}:role/[\w+=,.@/-]+", value):
            raise forms.ValidationError("Enter a valid IAM role ARN.")
        return value

    def clean(self):
        cleaned = super().clean()
        credential_type = cleaned.get("credential_type")
        access_key = cleaned.get("access_key_id", "").strip()
        secret_key = cleaned.get("secret_access_key", "").strip()
        if not access_key or not secret_key:
            self.add_error("access_key_id", "AWS access credentials are required.")
        if credential_type == CloudAccount.CredentialType.ASSUME_ROLE and not cleaned.get("role_arn"):
            self.add_error("role_arn", "A role ARN is required for role-based access.")
        cleaned["credentials"] = {
            "access_key_id": access_key,
            "secret_access_key": secret_key,
        }
        if cleaned.get("external_id"):
            cleaned["credentials"]["external_id"] = cleaned["external_id"]
        return cleaned
