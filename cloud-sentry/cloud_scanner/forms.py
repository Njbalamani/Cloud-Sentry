from django import forms

from cloud_accounts.models import CloudAccount

from .models import Finding, RemediationReview, ScanRun


class StartScanForm(forms.Form):
    cloud_account = forms.ModelChoiceField(queryset=CloudAccount.objects.none(), label="Cloud account")
    scan_mode = forms.ChoiceField(
        choices=ScanRun.Mode.choices,
        initial=ScanRun.Mode.LIVE,
        label="Assessment mode",
        help_text="Live mode uses read-only AWS APIs. Demo mode uses labelled synthetic data.",
    )

    def __init__(self, *args, organization=None, **kwargs):
        super().__init__(*args, **kwargs)
        if organization:
            self.fields["cloud_account"].queryset = CloudAccount.objects.filter(
                organization=organization,
                scan_enabled=True,
            )


class RemediationReviewForm(forms.ModelForm):
    class Meta:
        model = RemediationReview
        fields = ("decision", "notes")
        widgets = {
            "notes": forms.Textarea(attrs={"rows": 4}),
        }


class FindingFilterForm(forms.Form):
    severity = forms.ChoiceField(choices=[("", "All severities")] + Finding.Severity.choices, required=False)
    status = forms.ChoiceField(choices=[("", "All statuses")] + Finding.Status.choices, required=False)
    search = forms.CharField(max_length=120, required=False)
