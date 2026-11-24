from django import forms

from cloud_accounts.models import CloudAccount


class IAMAnalyzeForm(forms.Form):
    cloud_account = forms.ModelChoiceField(queryset=CloudAccount.objects.none(), label="Cloud account")

    def __init__(self, *args, organization=None, **kwargs):
        super().__init__(*args, **kwargs)
        if organization:
            self.fields["cloud_account"].queryset = CloudAccount.objects.filter(
                organization=organization,
                is_read_only=True,
            )
