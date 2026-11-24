from django import forms

from cloud_scanner.models import ScanRun

from .models import Report


class ReportGenerateForm(forms.Form):
    report_type = forms.ChoiceField(choices=Report.ReportType.choices, label="Report type")
    file_format = forms.ChoiceField(choices=Report.FileFormat.choices, label="File format")
    scan_run = forms.ModelChoiceField(queryset=ScanRun.objects.none(), required=False, label="Assessment scope")
    include_demo = forms.BooleanField(required=False, label="Include clearly labelled synthetic demo data")

    def __init__(self, *args, organization=None, **kwargs):
        super().__init__(*args, **kwargs)
        if organization:
            self.fields["scan_run"].queryset = ScanRun.objects.filter(organization=organization)
