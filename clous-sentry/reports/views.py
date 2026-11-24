from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.http import FileResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from django.views.generic import ListView

from accounts.permissions import OrganizationMemberRequiredMixin, has_organization_level

from .forms import ReportGenerateForm
from .models import Report
from .services import ReportService


class ReportListView(LoginRequiredMixin, OrganizationMemberRequiredMixin, ListView):
    model = Report
    template_name = "reports/list.html"
    context_object_name = "reports"

    def get_queryset(self):
        return Report.objects.filter(organization=self.request.current_organization).select_related("created_by")


class GenerateReportView(LoginRequiredMixin, OrganizationMemberRequiredMixin, View):
    template_name = "reports/generate.html"

    def get(self, request):
        return render(
            request,
            self.template_name,
            {"form": ReportGenerateForm(organization=request.current_organization)},
        )

    def post(self, request):
        if not has_organization_level(request.user, request.current_organization, "analyst"):
            raise PermissionDenied("Analyst access is required to generate reports.")
        form = ReportGenerateForm(request.POST, organization=request.current_organization)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})
        if form.cleaned_data.get("include_demo") and not settings.CLOUDSENTRY["DEMO_MODE"]:
            form.add_error("include_demo", "Demo data is disabled for this deployment.")
            return render(request, self.template_name, {"form": form})
        try:
            report = ReportService.generate(
                organization=request.current_organization,
                created_by=request.user,
                report_type=form.cleaned_data["report_type"],
                file_format=form.cleaned_data["file_format"],
                scan_run=form.cleaned_data.get("scan_run"),
                include_demo=form.cleaned_data.get("include_demo", False),
            )
        except ValueError as exc:
            messages.error(request, str(exc))
            return render(request, self.template_name, {"form": form})
        except Exception:
            messages.error(request, "The report could not be generated.")
            return render(request, self.template_name, {"form": form})
        messages.success(request, "Report generated and ready to download.")
        return redirect("reports:download", report.pk)


class DownloadReportView(LoginRequiredMixin, OrganizationMemberRequiredMixin, View):
    def get(self, request, *args, **kwargs):
        report = get_object_or_404(
            Report,
            pk=kwargs["pk"],
            organization=request.current_organization,
        )
        if not report.file:
            raise PermissionDenied("The report file is unavailable.")
        filename = report.file.name.rsplit("/", 1)[-1]
        content_type = "text/csv" if report.file_format == Report.FileFormat.CSV else "application/pdf"
        response = FileResponse(report.file.open("rb"), as_attachment=True, filename=filename, content_type=content_type)
        return response
