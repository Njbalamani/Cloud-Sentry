from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views import View
from django.views.generic import DetailView, ListView

from accounts.permissions import OrganizationMemberRequiredMixin, has_organization_level
from cloud_scanner.models import ScanRun

from .forms import IAMAnalyzeForm
from .models import IAMAnalysis
from .services import analyze_cloud_account


class IAMAnalysisListView(LoginRequiredMixin, OrganizationMemberRequiredMixin, ListView):
    model = IAMAnalysis
    template_name = "iam_analyzer/list.html"
    context_object_name = "analyses"

    def get_queryset(self):
        return IAMAnalysis.objects.filter(cloud_account__organization=self.request.current_organization).select_related(
            "cloud_account"
        )


class IAMAnalysisDetailView(LoginRequiredMixin, OrganizationMemberRequiredMixin, DetailView):
    model = IAMAnalysis
    template_name = "iam_analyzer/detail.html"
    context_object_name = "analysis"

    def get_object(self, queryset=None):
        return get_object_or_404(
            IAMAnalysis,
            pk=self.kwargs["pk"],
            cloud_account__organization=self.request.current_organization,
        )


class AnalyzeIAMView(LoginRequiredMixin, OrganizationMemberRequiredMixin, View):
    template_name = "iam_analyzer/analyze.html"

    def get(self, request):
        return render(request, self.template_name, {"form": IAMAnalyzeForm(organization=request.current_organization)})

    def post(self, request):
        if not has_organization_level(request.user, request.current_organization, "analyst"):
            raise PermissionDenied("Analyst access is required to analyze IAM policies.")
        form = IAMAnalyzeForm(request.POST, organization=request.current_organization)
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})
        cloud_account = form.cleaned_data["cloud_account"]
        scan_run = ScanRun.objects.create(
            organization=request.current_organization,
            cloud_account=cloud_account,
            initiated_by=request.user,
            scan_mode=ScanRun.Mode.LIVE,
            status=ScanRun.Status.RUNNING,
            summary={"source": "IAM analyzer"},
        )
        try:
            analyses = analyze_cloud_account(cloud_account, scan_run=scan_run, user=request.user)
        except Exception:
            scan_run.status = ScanRun.Status.FAILED
            scan_run.error_message = "IAM analysis could not be completed. Verify the read-only connection."
            scan_run.finished_at = timezone.now()
            scan_run.save(update_fields=["status", "error_message", "finished_at", "updated_at"])
            messages.error(request, scan_run.error_message)
            return render(request, self.template_name, {"form": form})
        scan_run.status = ScanRun.Status.COMPLETED
        scan_run.findings_count = sum(len(analysis.findings) for analysis in analyses)
        scan_run.summary = {"source": "IAM analyzer", "policies_analyzed": len(analyses)}
        scan_run.finished_at = timezone.now()
        scan_run.save(update_fields=["status", "findings_count", "summary", "finished_at", "updated_at"])
        messages.success(request, f"Analyzed {len(analyses)} IAM policies and role trust documents.")
        return redirect("iam_analyzer:list")
