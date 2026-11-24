from django.conf import settings
from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render
from django.views import View
from django.views.generic import DetailView, ListView, TemplateView

from accounts.permissions import OrganizationMemberRequiredMixin, has_organization_level
from cloud_accounts.models import CloudAccount

from .forms import FindingFilterForm, RemediationReviewForm, StartScanForm
from .models import Finding, RemediationReview, ScanRun
from .services import ScannerError, create_scan_run, review_remediation, run_scan


class SecurityOperationsView(LoginRequiredMixin, OrganizationMemberRequiredMixin, TemplateView):
    template_name = "cloud_scanner/operations.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        organization = self.request.current_organization
        context["accounts"] = CloudAccount.objects.filter(organization=organization, scan_enabled=True)
        context["recent_scans"] = ScanRun.objects.filter(organization=organization).order_by("-started_at")[:8]
        context["open_findings"] = Finding.objects.filter(
            cloud_account__organization=organization,
            status=Finding.Status.OPEN,
        ).order_by("-created_at")[:8]
        return context


class StartScanView(LoginRequiredMixin, OrganizationMemberRequiredMixin, View):
    template_name = "cloud_scanner/start.html"

    def get(self, request):
        form = StartScanForm(organization=request.current_organization)
        if not settings.CLOUDSENTRY["DEMO_MODE"]:
            form.fields["scan_mode"].choices = [
                choice for choice in ScanRun.Mode.choices if choice[0] != ScanRun.Mode.DEMO
            ]
        return render(request, self.template_name, {"form": form})

    def post(self, request):
        if not has_organization_level(request.user, request.current_organization, "analyst"):
            raise PermissionDenied("Analyst access is required to run assessments.")
        form = StartScanForm(request.POST, organization=request.current_organization)
        if not settings.CLOUDSENTRY["DEMO_MODE"]:
            form.fields["scan_mode"].choices = [
                choice for choice in ScanRun.Mode.choices if choice[0] != ScanRun.Mode.DEMO
            ]
        if not form.is_valid():
            return render(request, self.template_name, {"form": form})
        try:
            scan_run = create_scan_run(
                cloud_account=form.cleaned_data["cloud_account"],
                initiated_by=request.user,
                mode=form.cleaned_data["scan_mode"],
            )
            run_scan(scan_run)
        except ScannerError as exc:
            messages.error(request, str(exc))
            return render(request, self.template_name, {"form": form})
        messages.success(request, f"Assessment {scan_run.id} completed with {scan_run.findings_count} findings.")
        return redirect("cloud_scanner:scan-detail", scan_run.pk)


class ScanRunListView(LoginRequiredMixin, OrganizationMemberRequiredMixin, ListView):
    model = ScanRun
    template_name = "cloud_scanner/scan_list.html"
    context_object_name = "scans"

    def get_queryset(self):
        return ScanRun.objects.filter(organization=self.request.current_organization).select_related("cloud_account")


class ScanRunDetailView(LoginRequiredMixin, OrganizationMemberRequiredMixin, DetailView):
    model = ScanRun
    template_name = "cloud_scanner/scan_detail.html"
    context_object_name = "scan"

    def get_object(self, queryset=None):
        return get_object_or_404(
            ScanRun,
            pk=self.kwargs["pk"],
            organization=self.request.current_organization,
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["findings"] = self.object.findings.select_related("resource", "rule").order_by("severity", "title")
        return context


class FindingListView(LoginRequiredMixin, OrganizationMemberRequiredMixin, ListView):
    model = Finding
    template_name = "cloud_scanner/finding_list.html"
    context_object_name = "findings"
    paginate_by = 25

    def get_queryset(self):
        self.filter_form = FindingFilterForm(self.request.GET)
        queryset = Finding.objects.filter(
            cloud_account__organization=self.request.current_organization
        ).select_related("cloud_account", "resource", "rule")
        if self.filter_form.is_valid():
            data = self.filter_form.cleaned_data
            if data.get("severity"):
                queryset = queryset.filter(severity=data["severity"])
            if data.get("status"):
                queryset = queryset.filter(status=data["status"])
            if data.get("search"):
                term = data["search"]
                queryset = queryset.filter(
                    Q(title__icontains=term)
                    | Q(description__icontains=term)
                    | Q(rule__title__icontains=term)
                    | Q(resource__name__icontains=term)
                )
        return queryset.order_by("-created_at")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["filter_form"] = self.filter_form
        return context


class FindingDetailView(LoginRequiredMixin, OrganizationMemberRequiredMixin, View):
    template_name = "cloud_scanner/finding_detail.html"

    def get_finding(self):
        return get_object_or_404(
            Finding,
            pk=self.kwargs["pk"],
            cloud_account__organization=self.request.current_organization,
        )

    def get_context_data(self, finding):
        from risk_engine.models import RiskAssessment

        can_review = has_organization_level(self.request.user, self.request.current_organization, "admin")
        return {
            "finding": finding,
            "risk_assessments": RiskAssessment.objects.filter(finding=finding).order_by("-created_at"),
            "reviews": RemediationReview.objects.filter(finding=finding).select_related("reviewer"),
            "review_form": RemediationReviewForm() if can_review else None,
            "can_review": can_review,
        }

    def get(self, request, *args, **kwargs):
        finding = self.get_finding()
        return render(request, self.template_name, self.get_context_data(finding))

    def post(self, request, *args, **kwargs):
        finding = self.get_finding()
        if not has_organization_level(request.user, request.current_organization, "admin"):
            raise PermissionDenied("Administrator access is required to review remediation actions.")
        form = RemediationReviewForm(request.POST)
        if form.is_valid():
            review_remediation(
                finding=finding,
                reviewer=request.user,
                decision=form.cleaned_data["decision"],
                notes=form.cleaned_data.get("notes", ""),
            )
            messages.success(request, "Remediation review recorded. No cloud changes were made.")
            return redirect("cloud_scanner:finding-detail", finding.pk)
        context = self.get_context_data(finding)
        context["review_form"] = form
        return render(request, self.template_name, context)
