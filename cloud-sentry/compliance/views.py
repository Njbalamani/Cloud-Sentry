from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404
from django.views.generic import DetailView, TemplateView

from accounts.permissions import OrganizationMemberRequiredMixin
from compliance.controls import ensure_controls

from .models import ComplianceAssessment


class ComplianceOverviewView(LoginRequiredMixin, OrganizationMemberRequiredMixin, TemplateView):
    template_name = "compliance/index.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["assessments"] = ComplianceAssessment.objects.filter(
            organization=self.request.current_organization
        ).select_related("scan_run")[:12]
        context["latest"] = context["assessments"][0] if context["assessments"] else None
        context["controls"] = ensure_controls()
        return context


class ComplianceAssessmentDetailView(LoginRequiredMixin, OrganizationMemberRequiredMixin, DetailView):
    model = ComplianceAssessment
    template_name = "compliance/detail.html"
    context_object_name = "assessment"

    def get_object(self, queryset=None):
        return get_object_or_404(
            ComplianceAssessment,
            pk=self.kwargs["pk"],
            organization=self.request.current_organization,
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["results"] = self.object.results.select_related("control")
        return context
