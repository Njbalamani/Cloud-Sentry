from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import get_object_or_404
from django.views.generic import DetailView, ListView

from accounts.permissions import OrganizationMemberRequiredMixin

from .models import RiskAssessment


class RiskAssessmentListView(LoginRequiredMixin, OrganizationMemberRequiredMixin, ListView):
    model = RiskAssessment
    template_name = "risk_engine/list.html"
    context_object_name = "assessments"

    def get_queryset(self):
        return RiskAssessment.objects.filter(
            finding__cloud_account__organization=self.request.current_organization
        ).select_related("finding", "finding__cloud_account")


class RiskAssessmentDetailView(LoginRequiredMixin, OrganizationMemberRequiredMixin, DetailView):
    model = RiskAssessment
    template_name = "risk_engine/detail.html"
    context_object_name = "assessment"

    def get_object(self, queryset=None):
        return get_object_or_404(
            RiskAssessment,
            pk=self.kwargs["pk"],
            finding__cloud_account__organization=self.request.current_organization,
        )
