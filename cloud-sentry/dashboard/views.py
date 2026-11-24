from django.contrib.auth.mixins import LoginRequiredMixin
from django.shortcuts import redirect
from django.views.generic import TemplateView

from accounts.permissions import OrganizationMemberRequiredMixin

from .services import get_metrics


def landing(request):
    if request.user.is_authenticated:
        return redirect("dashboard:index")
    return redirect("accounts:login")


class DashboardView(LoginRequiredMixin, OrganizationMemberRequiredMixin, TemplateView):
    template_name = "dashboard/index.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["metrics"] = get_metrics(self.request.current_organization)
        return context
