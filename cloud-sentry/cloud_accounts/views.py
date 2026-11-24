from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.db.models import Count, Q
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect
from django.views import View
from django.views.generic import CreateView, DetailView, ListView

from accounts.permissions import OrganizationMemberRequiredMixin, has_organization_level

from .forms import CloudAccountForm
from .models import CloudAccount, CloudResource
from .services import test_connection


class CloudAccountListView(LoginRequiredMixin, OrganizationMemberRequiredMixin, ListView):
    model = CloudAccount
    template_name = "cloud_accounts/list.html"
    context_object_name = "accounts"

    def get_queryset(self):
        return CloudAccount.objects.filter(organization=self.request.current_organization).annotate(
            resource_count=Count("resources"),
            finding_count=Count("findings", filter=Q(findings__status="open")),
        )


class CloudAccountDetailView(LoginRequiredMixin, OrganizationMemberRequiredMixin, DetailView):
    model = CloudAccount
    template_name = "cloud_accounts/detail.html"
    context_object_name = "cloud_account"

    def get_object(self, queryset=None):
        return get_object_or_404(
            CloudAccount,
            pk=self.kwargs["pk"],
            organization=self.request.current_organization,
        )

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["resources"] = CloudResource.objects.filter(cloud_account=self.object).order_by("resource_type")
        context["scans"] = self.object.scans.order_by("-started_at")[:10]
        return context


class CloudAccountCreateView(LoginRequiredMixin, OrganizationMemberRequiredMixin, CreateView):
    model = CloudAccount
    form_class = CloudAccountForm
    template_name = "cloud_accounts/connect.html"

    def form_valid(self, form):
        if not has_organization_level(self.request.user, self.request.current_organization, "admin"):
            raise PermissionDenied("Administrator access is required to connect cloud accounts.")
        account = form.save(commit=False)
        account.organization = self.request.current_organization
        account.created_by = self.request.user
        account.is_read_only = True
        account.set_credentials(form.cleaned_data["credentials"])
        account.save()
        messages.success(self.request, "Cloud account saved. Verify the read-only connection before scanning.")
        return redirect("cloud_accounts:detail", account.pk)


class CloudAccountResourcesView(LoginRequiredMixin, OrganizationMemberRequiredMixin, ListView):
    model = CloudResource
    template_name = "cloud_accounts/resources.html"
    context_object_name = "resources"

    def get_queryset(self):
        self.cloud_account = get_object_or_404(
            CloudAccount,
            pk=self.kwargs["pk"],
            organization=self.request.current_organization,
        )
        return CloudResource.objects.filter(cloud_account=self.cloud_account).order_by("resource_type", "name")

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["cloud_account"] = self.cloud_account
        return context


class TestConnectionView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        account = get_object_or_404(
            CloudAccount,
            pk=kwargs["pk"],
            organization=request.current_organization,
        )
        if not has_organization_level(request.user, request.current_organization, "analyst"):
            raise PermissionDenied("Analyst access is required to verify connections.")
        result = test_connection(account)
        status = 200 if result["success"] else 400
        return JsonResponse(result, status=status)
