from django.contrib import messages
from django.contrib.auth.mixins import LoginRequiredMixin
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, redirect, render
from django.utils.http import url_has_allowed_host_and_scheme
from django.views import View
from django.views.generic import CreateView, DetailView, TemplateView

from accounts.permissions import has_organization_level

from .forms import OrganizationCreateForm, OrganizationMemberForm
from .models import Organization, OrganizationMembership
from .services import add_member, create_organization_with_owner, organizations_for_user, set_active_organization


class OrganizationListView(LoginRequiredMixin, TemplateView):
    template_name = "organizations/list.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["organizations"] = organizations_for_user(self.request.user)
        return context


class OrganizationCreateView(LoginRequiredMixin, CreateView):
    model = Organization
    form_class = OrganizationCreateForm
    template_name = "organizations/create.html"

    def form_valid(self, form):
        organization = create_organization_with_owner(
            name=form.cleaned_data["name"],
            owner=self.request.user,
            description=form.cleaned_data.get("description", ""),
        )
        set_active_organization(self.request, organization)
        messages.success(self.request, "Organization created.")
        return redirect("organizations:detail", organization.slug)


class OrganizationDetailView(LoginRequiredMixin, DetailView):
    model = Organization
    template_name = "organizations/detail.html"
    slug_field = "slug"
    slug_url_kwarg = "slug"

    def get_object(self, queryset=None):
        organization = get_object_or_404(Organization, slug=self.kwargs["slug"])
        if not has_organization_level(self.request.user, organization, "viewer"):
            raise PermissionDenied("You do not have access to this organization.")
        return organization

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["memberships"] = self.object.memberships.filter(is_active=True).select_related("user")
        return context


class SetActiveOrganizationView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        organization = get_object_or_404(Organization, id=kwargs["organization_id"])
        if not set_active_organization(request, organization):
            raise PermissionDenied("You do not have access to this organization.")
        messages.success(request, f"Active organization set to {organization.name}.")
        referer = request.META.get("HTTP_REFERER", "")
        if url_has_allowed_host_and_scheme(referer, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
            return redirect(referer)
        return redirect("dashboard:index")


class OrganizationMembersView(LoginRequiredMixin, View):
    template_name = "organizations/members.html"

    def get_organization(self):
        organization = get_object_or_404(Organization, slug=self.kwargs["slug"])
        if not has_organization_level(self.request.user, organization, "admin"):
            raise PermissionDenied("Organization administrator access is required.")
        return organization

    def get(self, request, *args, **kwargs):
        organization = self.get_organization()
        return render(
            request,
            self.template_name,
            {
                "organization": organization,
                "memberships": organization.memberships.filter(is_active=True).select_related("user"),
                "form": OrganizationMemberForm(organization=organization),
            },
        )

    def post(self, request, *args, **kwargs):
        organization = self.get_organization()
        form = OrganizationMemberForm(request.POST, organization=organization)
        if form.is_valid():
            add_member(
                organization=organization,
                email=form.cleaned_data["email"],
                role=form.cleaned_data["role"],
                added_by=request.user,
            )
            messages.success(request, "Organization member updated.")
            return redirect("organizations:members", organization.slug)
        return render(
            request,
            self.template_name,
            {
                "organization": organization,
                "memberships": organization.memberships.filter(is_active=True).select_related("user"),
                "form": form,
            },
        )


class MembershipRemoveView(LoginRequiredMixin, View):
    def post(self, request, *args, **kwargs):
        membership = get_object_or_404(OrganizationMembership, id=kwargs["membership_id"])
        if not has_organization_level(request.user, membership.organization, "admin"):
            raise PermissionDenied("Organization administrator access is required.")
        if membership.role == OrganizationMembership.Role.OWNER:
            raise PermissionDenied("The organization owner cannot be removed.")
        membership.is_active = False
        membership.save(update_fields=["is_active"])
        messages.success(request, "Member access revoked.")
        return redirect("organizations:members", membership.organization.slug)
