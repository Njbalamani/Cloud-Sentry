from django.core.exceptions import PermissionDenied
from django.shortcuts import redirect
from rest_framework.permissions import BasePermission

ROLE_LEVELS = {"viewer": 1, "analyst": 2, "admin": 3, "owner": 4}


def organization_role(user, organization):
    if not user or not user.is_authenticated or organization is None:
        return None
    if user.is_platform_admin:
        return "owner"
    from organizations.models import OrganizationMembership

    membership = OrganizationMembership.objects.filter(
        user=user,
        organization=organization,
        is_active=True,
    ).first()
    return membership.role if membership else None


def has_organization_level(user, organization, minimum_role="analyst"):
    role = organization_role(user, organization)
    if role is None:
        return False
    return ROLE_LEVELS.get(role, 0) >= ROLE_LEVELS.get(minimum_role, 2)


class OrganizationMemberRequiredMixin:
    minimum_role = "analyst"

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("accounts:login")
        organization = getattr(request, "current_organization", None)
        if organization is None:
            raise PermissionDenied("Select an active organization.")
        if not has_organization_level(request.user, organization, self.minimum_role):
            raise PermissionDenied("You do not have access to this organization.")
        return super().dispatch(request, *args, **kwargs)


class OrganizationAdminRequiredMixin(OrganizationMemberRequiredMixin):
    minimum_role = "admin"


class PlatformAdminRequiredMixin:
    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return redirect("accounts:login")
        if not request.user.is_platform_admin:
            raise PermissionDenied("Platform administrator access is required.")
        return super().dispatch(request, *args, **kwargs)


class IsOrganizationMember(BasePermission):
    minimum_role = "analyst"

    def has_permission(self, request, view):
        organization = view.get_organization()
        return has_organization_level(request.user, organization, self.minimum_role)

    def has_object_permission(self, request, view, obj):
        organization = getattr(obj, "organization", None) or view.get_organization()
        return has_organization_level(request.user, organization, self.minimum_role)


class IsOrganizationAdmin(IsOrganizationMember):
    minimum_role = "admin"


class IsOrganizationViewer(IsOrganizationMember):
    minimum_role = "viewer"
