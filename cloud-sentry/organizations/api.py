from rest_framework.exceptions import PermissionDenied
from rest_framework.permissions import IsAuthenticated
from rest_framework.viewsets import ModelViewSet, ReadOnlyModelViewSet

from accounts.permissions import IsOrganizationMember, has_organization_level

from .models import OrganizationMembership
from .serializers import OrganizationMembershipSerializer, OrganizationSerializer
from .services import organizations_for_user


class OrganizationViewSet(ReadOnlyModelViewSet):
    serializer_class = OrganizationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return organizations_for_user(self.request.user)


class OrganizationMembershipViewSet(ReadOnlyModelViewSet):
    serializer_class = OrganizationMembershipSerializer
    permission_classes = [IsAuthenticated, IsOrganizationMember]
    http_method_names = ["get", "head", "options"]

    def get_organization(self):
        organization = getattr(self.request, "current_organization", None)
        if organization is None:
            raise PermissionDenied("Select an active organization.")
        return organization

    def get_queryset(self):
        return OrganizationMembership.objects.filter(
            organization=self.get_organization(),
            is_active=True,
        ).select_related("user")

    def get_object(self):
        obj = super().get_object()
        if not has_organization_level(self.request.user, self.get_organization(), "admin"):
            if obj.user_id != self.request.user.id:
                raise PermissionDenied("Organization administrator access is required.")
        return obj


class OrganizationScopedViewSet(ModelViewSet):
    permission_classes = [IsAuthenticated, IsOrganizationMember]

    def get_organization(self):
        organization = getattr(self.request, "current_organization", None)
        if organization is None:
            raise PermissionDenied("Select an active organization.")
        return organization
