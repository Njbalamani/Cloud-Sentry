from django.db.models import Count

from organizations.api import OrganizationScopedViewSet

from .models import CloudAccount, CloudResource
from .serializers import CloudAccountSerializer, CloudAccountWriteSerializer, CloudResourceSerializer


class CloudAccountViewSet(OrganizationScopedViewSet):
    def get_serializer_class(self):
        if self.action in {"create", "update", "partial_update"}:
            return CloudAccountWriteSerializer
        return CloudAccountSerializer

    def get_queryset(self):
        return CloudAccount.objects.filter(organization=self.get_organization()).annotate(
            resource_count=Count("resources")
        )


class CloudResourceViewSet(OrganizationScopedViewSet):
    serializer_class = CloudResourceSerializer
    http_method_names = ["get", "head", "options"]

    def get_queryset(self):
        queryset = CloudResource.objects.filter(cloud_account__organization=self.get_organization()).select_related(
            "cloud_account"
        )
        account_id = self.request.query_params.get("cloud_account")
        if account_id:
            queryset = queryset.filter(cloud_account_id=account_id)
        resource_type = self.request.query_params.get("resource_type")
        if resource_type:
            queryset = queryset.filter(resource_type=resource_type)
        return queryset
