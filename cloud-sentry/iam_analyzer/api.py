from organizations.api import OrganizationScopedViewSet

from .models import IAMAnalysis
from .serializers import IAMAnalysisSerializer


class IAMAnalysisViewSet(OrganizationScopedViewSet):
    serializer_class = IAMAnalysisSerializer
    http_method_names = ["get", "head", "options"]

    def get_queryset(self):
        queryset = IAMAnalysis.objects.filter(cloud_account__organization=self.get_organization()).select_related(
            "cloud_account"
        )
        cloud_account = self.request.query_params.get("cloud_account")
        if cloud_account:
            queryset = queryset.filter(cloud_account_id=cloud_account)
        return queryset
