from organizations.api import OrganizationScopedViewSet

from .models import ComplianceAssessment, ComplianceControl
from .serializers import ComplianceAssessmentSerializer, ComplianceControlSerializer


class ComplianceAssessmentViewSet(OrganizationScopedViewSet):
    serializer_class = ComplianceAssessmentSerializer
    http_method_names = ["get", "head", "options"]

    def get_queryset(self):
        return ComplianceAssessment.objects.filter(organization=self.get_organization()).prefetch_related(
            "results__control"
        )


class ComplianceControlViewSet(OrganizationScopedViewSet):
    serializer_class = ComplianceControlSerializer
    http_method_names = ["get", "head", "options"]

    def get_queryset(self):
        return ComplianceControl.objects.filter(enabled=True)
