from organizations.api import OrganizationScopedViewSet

from .models import RiskAssessment
from .serializers import RiskAssessmentSerializer


class RiskAssessmentViewSet(OrganizationScopedViewSet):
    serializer_class = RiskAssessmentSerializer
    http_method_names = ["get", "head", "options"]

    def get_queryset(self):
        return RiskAssessment.objects.filter(
            finding__cloud_account__organization=self.get_organization()
        ).select_related("finding", "finding__cloud_account")
