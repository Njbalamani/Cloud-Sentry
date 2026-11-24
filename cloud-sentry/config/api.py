from rest_framework.routers import DefaultRouter

from cloud_accounts.api import CloudAccountViewSet, CloudResourceViewSet
from cloud_scanner.api import FindingViewSet, RemediationReviewViewSet, ScanRunViewSet
from compliance.api import ComplianceAssessmentViewSet, ComplianceControlViewSet
from iam_analyzer.api import IAMAnalysisViewSet
from organizations.api import OrganizationMembershipViewSet, OrganizationViewSet
from reports.api import ReportViewSet
from risk_engine.api import RiskAssessmentViewSet

api_router = DefaultRouter()
api_router.register("organizations", OrganizationViewSet, basename="organization")
api_router.register("organization-members", OrganizationMembershipViewSet, basename="organization-member")
api_router.register("cloud-accounts", CloudAccountViewSet, basename="cloud-account")
api_router.register("cloud-resources", CloudResourceViewSet, basename="cloud-resource")
api_router.register("scan-runs", ScanRunViewSet, basename="scan-run")
api_router.register("findings", FindingViewSet, basename="finding")
api_router.register("remediation-reviews", RemediationReviewViewSet, basename="remediation-review")
api_router.register("iam-analyses", IAMAnalysisViewSet, basename="iam-analysis")
api_router.register("risk-assessments", RiskAssessmentViewSet, basename="risk-assessment")
api_router.register("compliance-assessments", ComplianceAssessmentViewSet, basename="compliance-assessment")
api_router.register("compliance-controls", ComplianceControlViewSet, basename="compliance-control")
api_router.register("reports", ReportViewSet, basename="report")
