from django.urls import include, path
from django.views.generic import RedirectView
from drf_spectacular.views import SpectacularAPIView, SpectacularRedocView, SpectacularSwaggerView

from config.api import api_router
from dashboard.views import landing

urlpatterns = [
    path("admin/", RedirectView.as_view(pattern_name="dashboard:index", permanent=False)),
    path("api/schema/", SpectacularAPIView.as_view(), name="schema"),
    path("api/docs/", SpectacularSwaggerView.as_view(url_name="schema"), name="api-docs"),
    path("api/redoc/", SpectacularRedocView.as_view(url_name="schema"), name="api-redoc"),
    path("api/v1/", include(api_router.urls)),
    path("api/v1/dashboard/", include("dashboard.api_urls")),
    path("dashboard/", include("dashboard.urls")),
    path("accounts/", include("accounts.urls")),
    path("organizations/", include("organizations.urls")),
    path("cloud-accounts/", include("cloud_accounts.urls")),
    path("scans/", include("cloud_scanner.urls")),
    path("iam/", include("iam_analyzer.urls")),
    path("risk/", include("risk_engine.urls")),
    path("compliance/", include("compliance.urls")),
    path("reports/", include("reports.urls")),
    path("", landing, name="landing"),
]

handler403 = "config.error_views.permission_denied"
handler404 = "config.error_views.not_found"
handler500 = "config.error_views.server_error"
