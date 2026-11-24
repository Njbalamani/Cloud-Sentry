from django.urls import path

from .api import CloudTopologyAPIView, DashboardMetricsAPIView

app_name = "dashboard_api"

urlpatterns = [
    path("metrics/", DashboardMetricsAPIView.as_view(), name="metrics"),
    path("topology/", CloudTopologyAPIView.as_view(), name="topology"),
]
