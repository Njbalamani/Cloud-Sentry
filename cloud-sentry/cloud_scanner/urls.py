from django.urls import path

from . import views

app_name = "cloud_scanner"

urlpatterns = [
    path("", views.SecurityOperationsView.as_view(), name="operations"),
    path("start/", views.StartScanView.as_view(), name="start"),
    path("runs/", views.ScanRunListView.as_view(), name="scan-list"),
    path("runs/<int:pk>/", views.ScanRunDetailView.as_view(), name="scan-detail"),
    path("findings/", views.FindingListView.as_view(), name="finding-list"),
    path("findings/<int:pk>/", views.FindingDetailView.as_view(), name="finding-detail"),
]
