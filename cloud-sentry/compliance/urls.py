from django.urls import path

from . import views

app_name = "compliance"

urlpatterns = [
    path("", views.ComplianceOverviewView.as_view(), name="index"),
    path("assessments/<int:pk>/", views.ComplianceAssessmentDetailView.as_view(), name="detail"),
]
