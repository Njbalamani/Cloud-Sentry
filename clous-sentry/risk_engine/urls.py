from django.urls import path

from . import views

app_name = "risk_engine"

urlpatterns = [
    path("", views.RiskAssessmentListView.as_view(), name="list"),
    path("<int:pk>/", views.RiskAssessmentDetailView.as_view(), name="detail"),
]
