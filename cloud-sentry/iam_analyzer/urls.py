from django.urls import path

from . import views

app_name = "iam_analyzer"

urlpatterns = [
    path("", views.IAMAnalysisListView.as_view(), name="list"),
    path("analyze/", views.AnalyzeIAMView.as_view(), name="analyze"),
    path("<int:pk>/", views.IAMAnalysisDetailView.as_view(), name="detail"),
]
