from django.urls import path

from . import views

app_name = "cloud_accounts"

urlpatterns = [
    path("", views.CloudAccountListView.as_view(), name="list"),
    path("connect/", views.CloudAccountCreateView.as_view(), name="connect"),
    path("<int:pk>/", views.CloudAccountDetailView.as_view(), name="detail"),
    path("<int:pk>/resources/", views.CloudAccountResourcesView.as_view(), name="resources"),
    path("<int:pk>/test/", views.TestConnectionView.as_view(), name="test"),
]
