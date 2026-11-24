from django.urls import path

from . import views

app_name = "organizations"

urlpatterns = [
    path("", views.OrganizationListView.as_view(), name="list"),
    path("create/", views.OrganizationCreateView.as_view(), name="create"),
    path("activate/<int:organization_id>/", views.SetActiveOrganizationView.as_view(), name="activate"),
    path("<slug:slug>/", views.OrganizationDetailView.as_view(), name="detail"),
    path("<slug:slug>/members/", views.OrganizationMembersView.as_view(), name="members"),
    path("members/<int:membership_id>/remove/", views.MembershipRemoveView.as_view(), name="remove-member"),
]
