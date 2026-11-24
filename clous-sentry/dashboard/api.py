from drf_spectacular.utils import extend_schema
from rest_framework import serializers
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import IsOrganizationMember

from .services import get_metrics, get_topology


class DashboardMetricsAPIView(APIView):
    permission_classes = [IsAuthenticated, IsOrganizationMember]

    def get_organization(self):
        organization = getattr(self.request, "current_organization", None)
        if organization is None:
            from rest_framework.exceptions import PermissionDenied

            raise PermissionDenied("Select an active organization.")
        return organization

    @extend_schema(responses=serializers.DictField)
    def get(self, request):
        return Response(get_metrics(self.get_organization()))


class CloudTopologyAPIView(APIView):
    permission_classes = [IsAuthenticated, IsOrganizationMember]

    def get_organization(self):
        organization = getattr(self.request, "current_organization", None)
        if organization is None:
            from rest_framework.exceptions import PermissionDenied

            raise PermissionDenied("Select an active organization.")
        return organization

    @extend_schema(responses=serializers.DictField)
    def get(self, request):
        return Response(get_topology(self.get_organization()))
