from drf_spectacular.utils import extend_schema
from rest_framework import status
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts.permissions import IsOrganizationAdmin
from organizations.api import OrganizationScopedViewSet

from .models import Finding, RemediationReview, ScanRun
from .serializers import (
    FindingSerializer,
    RemediationReviewSerializer,
    ScanRunCreateSerializer,
    ScanRunSerializer,
)
from .services import ScannerError, run_scan


class ScanRunViewSet(OrganizationScopedViewSet):
    def get_serializer_class(self):
        if self.action == "create":
            return ScanRunCreateSerializer
        return ScanRunSerializer

    def get_permissions(self):
        if self.action in {"create", "run"}:
            self.permission_classes = [self.permission_classes[0], IsOrganizationAdmin]
        return super().get_permissions()

    def get_queryset(self):
        return ScanRun.objects.filter(organization=self.get_organization()).select_related("cloud_account")

    @extend_schema(request=None, responses=ScanRunSerializer)
    @action(detail=True, methods=["post"])
    def run(self, request, pk=None):
        scan_run = self.get_object()
        try:
            run_scan(scan_run)
        except ScannerError as exc:
            return Response({"error": {"message": str(exc)}}, status=status.HTTP_400_BAD_REQUEST)
        return Response(self.get_serializer(scan_run).data)

    @extend_schema(responses=FindingSerializer(many=True))
    @action(detail=True, methods=["get"])
    def findings(self, request, pk=None):
        scan_run = self.get_object()
        findings = scan_run.findings.select_related("resource", "rule")
        page = self.paginate_queryset(findings)
        if page is not None:
            return self.get_paginated_response(FindingSerializer(page, many=True).data)
        return Response(FindingSerializer(findings, many=True).data)


class FindingViewSet(OrganizationScopedViewSet):
    serializer_class = FindingSerializer
    http_method_names = ["get", "head", "options"]

    def get_queryset(self):
        queryset = Finding.objects.filter(cloud_account__organization=self.get_organization()).select_related(
            "cloud_account",
            "resource",
            "rule",
        )
        severity = self.request.query_params.get("severity")
        if severity:
            queryset = queryset.filter(severity=severity)
        finding_status = self.request.query_params.get("status")
        if finding_status:
            queryset = queryset.filter(status=finding_status)
        if self.request.query_params.get("include_remediated") != "true":
            queryset = queryset.exclude(status=Finding.Status.REMEDIATED)
        return queryset


class RemediationReviewViewSet(OrganizationScopedViewSet):
    serializer_class = RemediationReviewSerializer

    def get_permissions(self):
        if self.action in {"create", "update", "partial_update", "destroy"}:
            self.permission_classes = [self.permission_classes[0], IsOrganizationAdmin]
        return super().get_permissions()

    def get_queryset(self):
        return RemediationReview.objects.filter(
            finding__cloud_account__organization=self.get_organization()
        ).select_related("finding", "reviewer")
