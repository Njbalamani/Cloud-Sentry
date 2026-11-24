from django.http import FileResponse
from drf_spectacular.utils import extend_schema
from rest_framework import serializers, status
from rest_framework.decorators import action
from rest_framework.response import Response

from accounts.permissions import IsOrganizationAdmin
from organizations.api import OrganizationScopedViewSet

from .models import Report
from .serializers import ReportSerializer
from .services import ReportService


class ReportGenerateSerializer(serializers.Serializer):
    report_type = serializers.ChoiceField(choices=Report.ReportType.choices)
    file_format = serializers.ChoiceField(choices=Report.FileFormat.choices)
    scan_run = serializers.IntegerField(required=False, allow_null=True)
    include_demo = serializers.BooleanField(default=False)


class ReportViewSet(OrganizationScopedViewSet):
    serializer_class = ReportSerializer

    def get_queryset(self):
        return Report.objects.filter(organization=self.get_organization()).select_related("created_by")

    def get_permissions(self):
        if self.action in {"generate", "destroy"}:
            self.permission_classes = [self.permission_classes[0], IsOrganizationAdmin]
        return super().get_permissions()

    @extend_schema(request=ReportGenerateSerializer, responses=ReportSerializer)
    @action(detail=False, methods=["post"])
    def generate(self, request):
        payload = ReportGenerateSerializer(data=request.data)
        payload.is_valid(raise_exception=True)
        scan_run = None
        scan_run_id = payload.validated_data.get("scan_run")
        if scan_run_id:
            from cloud_scanner.models import ScanRun

            scan_run = ScanRun.objects.filter(
                id=scan_run_id,
                organization=self.get_organization(),
            ).first()
            if scan_run is None:
                return Response(
                    {"error": {"message": "The selected assessment does not belong to this organization."}},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        report = ReportService.generate(
            organization=self.get_organization(),
            created_by=request.user,
            report_type=payload.validated_data["report_type"],
            file_format=payload.validated_data["file_format"],
            scan_run=scan_run,
            include_demo=payload.validated_data.get("include_demo", False),
        )
        return Response(self.get_serializer(report).data, status=status.HTTP_201_CREATED)

    @action(detail=True, methods=["get"])
    def download(self, request, pk=None):
        report = self.get_object()
        if not report.file:
            return Response({"error": {"message": "The report file is unavailable."}}, status=404)
        filename = report.file.name.rsplit("/", 1)[-1]
        response = FileResponse(report.file.open("rb"), as_attachment=True, filename=filename)
        return response
