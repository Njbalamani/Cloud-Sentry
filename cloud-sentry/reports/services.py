import csv
import uuid
from io import BytesIO, StringIO
from xml.sax.saxutils import escape

from django.conf import settings
from django.core.files.base import ContentFile
from django.utils import timezone
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from cloud_accounts.models import CloudAccount, CloudResource
from cloud_scanner.models import Finding, ScanRun
from compliance.models import ComplianceAssessment
from iam_analyzer.models import IAMAnalysis

from .models import Report

NAVY = colors.HexColor("#07101f")
GOLD = colors.HexColor("#d8b46a")
LIGHT = colors.HexColor("#dce7f7")


def text(value, limit=180):
    value = "" if value is None else str(value)
    if len(value) > limit:
        return value[: limit - 1] + "…"
    return value


class ReportService:
    @staticmethod
    def build_context(organization, report_type, scan_run=None, include_demo=False):
        scans = ScanRun.objects.filter(organization=organization)
        findings = Finding.objects.filter(cloud_account__organization=organization).select_related(
            "cloud_account",
            "resource",
            "rule",
        )
        if scan_run:
            scans = scans.filter(id=scan_run.id)
            findings = findings.filter(scan_run=scan_run)
        if not include_demo:
            scans = scans.filter(scan_mode__in=[ScanRun.Mode.LIVE, ScanRun.Mode.PROWLER])
            findings = findings.filter(is_demo=False)
        resources = CloudResource.objects.filter(cloud_account__organization=organization)
        if not include_demo:
            resources = resources.filter(is_demo=False)
        assessments = ComplianceAssessment.objects.filter(organization=organization)
        if scan_run:
            assessments = assessments.filter(scan_run=scan_run)
        latest_assessment = assessments.first()
        severity_counts = {choice: findings.filter(severity=choice).count() for choice, _ in Finding.Severity.choices}
        return {
            "organization": organization,
            "generated_at": timezone.now(),
            "report_type": report_type,
            "include_demo": include_demo,
            "scan_run": scan_run,
            "summary": {
                "cloud_accounts": CloudAccount.objects.filter(organization=organization).count(),
                "resources": resources.count(),
                "scans": scans.count(),
                "findings": findings.count(),
                "critical_findings": severity_counts["critical"],
                "high_findings": severity_counts["high"],
                "compliance_score": latest_assessment.score if latest_assessment else None,
            },
            "findings": findings,
            "scans": scans,
            "assessment": latest_assessment,
            "iam_analyses": IAMAnalysis.objects.filter(cloud_account__organization=organization, is_demo=include_demo),
        }

    @staticmethod
    def rows_for_context(context):
        report_type = context["report_type"]
        if report_type == Report.ReportType.COMPLIANCE:
            assessment = context["assessment"]
            if not assessment:
                return ["Framework", "Control", "Title", "Status"], []
            rows = [
                [result.control.framework, result.control.control_id, result.control.title, result.get_status_display()]
                for result in assessment.results.select_related("control")
            ]
            return ["Framework", "Control", "Title", "Status"], rows
        if report_type == Report.ReportType.IAM_RISK:
            rows = [
                [item.policy_name, item.principal_arn, item.risk_score, len(item.findings), "Yes" if item.is_demo else "No"]
                for item in context["iam_analyses"]
            ]
            return ["Policy", "Principal", "Risk score", "Findings", "Synthetic"], rows
        rows = [
            [
                finding.id,
                finding.title,
                finding.get_severity_display(),
                finding.get_status_display(),
                finding.resource_name,
                finding.risk_score,
                "Yes" if finding.is_demo else "No",
            ]
            for finding in context["findings"]
        ]
        return ["ID", "Finding", "Severity", "Status", "Resource", "Risk score", "Synthetic"], rows

    @staticmethod
    def build_csv(context):
        header, rows = ReportService.rows_for_context(context)
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(header)
        writer.writerows(rows)
        return output.getvalue().encode("utf-8-sig")

    @staticmethod
    def build_pdf(context):
        header, rows = ReportService.rows_for_context(context)
        output = BytesIO()
        document = SimpleDocTemplate(
            output,
            pagesize=A4,
            rightMargin=16 * mm,
            leftMargin=16 * mm,
            topMargin=18 * mm,
            bottomMargin=18 * mm,
            title=f"CloudSentry {context['report_type']} report",
        )
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            "CloudSentryTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=22,
            textColor=NAVY,
            spaceAfter=8,
        )
        heading_style = ParagraphStyle(
            "CloudSentryHeading",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=colors.HexColor("#9a7229"),
            spaceBefore=10,
            spaceAfter=5,
        )
        body_style = ParagraphStyle(
            "CloudSentryBody",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=9,
            leading=13,
            alignment=TA_LEFT,
        )
        cell_style = ParagraphStyle(
            "CloudSentryCell",
            parent=body_style,
            fontSize=7,
            leading=9,
        )
        story = [
            Paragraph("CLOUDSENTRY SECURITY REPORT", title_style),
            Paragraph(
                f"Organization: {escape(text(context['organization'].name, 120))}<br/>"
                f"Report type: {escape(context['report_type'])}<br/>"
                f"Generated: {context['generated_at'].strftime('%Y-%m-%d %H:%M UTC')}<br/>"
                f"Data classification: {'Synthetic demo data included' if context['include_demo'] else 'Assessment data'}",
                body_style,
            ),
            Spacer(1, 8 * mm),
            Paragraph("EXECUTIVE SUMMARY", heading_style),
        ]
        summary = context["summary"]
        summary_rows = [
            ["Cloud accounts", summary["cloud_accounts"]],
            ["Resources", summary["resources"]],
            ["Assessments", summary["scans"]],
            ["Findings", summary["findings"]],
            ["Critical findings", summary["critical_findings"]],
            ["High findings", summary["high_findings"]],
            ["Compliance score", "Not assessed" if summary["compliance_score"] is None else f"{summary['compliance_score']}%"],
        ]
        summary_table = Table(summary_rows, colWidths=[60 * mm, 105 * mm])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#eef2f8")),
                    ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.4, LIGHT),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ]
            )
        )
        story.extend([summary_table, Spacer(1, 8 * mm), Paragraph("DETAILED RESULTS", heading_style)])
        if not rows:
            story.append(Paragraph("No records matched the selected report parameters.", body_style))
        else:
            table_rows = [[Paragraph(escape(str(item)), cell_style) for item in row] for row in [header] + rows]
            column_width = (165 * mm) / len(header)
            table = Table(table_rows, colWidths=[column_width] * len(header), repeatRows=1)
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
                        ("TEXTCOLOR", (0, 0), (-1, 0), GOLD),
                        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                        ("FONTSIZE", (0, 0), (-1, 0), 8),
                        ("GRID", (0, 0), (-1, -1), 0.35, LIGHT),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7f9fc")]),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 3),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                    ]
                )
            )
            story.append(table)
        story.append(Spacer(1, 8 * mm))
        story.append(
            Paragraph(
                "CloudSentry reports reflect the selected assessment scope. Synthetic rows are labelled when included.",
                body_style,
            )
        )
        document.build(story)
        return output.getvalue()

    @staticmethod
    def generate(organization, created_by, report_type, file_format, scan_run=None, include_demo=False):
        if report_type not in dict(Report.ReportType.choices):
            raise ValueError("Unsupported report type.")
        if file_format not in dict(Report.FileFormat.choices):
            raise ValueError("Unsupported report format.")
        settings.REPORTS_ROOT.mkdir(parents=True, exist_ok=True)
        context = ReportService.build_context(organization, report_type, scan_run, include_demo)
        if file_format == Report.FileFormat.CSV:
            payload = ReportService.build_csv(context)
        else:
            payload = ReportService.build_pdf(context)
        report = Report.objects.create(
            organization=organization,
            created_by=created_by,
            report_type=report_type,
            file_format=file_format,
            status="completed",
            parameters={
                "scan_run_id": scan_run.id if scan_run else None,
                "include_demo": include_demo,
            },
        )
        stamp = timezone.now().strftime("%Y%m%d%H%M%S")
        extension = "csv" if file_format == Report.FileFormat.CSV else "pdf"
        file_name = f"cloudsentry-{organization.slug}-{report_type}-{stamp}-{uuid.uuid4().hex[:6]}.{extension}"
        report.file.save(file_name, ContentFile(payload), save=False)
        report.save(update_fields=["file"])
        return report
