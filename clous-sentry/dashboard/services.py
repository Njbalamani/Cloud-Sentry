from datetime import timedelta

from django.db.models import Count
from django.db.models.functions import TruncDate
from django.utils import timezone

from cloud_accounts.models import CloudAccount, CloudResource
from cloud_scanner.models import Finding, ScanRun
from compliance.service import ComplianceService


def severity_counts(findings):
    counts = {choice: findings.filter(severity=choice).count() for choice, _ in Finding.Severity.choices}
    return counts


def resource_type_breakdown(resources):
    rows = resources.values("resource_type").annotate(total=Count("id")).order_by("-total")
    return [{"type": row["resource_type"], "total": row["total"]} for row in rows]


def finding_trend(findings):
    start = timezone.now().date() - timedelta(days=6)
    queryset = (
        findings.filter(created_at__date__gte=start)
        .annotate(day=TruncDate("created_at"))
        .values("day")
        .annotate(total=Count("id"))
        .order_by("day")
    )
    values = {row["day"]: row["total"] for row in queryset}
    result = []
    for offset in range(7):
        day = start + timedelta(days=offset)
        result.append({"date": day.isoformat(), "total": values.get(day, 0)})
    return result


def get_metrics(organization):
    cloud_accounts = CloudAccount.objects.filter(organization=organization)
    resources = CloudResource.objects.filter(cloud_account__organization=organization)
    findings = Finding.objects.filter(cloud_account__organization=organization)
    open_findings = findings.filter(status=Finding.Status.OPEN)
    scans = ScanRun.objects.filter(organization=organization)
    assessment = ComplianceService.latest_assessment(organization)
    high_risk_resources = resources.filter(risk_level__in=[CloudResource.RiskLevel.HIGH, CloudResource.RiskLevel.CRITICAL])
    recent_scans = [
        {
            "id": scan.id,
            "status": scan.status,
            "scan_mode": scan.scan_mode,
            "findings_count": scan.findings_count,
            "started_at": scan.started_at.isoformat(),
        }
        for scan in scans.order_by("-started_at")[:6]
    ]
    top_findings = [
        {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity,
            "risk_score": finding.risk_score,
            "is_demo": finding.is_demo,
            "resource_name": finding.resource_name,
        }
        for finding in open_findings.order_by("-risk_score", "-created_at")[:6]
    ]
    return {
        "generated_at": timezone.now().isoformat(),
        "organization": {"id": organization.id, "name": organization.name, "slug": organization.slug},
        "total_cloud_accounts": cloud_accounts.count(),
        "total_resources": resources.count(),
        "critical_misconfigurations": open_findings.filter(severity=Finding.Severity.CRITICAL).count(),
        "high_risk_resources": high_risk_resources.count(),
        "compliance_score": assessment.score if assessment else None,
        "open_findings": open_findings.count(),
        "total_findings": findings.count(),
        "total_scans": scans.count(),
        "completed_scans": scans.filter(status=ScanRun.Status.COMPLETED).count(),
        "demo_resources": resources.filter(is_demo=True).count(),
        "demo_findings": findings.filter(is_demo=True).count(),
        "severity_counts": severity_counts(findings),
        "resource_types": resource_type_breakdown(resources),
        "trend": finding_trend(findings),
        "recent_scans": recent_scans,
        "top_findings": top_findings,
    }


def get_topology(organization, limit=40):
    resources = (
        CloudResource.objects.filter(cloud_account__organization=organization)
        .select_related("cloud_account")
        .order_by("-last_seen_at")[:limit]
    )
    finding_counts = {
        row["resource_id"]: row["total"]
        for row in Finding.objects.filter(
            cloud_account__organization=organization,
            resource__isnull=False,
        )
        .values("resource_id")
        .annotate(total=Count("id"))
    }
    nodes = []
    links = []
    account_ids = set()
    for resource in resources:
        account_key = f"account-{resource.cloud_account_id}"
        if account_key not in account_ids:
            account_ids.add(account_key)
            nodes.append(
                {
                    "id": account_key,
                    "label": resource.cloud_account.name,
                    "type": "cloud_account",
                    "risk": "account",
                    "demo": False,
                    "finding_count": 0,
                }
            )
        nodes.append(
            {
                "id": f"resource-{resource.id}",
                "label": resource.name or resource.resource_id,
                "type": resource.resource_type,
                "risk": resource.risk_level,
                "demo": resource.is_demo,
                "finding_count": finding_counts.get(resource.id, 0),
            }
        )
        links.append({"source": account_key, "target": f"resource-{resource.id}", "demo": resource.is_demo})
    return {"nodes": nodes, "links": links}
