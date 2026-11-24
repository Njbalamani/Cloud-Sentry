from django.conf import settings
from django.db import transaction
from django.utils import timezone

from .engines.aws import AWSScanner
from .engines.demo import DemoScanner
from .engines.prowler import ProwlerScanner
from .models import Finding, RemediationReview, ScanRun
from .rules import ensure_rules


class ScannerError(Exception):
    pass


def create_scan_run(cloud_account, initiated_by, mode=ScanRun.Mode.LIVE):
    if mode == ScanRun.Mode.DEMO and not settings.CLOUDSENTRY["DEMO_MODE"]:
        raise ScannerError("Demo scanning is disabled for this deployment.")
    if not cloud_account.scan_enabled:
        raise ScannerError("Scanning is disabled for this cloud account.")
    return ScanRun.objects.create(
        organization=cloud_account.organization,
        cloud_account=cloud_account,
        initiated_by=initiated_by,
        scan_mode=mode,
        status=ScanRun.Status.PENDING,
    )


def get_engine(mode):
    if mode == ScanRun.Mode.LIVE:
        return AWSScanner()
    if mode == ScanRun.Mode.DEMO:
        return DemoScanner()
    if mode == ScanRun.Mode.PROWLER:
        return ProwlerScanner()
    raise ScannerError("Unsupported scan mode.")


def _resolve_resource(cloud_account, draft):
    if not draft.resource_id:
        return None
    return cloud_account.resources.filter(resource_id=draft.resource_id).first()


def _create_findings(scan_run, result, rules):
    created = []
    for draft in result.findings:
        rule = rules.get(draft.rule_id)
        if rule is None:
            continue
        severity = draft.severity if draft.severity in dict(Finding.Severity.choices) else Finding.Severity.MEDIUM
        finding = Finding.objects.create(
            scan_run=scan_run,
            cloud_account=scan_run.cloud_account,
            resource=_resolve_resource(scan_run.cloud_account, draft),
            rule=rule,
            title=draft.title,
            description=draft.description,
            severity=severity,
            evidence=draft.evidence or {},
            remediation=draft.remediation or rule.remediation or {},
            is_demo=draft.is_demo or scan_run.is_demo,
        )
        created.append(finding)
    return created


def _update_resource_risk(findings):
    from cloud_accounts.models import CloudResource

    severity_rank = {
        Finding.Severity.INFO: CloudResource.RiskLevel.LOW,
        Finding.Severity.LOW: CloudResource.RiskLevel.LOW,
        Finding.Severity.MEDIUM: CloudResource.RiskLevel.MEDIUM,
        Finding.Severity.HIGH: CloudResource.RiskLevel.HIGH,
        Finding.Severity.CRITICAL: CloudResource.RiskLevel.CRITICAL,
    }
    by_resource = {}
    for finding in findings:
        if not finding.resource_id:
            continue
        current = by_resource.get(finding.resource_id)
        rank = list(severity_rank.values()).index(severity_rank.get(finding.severity, CloudResource.RiskLevel.LOW))
        if current is None or rank > current[0]:
            by_resource[finding.resource_id] = (rank, severity_rank.get(finding.severity, CloudResource.RiskLevel.LOW))
    for resource_id, (_, level) in by_resource.items():
        CloudResource.objects.filter(id=resource_id).update(risk_level=level)


def _severity_counts(findings):
    counts = {severity: 0 for severity, _ in Finding.Severity.choices}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def run_scan(scan_run):
    rules = ensure_rules()
    engine = get_engine(scan_run.scan_mode)
    scan_run.status = ScanRun.Status.RUNNING
    scan_run.save(update_fields=["status", "updated_at"])
    try:
        result = engine.scan(scan_run.cloud_account, rules)
    except Exception as exc:
        scan_run.status = ScanRun.Status.FAILED
        scan_run.error_message = "The scan could not be completed. Check cloud account access and try again."
        scan_run.finished_at = timezone.now()
        scan_run.save(update_fields=["status", "error_message", "finished_at", "updated_at"])
        raise ScannerError(scan_run.error_message) from exc

    with transaction.atomic():
        findings = _create_findings(scan_run, result, rules)
        _update_resource_risk(findings)
        scan_run.resources_scanned = len(result.resources)
        scan_run.findings_count = len(findings)
        scan_run.summary = {
            "severity_counts": _severity_counts(findings),
            "errors": result.errors,
            "stats": result.stats,
            "synthetic_data": scan_run.is_demo,
        }
        scan_run.status = ScanRun.Status.COMPLETED
        scan_run.finished_at = timezone.now()
        scan_run.save(
            update_fields=[
                "resources_scanned",
                "findings_count",
                "summary",
                "status",
                "finished_at",
                "updated_at",
            ]
        )
        scan_run.cloud_account.last_checked_at = scan_run.finished_at
        scan_run.cloud_account.save(update_fields=["last_checked_at", "updated_at"])

    for finding in findings:
        try:
            from risk_engine.engine import RiskEngine

            RiskEngine().score_finding(finding)
        except Exception:
            pass

    try:
        from compliance.service import ComplianceService

        ComplianceService.evaluate_scan_run(scan_run)
    except Exception:
        pass

    return scan_run


def review_remediation(finding, reviewer, decision, notes=""):
    if decision not in dict(RemediationReview.Decision.choices):
        raise ScannerError("Unsupported remediation decision.")
    review = RemediationReview.objects.create(
        finding=finding,
        reviewer=reviewer,
        decision=decision,
        notes=notes,
        proposed_action=finding.remediation or {},
    )
    finding.status = Finding.Status.IN_REVIEW
    finding.save(update_fields=["status", "updated_at"])
    return review
