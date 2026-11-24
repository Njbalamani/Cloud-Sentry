from .controls import ensure_controls
from .models import ComplianceAssessment, ControlResult


class ComplianceService:
    @staticmethod
    def evaluate_scan_run(scan_run):
        controls = ensure_controls()
        findings = list(scan_run.findings.select_related("rule"))
        assessment = ComplianceAssessment.objects.create(
            organization=scan_run.organization,
            scan_run=scan_run,
            score=0,
            passed=0,
            failed=0,
            total=0,
            summary={"framework": "CIS AWS Foundations Benchmark v2.0"},
        )
        passed = 0
        failed = 0
        failed_controls = []
        for control in controls:
            relevant = [
                finding
                for finding in findings
                if finding.rule and finding.rule.rule_id in (control.rule_ids or [])
            ]
            if not control.rule_ids:
                ControlResult.objects.create(
                    assessment=assessment,
                    control=control,
                    status=ControlResult.Status.NOT_APPLICABLE,
                    evidence={"reason": "No rule mapping configured."},
                )
                continue
            if relevant:
                failed += 1
                failed_controls.append(control.control_id)
                status = ControlResult.Status.FAILED
                evidence = {
                    "findings": [
                        {"id": finding.id, "title": finding.title, "severity": finding.severity}
                        for finding in relevant[:10]
                    ],
                    "finding_count": len(relevant),
                }
            else:
                passed += 1
                status = ControlResult.Status.PASSED
                evidence = {"checked_rules": control.rule_ids}
            ControlResult.objects.create(
                assessment=assessment,
                control=control,
                status=status,
                evidence=evidence,
            )
        total = passed + failed
        assessment.passed = passed
        assessment.failed = failed
        assessment.total = total
        assessment.score = round((passed / total) * 100, 1) if total else 0
        assessment.summary = {
            "framework": "CIS AWS Foundations Benchmark v2.0",
            "failed_controls": failed_controls,
            "findings_evaluated": len(findings),
        }
        assessment.save(update_fields=["passed", "failed", "total", "score", "summary"])
        return assessment

    @staticmethod
    def latest_assessment(organization):
        return ComplianceAssessment.objects.filter(organization=organization).select_related("scan_run").first()
