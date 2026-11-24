from django.utils import timezone

from .analyzer import analyze_policy_document, least_privilege_summary
from .models import IAMAnalysis


def _risk_score(findings):
    return max([finding.get("risk_hint", 0) for finding in findings], default=0)


def _store_analysis(cloud_account, principal_arn, policy_name, document, scan_run=None, analyzed_by=None):
    findings = analyze_policy_document(document, principal=principal_arn)
    analysis = IAMAnalysis.objects.create(
        cloud_account=cloud_account,
        scan_run=scan_run,
        principal_arn=principal_arn,
        policy_name=policy_name,
        policy_document=document,
        findings=findings,
        recommendations=least_privilege_summary(findings),
        risk_score=_risk_score(findings),
        is_demo=bool(scan_run and scan_run.is_demo),
        analyzed_by=analyzed_by or (scan_run.initiated_by if scan_run else None),
    )
    return analysis


def _create_findings(analysis, scan_run):
    if scan_run is None or not analysis.findings:
        return []
    from cloud_accounts.models import CloudResource
    from cloud_scanner.models import Finding
    from cloud_scanner.rules import get_rule_map

    rules = get_rule_map()
    created = []
    resource = CloudResource.objects.filter(
        cloud_account=analysis.cloud_account,
        resource_id=analysis.principal_arn,
    ).first()
    for item in analysis.findings:
        rule = rules.get(item.get("rule_id"))
        if rule is None:
            continue
        created.append(
            Finding.objects.create(
                scan_run=scan_run,
                cloud_account=analysis.cloud_account,
                resource=resource,
                rule=rule,
                title=item["title"],
                description=item.get("description", ""),
                severity=item.get("severity", "high"),
                evidence=item.get("evidence", {}),
                remediation=item.get("recommendation", {}),
                is_demo=analysis.is_demo,
            )
        )
    return created


def analyze_cloud_account(cloud_account, scan_run=None, user=None):
    session = cloud_account.get_boto3_session()
    iam = session.client("iam")
    analyses = []
    for policy in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for item in policy.get("Policies", []):
            try:
                version = iam.get_policy_version(
                    PolicyArn=item["Arn"],
                    VersionId=item["DefaultVersionId"],
                )
                document = version["PolicyVersion"]["Document"]
            except Exception:
                continue
            analysis = _store_analysis(
                cloud_account=cloud_account,
                principal_arn=item["Arn"],
                policy_name=item.get("PolicyName", item["Arn"]),
                document=document,
                scan_run=scan_run,
                analyzed_by=user,
            )
            analyses.append(analysis)
            for finding in _create_findings(analysis, scan_run):
                try:
                    from risk_engine.engine import RiskEngine

                    RiskEngine().score_finding(finding)
                except Exception:
                    pass
    for role_page in iam.get_paginator("list_roles").paginate():
        for role in role_page.get("Roles", []):
            document = role.get("AssumeRolePolicyDocument")
            if not document:
                continue
            analysis = _store_analysis(
                cloud_account=cloud_account,
                principal_arn=role["Arn"],
                policy_name=f"Trust::{role['RoleName']}",
                document=document,
                scan_run=scan_run,
                analyzed_by=user,
            )
            analyses.append(analysis)
            for finding in _create_findings(analysis, scan_run):
                try:
                    from risk_engine.engine import RiskEngine

                    RiskEngine().score_finding(finding)
                except Exception:
                    pass
    cloud_account.last_checked_at = timezone.now()
    cloud_account.save(update_fields=["last_checked_at", "updated_at"])
    return analyses
