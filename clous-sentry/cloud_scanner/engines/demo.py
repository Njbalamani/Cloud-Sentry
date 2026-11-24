from cloud_accounts.models import CloudResource

from .base import BaseScanner, FindingDraft, ScanResult


class DemoScanner(BaseScanner):
    mode = "demo"

    def scan(self, cloud_account, rules):
        result = ScanResult()
        resources = CloudResource.objects.filter(cloud_account=cloud_account, is_demo=True)
        for resource in resources:
            result.resources.append(resource)
            metadata = resource.metadata or {}
            findings = self._findings_for_resource(resource, metadata)
            for finding in findings:
                if finding.rule_id not in rules:
                    continue
                finding.is_demo = True
                result.findings.append(finding)
        result.stats = {
            "synthetic_data": True,
            "read_only": True,
            "source": "CloudSentry synthetic demo dataset",
        }
        return result

    def _findings_for_resource(self, resource, metadata):
        drafts = []
        common = {
            "resource_id": resource.resource_id,
            "resource_type": resource.resource_type,
            "resource_name": resource.name,
            "region": resource.region,
        }
        if resource.resource_type == "s3_bucket":
            if metadata.get("public_access"):
                drafts.append(
                    FindingDraft(
                        rule_id="CS-AWS-S3-001",
                        title=f"Synthetic public access finding for {resource.name}",
                        description="Synthetic demonstration of an internet-accessible bucket.",
                        severity="critical",
                        evidence={"resource": resource.name, **metadata},
                        **common,
                    )
                )
            if not metadata.get("encrypted"):
                drafts.append(
                    FindingDraft(
                        rule_id="CS-AWS-S3-002",
                        title=f"Synthetic encryption finding for {resource.name}",
                        description="Synthetic demonstration of a bucket without default encryption.",
                        severity="high",
                        evidence={"resource": resource.name, **metadata},
                        **common,
                    )
                )
        elif resource.resource_type == "security_group":
            if metadata.get("broad_management_ingress"):
                drafts.append(
                    FindingDraft(
                        rule_id="CS-AWS-SG-001",
                        title=f"Synthetic exposed security group {resource.name}",
                        description="Synthetic demonstration of unrestricted SSH ingress.",
                        severity="critical",
                        evidence={"resource": resource.resource_id, **metadata},
                        **common,
                    )
                )
        elif resource.resource_type == "ebs_volume":
            if not metadata.get("encrypted"):
                drafts.append(
                    FindingDraft(
                        rule_id="CS-AWS-EC2-001",
                        title=f"Synthetic unencrypted volume {resource.name}",
                        description="Synthetic demonstration of an unencrypted EBS volume.",
                        severity="high",
                        evidence={"resource": resource.resource_id, **metadata},
                        **common,
                    )
                )
        elif resource.resource_type == "rds_instance":
            if metadata.get("publicly_accessible"):
                drafts.append(
                    FindingDraft(
                        rule_id="CS-AWS-RDS-001",
                        title=f"Synthetic public database {resource.name}",
                        description="Synthetic demonstration of a publicly accessible RDS instance.",
                        severity="critical",
                        evidence={"resource": resource.resource_id, **metadata},
                        **common,
                    )
                )
        elif resource.resource_type == "iam_policy":
            if metadata.get("wildcard_admin"):
                drafts.append(
                    FindingDraft(
                        rule_id="CS-AWS-IAM-001",
                        title=f"Synthetic wildcard IAM policy {resource.name}",
                        description="Synthetic demonstration of an administrative wildcard policy.",
                        severity="critical",
                        evidence={"resource": resource.resource_id, **metadata},
                        **common,
                    )
                )
        return drafts
