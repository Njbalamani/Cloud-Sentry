from django.core.management.base import BaseCommand, CommandError

from cloud_accounts.models import CloudAccount
from cloud_accounts.services import upsert_resource
from cloud_scanner.rules import ensure_rules
from compliance.controls import ensure_controls
from iam_analyzer.analyzer import analyze_policy_document, least_privilege_summary
from iam_analyzer.models import IAMAnalysis
from organizations.models import Organization

DEMO_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
    ],
}


class Command(BaseCommand):
    help = "Seed clearly labelled synthetic demo data into an existing organization."

    def add_arguments(self, parser):
        parser.add_argument("--organization-slug", required=True)
        parser.add_argument("--account-name", default="Synthetic Demo AWS Account")

    def handle(self, *args, **options):
        organization = Organization.objects.filter(slug=options["organization_slug"]).first()
        if organization is None:
            raise CommandError("Organization not found. Create an organization before seeding demo data.")
        ensure_rules()
        ensure_controls()
        account, _ = CloudAccount.objects.get_or_create(
            organization=organization,
            provider=CloudAccount.Provider.AWS,
            account_identifier="000000000000",
            defaults={
                "name": options["account_name"],
                "region": "us-east-1",
                "credential_type": CloudAccount.CredentialType.ASSUME_ROLE,
                "is_read_only": True,
                "status": CloudAccount.Status.PENDING,
                "notes": "Synthetic demo environment. No live AWS credentials are configured.",
            },
        )
        definitions = [
            ("demo-s3-public", "s3_bucket", "demo-customer-records", {"public_access": True, "encrypted": False}),
            ("demo-sg-open-ssh", "security_group", "demo-admin-access", {"broad_management_ingress": True}),
            ("demo-ebs-unencrypted", "ebs_volume", "demo-data-volume", {"encrypted": False}),
            ("demo-rds-public", "rds_instance", "demo-customer-db", {"publicly_accessible": True}),
            ("demo-iam-admin", "iam_policy", "demo-admin-policy", {"wildcard_admin": True}),
        ]
        for resource_id, resource_type, name, metadata in definitions:
            upsert_resource(
                cloud_account=account,
                resource_id=resource_id,
                resource_type=resource_type,
                name=name,
                region="us-east-1",
                metadata=metadata,
                tags={"environment": "synthetic-demo"},
                is_demo=True,
            )
        findings = analyze_policy_document(DEMO_POLICY, principal="arn:aws:iam::000000000000:role/DemoAdminRole")
        IAMAnalysis.objects.update_or_create(
            cloud_account=account,
            principal_arn="arn:aws:iam::000000000000:role/DemoAdminRole",
            policy_name="demo-admin-policy",
            defaults={
                "policy_document": DEMO_POLICY,
                "findings": findings,
                "recommendations": least_privilege_summary(findings),
                "risk_score": max([item.get("risk_hint", 0) for item in findings], default=0),
                "is_demo": True,
            },
        )
        self.stdout.write(
            self.style.SUCCESS(
                f"Seeded {len(definitions)} synthetic resources and one IAM analysis into {organization.name}. "
                "All demo records are labelled is_demo and no live credentials were configured."
            )
        )
