import shutil
import tempfile
from pathlib import Path

from django.conf import settings
from django.test import TestCase, override_settings
from django.urls import reverse

from accounts.forms import RegistrationForm
from accounts.models import User
from cloud_accounts.models import CloudAccount, CloudResource
from cloud_scanner.models import Finding, ScanRun
from cloud_scanner.services import create_scan_run, run_scan
from organizations.models import OrganizationMembership
from organizations.services import create_organization_with_owner
from reports.models import Report
from reports.services import ReportService

PASSWORD = "CloudSentry!2026"


def make_owner(email, organization_name):
    user = User.objects.create_user(email=email, password=PASSWORD, full_name=organization_name)
    organization = create_organization_with_owner(organization_name, user)
    return user, organization


def make_account(organization, user, account_id="123456789012"):
    account = CloudAccount.objects.create(
        organization=organization,
        name=f"Assessment account {account_id}",
        account_identifier=account_id,
        region="us-east-1",
        credential_type=CloudAccount.CredentialType.ACCESS_KEY,
        created_by=user,
        scan_enabled=True,
    )
    account.set_credentials(
        {
            "access_key_id": "AKIAEXAMPLE",
            "secret_access_key": "secret-value-must-never-be-exposed",
        }
    )
    account.save()
    return account


class AuthenticationFlowTests(TestCase):
    def test_registration_form_creates_organization(self):
        form = RegistrationForm(
            data={
                "email": "new.owner@example.com",
                "full_name": "New Owner",
                "organization_name": "New Organization",
                "password1": PASSWORD,
                "password2": PASSWORD,
            }
        )
        self.assertTrue(form.is_valid(), form.errors)
        user = form.save()
        organization = create_organization_with_owner(
            name=form.cleaned_data["organization_name"],
            owner=user,
            slug_source=form.cleaned_data["organization_name"],
        )
        self.assertTrue(User.objects.filter(email="new.owner@example.com").exists())
        self.assertTrue(
            OrganizationMembership.objects.filter(
                user=user,
                organization=organization,
                role=OrganizationMembership.Role.OWNER,
            ).exists()
        )

    def test_registration_login_and_protected_pages(self):
        response = self.client.post(
            reverse("accounts:register"),
            {
                "email": "portal.owner@example.com",
                "full_name": "Portal Owner",
                "organization_name": "Portal Org",
                "password1": PASSWORD,
                "password2": PASSWORD,
            },
        )
        self.assertRedirects(response, reverse("dashboard:index"))
        self.assertEqual(self.client.get(reverse("dashboard:index")).status_code, 200)
        self.assertEqual(self.client.get(reverse("accounts:profile")).status_code, 200)

    def test_login_lockout_records_failures(self):
        user, _ = make_owner("lockout@example.com", "Lockout Org")
        for _ in range(5):
            self.client.post(
                reverse("accounts:login"),
                {"username": user.email, "password": "WrongPassword!2026"},
            )
        response = self.client.post(
            reverse("accounts:login"),
            {"username": user.email, "password": PASSWORD},
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Too many failed sign-in attempts")


class OrganizationIsolationTests(TestCase):
    def setUp(self):
        self.user, self.organization = make_owner("alpha.owner@example.com", "Alpha Org")
        self.client.force_login(self.user)
        self.account = make_account(self.organization, self.user)

    def test_other_organization_account_is_not_accessible(self):
        other_user, other_organization = make_owner("beta.owner@example.com", "Beta Org")
        other_account = make_account(other_organization, other_user, "222222222222")
        response = self.client.get(reverse("cloud_accounts:detail", args=[other_account.pk]))
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.client.get(reverse("cloud_accounts:list")).context["accounts"][0], self.account)

    def test_key_application_pages_render(self):
        pages = [
            reverse("dashboard:index"),
            reverse("organizations:list"),
            reverse("organizations:detail", args=[self.organization.slug]),
            reverse("organizations:members", args=[self.organization.slug]),
            reverse("cloud_accounts:list"),
            reverse("cloud_accounts:connect"),
            reverse("cloud_accounts:detail", args=[self.account.pk]),
            reverse("cloud_accounts:resources", args=[self.account.pk]),
            reverse("cloud_scanner:operations"),
            reverse("cloud_scanner:start"),
            reverse("cloud_scanner:scan-list"),
            reverse("cloud_scanner:finding-list"),
            reverse("iam_analyzer:list"),
            reverse("iam_analyzer:analyze"),
            reverse("risk_engine:list"),
            reverse("compliance:index"),
            reverse("reports:list"),
            reverse("reports:generate"),
        ]
        for url in pages:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)


class CloudAccountCredentialTests(TestCase):
    def test_credentials_are_encrypted_at_rest(self):
        user, organization = make_owner("crypto.owner@example.com", "Crypto Org")
        account = make_account(organization, user)
        self.assertNotIn("secret-value-must-never-be-exposed", account.encrypted_credentials)
        self.assertEqual(
            account.get_credentials()["secret_access_key"],
            "secret-value-must-never-be-exposed",
        )
        self.assertEqual(account.credential_version, 1)


class DemoScanFlowTests(TestCase):
    def setUp(self):
        self.user, self.organization = make_owner("scan.owner@example.com", "Scan Org")
        self.client.force_login(self.user)
        self.account = make_account(self.organization, self.user)
        CloudResource.objects.create(
            cloud_account=self.account,
            resource_id="s3://synthetic-public-bucket",
            resource_type="s3_bucket",
            name="synthetic-public-bucket",
            region="us-east-1",
            metadata={"public_access": True, "encrypted": False},
            is_demo=True,
        )
        self.scan = create_scan_run(self.account, self.user, ScanRun.Mode.DEMO)
        run_scan(self.scan)
        self.scan.refresh_from_db()

    def test_demo_scan_creates_labelled_findings(self):
        self.assertEqual(self.scan.status, ScanRun.Status.COMPLETED)
        self.assertGreater(self.scan.findings_count, 0)
        self.assertTrue(self.scan.summary["synthetic_data"])
        findings = Finding.objects.filter(scan_run=self.scan)
        self.assertTrue(findings.exists())
        self.assertTrue(all(finding.is_demo for finding in findings))

    def test_post_scan_pages_render(self):
        finding = Finding.objects.filter(scan_run=self.scan).first()
        pages = [
            reverse("cloud_scanner:scan-detail", args=[self.scan.pk]),
            reverse("cloud_scanner:finding-list"),
            reverse("cloud_scanner:finding-detail", args=[finding.pk]),
            reverse("dashboard:index"),
            reverse("dashboard_api:metrics"),
            reverse("dashboard_api:topology"),
        ]
        for url in pages:
            with self.subTest(url=url):
                self.assertEqual(self.client.get(url).status_code, 200)

    def test_dashboard_metrics_exclude_other_organizations(self):
        other_user, other_organization = make_owner("other.scan@example.com", "Other Scan Org")
        other_account = make_account(other_organization, other_user, "333333333333")
        CloudResource.objects.create(
            cloud_account=other_account,
            resource_id="s3://other-synthetic-bucket",
            resource_type="s3_bucket",
            name="other-synthetic-bucket",
            metadata={"public_access": True},
            is_demo=True,
        )
        response = self.client.get(reverse("dashboard_api:metrics"))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["total_cloud_accounts"], 1)
        self.assertEqual(response.json()["organization"]["id"], self.organization.id)


REPORT_TEMP_DIR = tempfile.mkdtemp(prefix="cloudsentry-tests-")


@override_settings(MEDIA_ROOT=REPORT_TEMP_DIR, REPORTS_ROOT=Path(REPORT_TEMP_DIR) / "reports")
class ReportFlowTests(TestCase):
    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(REPORT_TEMP_DIR, ignore_errors=True)
        super().tearDownClass()

    def setUp(self):
        self.user, self.organization = make_owner("report.owner@example.com", "Report Org")
        self.client.force_login(self.user)
        self.account = make_account(self.organization, self.user)
        self.scan = ScanRun.objects.create(
            organization=self.organization,
            cloud_account=self.account,
            initiated_by=self.user,
            status=ScanRun.Status.COMPLETED,
            scan_mode=ScanRun.Mode.DEMO,
            findings_count=0,
        )

    def test_generate_and_download_csv_report(self):
        response = self.client.post(
            reverse("reports:generate"),
            {
                "report_type": Report.ReportType.FINDINGS,
                "file_format": Report.FileFormat.CSV,
                "include_demo": "on",
                "scan_run": self.scan.pk,
            },
        )
        report = Report.objects.get(organization=self.organization)
        self.assertRedirects(response, reverse("reports:download", args=[report.pk]))
        download = self.client.get(reverse("reports:download", args=[report.pk]))
        self.assertEqual(download.status_code, 200)
        self.assertEqual(download["Content-Type"], "text/csv")
        self.assertTrue(download.streaming_content)

    def test_pdf_report_service_builds_document(self):
        report = ReportService.generate(
            organization=self.organization,
            created_by=self.user,
            report_type=Report.ReportType.SECURITY_ASSESSMENT,
            file_format=Report.FileFormat.PDF,
            include_demo=False,
        )
        self.assertTrue(report.file)
        self.assertEqual(report.file_format, Report.FileFormat.PDF)
        self.assertEqual(settings.REPORTS_ROOT, Path(REPORT_TEMP_DIR) / "reports")
