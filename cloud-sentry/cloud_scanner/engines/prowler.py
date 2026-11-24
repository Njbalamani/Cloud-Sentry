import json
import os
import subprocess

from django.conf import settings

from cloud_accounts.services import assert_read_only, sanitize_aws_error

from .base import BaseScanner, FindingDraft, ScanResult


class ProwlerScanner(BaseScanner):
    mode = "prowler"

    def scan(self, cloud_account, rules):
        assert_read_only(cloud_account)
        result = ScanResult()
        binary = settings.CLOUDSENTRY.get("PROWLER_BIN", "")
        if not binary:
            result.errors.append(
                {
                    "service": "prowler",
                    "code": "ConfigurationError",
                    "message": "PROWLER_BIN is not configured.",
                }
            )
            return result
        credentials = cloud_account.get_credentials()
        env = os.environ.copy()
        env["AWS_ACCESS_KEY_ID"] = credentials.get("access_key_id", "")
        env["AWS_SECRET_ACCESS_KEY"] = credentials.get("secret_access_key", "")
        if credentials.get("session_token"):
            env["AWS_SESSION_TOKEN"] = credentials["session_token"]
        env["AWS_DEFAULT_REGION"] = cloud_account.region
        command = [
            binary,
            "aws",
            "--regions",
            cloud_account.region,
            "--output-format",
            "json",
            "--no-banner",
        ]
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=settings.CLOUDSENTRY["SCAN_TIMEOUT_SECONDS"],
                env=env,
                check=False,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            result.errors.append(
                {
                    "service": "prowler",
                    "code": "ProwlerExecutionError",
                    "message": sanitize_aws_error(exc)["message"],
                }
            )
            return result
        if completed.returncode not in {0, 2}:
            result.errors.append(
                {
                    "service": "prowler",
                    "code": "ProwlerExecutionError",
                    "message": "Prowler exited with a non-zero status.",
                }
            )
            return result
        try:
            payload = json.loads(completed.stdout)
        except (json.JSONDecodeError, TypeError):
            result.errors.append(
                {
                    "service": "prowler",
                    "code": "ProwlerOutputError",
                    "message": "Prowler output could not be parsed as JSON.",
                }
            )
            return result
        records = payload if isinstance(payload, list) else payload.get("findings", [])
        for record in records:
            if not isinstance(record, dict):
                continue
            check_id = record.get("CheckID") or record.get("check_id") or ""
            matched_rule = rules.get(check_id)
            if matched_rule is None:
                continue
            status = str(record.get("Status", "")).lower()
            if status in {"pass", "passed", "success"}:
                continue
            resource_id = record.get("ResourceId") or record.get("resource_id") or ""
            result.findings.append(
                FindingDraft(
                    rule_id=check_id,
                    title=record.get("CheckTitle") or matched_rule.title,
                    description=record.get("Description") or matched_rule.description,
                    severity=str(record.get("Severity", matched_rule.severity)).lower(),
                    evidence={
                        "resource": resource_id,
                        "status": status,
                        "check_id": check_id,
                    },
                    resource_id=resource_id,
                    resource_type="prowler_resource",
                    resource_name=record.get("ResourceName") or resource_id,
                    region=record.get("Region") or cloud_account.region,
                )
            )
        result.stats = {
            "source": "Prowler",
            "records_processed": len(records),
            "read_only": True,
        }
        return result
