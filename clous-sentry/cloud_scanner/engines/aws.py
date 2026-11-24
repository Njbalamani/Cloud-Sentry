from botocore.exceptions import BotoCoreError, ClientError
from django.conf import settings

from cloud_accounts.services import assert_read_only, sanitize_aws_error, upsert_resource

from .base import BaseScanner, FindingDraft, ScanResult

BROAD_CIDRS = {"0.0.0.0/0", "::/0"}
MANAGEMENT_PORTS = {22, 3389}


def error_code(exc):
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code", "ClientError")
    return "AssessmentError"


class AWSScanner(BaseScanner):
    mode = "live"

    def __init__(self, timeout=None):
        self.timeout = timeout or settings.CLOUDSENTRY["SCAN_TIMEOUT_SECONDS"]

    def scan(self, cloud_account, rules):
        assert_read_only(cloud_account)
        result = ScanResult()
        session = cloud_account.get_boto3_session()
        self._scan_s3(session, cloud_account, rules, result)
        exposed_group_ids = self._scan_security_groups(session, cloud_account, rules, result) or set()
        result.stats["exposed_group_ids"] = exposed_group_ids
        self._scan_ec2_instances(session, cloud_account, rules, result)
        self._scan_ebs_volumes(session, cloud_account, rules, result)
        self._scan_rds(session, cloud_account, rules, result)
        self._scan_iam(session, cloud_account, rules, result)
        result.stats = {
            "services": ["s3", "ec2", "rds", "iam"],
            "read_only": True,
            "timeout_seconds": self.timeout,
        }
        return result

    def _record_error(self, result, service, exc):
        detail = sanitize_aws_error(exc)
        result.errors.append({"service": service, "code": detail["code"], "message": detail["message"]})

    def _add_resource(self, result, cloud_account, resource_id, resource_type, name, region, metadata, tags=None):
        resource, _ = upsert_resource(
            cloud_account=cloud_account,
            resource_id=resource_id,
            resource_type=resource_type,
            name=name,
            region=region,
            metadata=metadata,
            tags=tags or {},
            is_demo=False,
        )
        result.resources.append(resource)
        return resource

    def _scan_s3(self, session, cloud_account, rules, result):
        try:
            client = session.client("s3")
            buckets = client.list_buckets().get("Buckets", [])
        except (ClientError, BotoCoreError) as exc:
            self._record_error(result, "s3", exc)
            return
        for bucket in buckets:
            name = bucket["Name"]
            try:
                location = client.get_bucket_location(Bucket=name).get("LocationConstraint") or "us-east-1"
            except (ClientError, BotoCoreError):
                location = cloud_account.region
            public_access = False
            public_evidence = {}
            try:
                status = client.get_bucket_policy_status(Bucket=name)
                public_access = bool(status.get("IsPublic", False))
                public_evidence["policy_is_public"] = public_access
            except ClientError as exc:
                if error_code(exc) not in {"NoSuchBucketPolicy", "AccessDenied", "NoSuchBucket"}:
                    self._record_error(result, "s3", exc)
            try:
                acl = client.get_bucket_acl(Bucket=name)
                all_users = [
                    grant
                    for grant in acl.get("Grants", [])
                    if grant.get("Grantee", {}).get("URI", "").endswith("/AllUsers")
                    and grant.get("Permission") in {"READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"}
                ]
                if all_users:
                    public_access = True
                    public_evidence["acl_all_users"] = True
            except ClientError as exc:
                if error_code(exc) not in {"AccessDenied", "NoSuchAcl", "NoSuchBucket"}:
                    self._record_error(result, "s3", exc)
            try:
                block = client.get_bucket_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {})
            except ClientError:
                block = {}
            public_evidence["public_access_block"] = block
            self._add_resource(
                result,
                cloud_account,
                name,
                "s3_bucket",
                name,
                location,
                {"public_access_block": block, "policy_is_public": public_access},
            )
            if public_access:
                result.findings.append(
                    FindingDraft(
                        rule_id="CS-AWS-S3-001",
                        title=f"Public access detected on S3 bucket {name}",
                        description="The bucket is public through its policy or ACL.",
                        severity="critical",
                        evidence={"resource": name, "region": location, **public_evidence},
                        resource_id=name,
                        resource_type="s3_bucket",
                        resource_name=name,
                        region=location,
                    )
                )
            try:
                encryption = client.get_bucket_encryption(Bucket=name)
                encryption_config = encryption.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            except ClientError as exc:
                encryption_config = []
                if error_code(exc) not in {"ServerSideEncryptionConfigurationNotFoundError", "AccessDenied"}:
                    self._record_error(result, "s3", exc)
            if not encryption_config:
                result.findings.append(
                    FindingDraft(
                        rule_id="CS-AWS-S3-002",
                        title=f"S3 bucket {name} has no default encryption",
                        description="No server-side encryption configuration was returned for the bucket.",
                        severity="high",
                        evidence={"resource": name, "region": location, "rules": encryption_config},
                        resource_id=name,
                        resource_type="s3_bucket",
                        resource_name=name,
                        region=location,
                    )
                )
            try:
                versioning = client.get_bucket_versioning(Bucket=name).get("Status", "Suspended")
            except ClientError:
                versioning = "Unknown"
            if versioning not in {"Enabled", "Unknown"}:
                result.findings.append(
                    FindingDraft(
                        rule_id="CS-AWS-S3-003",
                        title=f"Versioning is not enabled on S3 bucket {name}",
                        description="Bucket versioning is not enabled.",
                        severity="low",
                        evidence={"resource": name, "status": versioning},
                        resource_id=name,
                        resource_type="s3_bucket",
                        resource_name=name,
                        region=location,
                    )
                )

    def _scan_security_groups(self, session, cloud_account, rules, result):
        try:
            client = session.client("ec2")
            paginator = client.get_paginator("describe_security_groups")
            groups = []
            for page in paginator.paginate():
                groups.extend(page.get("SecurityGroups", []))
        except (ClientError, BotoCoreError) as exc:
            self._record_error(result, "ec2-security-groups", exc)
            return
        exposed_group_ids = set()
        for group in groups:
            group_id = group["GroupId"]
            name = group.get("GroupName", group_id)
            dangerous_rules = []
            for permission in group.get("IpPermissions", []):
                from_port = permission.get("FromPort")
                to_port = permission.get("ToPort")
                protocol = permission.get("IpProtocol", "-1")
                cidrs = [item["CidrIp"] for item in permission.get("IpRanges", []) if "CidrIp" in item]
                cidrs += [item["CidrIpv6"] for item in permission.get("Ipv6Ranges", []) if "CidrIpv6" in item]
                broad = [cidr for cidr in cidrs if cidr in BROAD_CIDRS]
                if not broad:
                    continue
                sensitive = protocol == "-1" or from_port is None
                if not sensitive and isinstance(from_port, int) and isinstance(to_port, int):
                    sensitive = any(from_port <= port <= to_port for port in MANAGEMENT_PORTS)
                if not sensitive:
                    continue
                exposed_group_ids.add(group_id)
                dangerous_rules.append(
                    {
                        "protocol": protocol,
                        "from_port": from_port,
                        "to_port": to_port,
                        "cidrs": broad,
                    }
                )
            self._add_resource(
                result,
                cloud_account,
                group_id,
                "security_group",
                name,
                cloud_account.region,
                {"dangerous_ingress": dangerous_rules},
            )
            if dangerous_rules:
                result.findings.append(
                    FindingDraft(
                        rule_id="CS-AWS-SG-001",
                        title=f"Security group {name} exposes management ports",
                        description="Unrestricted internet ingress was detected on a management port or all traffic.",
                        severity="critical",
                        evidence={"resource": group_id, "group": name, "rules": dangerous_rules},
                        resource_id=group_id,
                        resource_type="security_group",
                        resource_name=name,
                        region=cloud_account.region,
                    )
                )
        return exposed_group_ids

    def _scan_ec2_instances(self, session, cloud_account, rules, result):
        exposed_group_ids = result.stats.get("exposed_group_ids", set())
        try:
            client = session.client("ec2")
            paginator = client.get_paginator("describe_instances")
            instances = []
            for page in paginator.paginate():
                for reservation in page.get("Reservations", []):
                    instances.extend(reservation.get("Instances", []))
        except (ClientError, BotoCoreError) as exc:
            self._record_error(result, "ec2-instances", exc)
            return
        for instance in instances:
            instance_id = instance["InstanceId"]
            public_ip = instance.get("PublicIpAddress")
            group_ids = [item["GroupId"] for item in instance.get("SecurityGroups", []) if "GroupId" in item]
            name = instance_id
            for tag in instance.get("Tags", []):
                if tag.get("Key") == "Name":
                    name = tag.get("Value", instance_id)
            self._add_resource(
                result,
                cloud_account,
                instance_id,
                "ec2_instance",
                name,
                cloud_account.region,
                {
                    "public_ip_present": bool(public_ip),
                    "instance_type": instance.get("InstanceType"),
                    "state": instance.get("State", {}).get("Name"),
                    "security_group_ids": group_ids,
                },
            )
            if public_ip and any(group_id in exposed_group_ids for group_id in group_ids):
                result.findings.append(
                    FindingDraft(
                        rule_id="CS-AWS-EC2-002",
                        title=f"Public EC2 instance {name} has exposed management services",
                        description="A public instance is attached to a security group with unrestricted management ingress.",
                        severity="critical",
                        evidence={
                            "resource": instance_id,
                            "public_ip_configured": True,
                            "security_group_ids": group_ids,
                        },
                        resource_id=instance_id,
                        resource_type="ec2_instance",
                        resource_name=name,
                        region=cloud_account.region,
                    )
                )

    def _scan_ebs_volumes(self, session, cloud_account, rules, result):
        try:
            client = session.client("ec2")
            paginator = client.get_paginator("describe_volumes")
            volumes = []
            for page in paginator.paginate():
                volumes.extend(page.get("Volumes", []))
        except (ClientError, BotoCoreError) as exc:
            self._record_error(result, "ebs", exc)
            return
        for volume in volumes:
            volume_id = volume["VolumeId"]
            encrypted = bool(volume.get("Encrypted"))
            self._add_resource(
                result,
                cloud_account,
                volume_id,
                "ebs_volume",
                volume_id,
                volume.get("AvailabilityZone", cloud_account.region),
                {"encrypted": encrypted, "size_gib": volume.get("Size"), "state": volume.get("State")},
            )
            if not encrypted:
                result.findings.append(
                    FindingDraft(
                        rule_id="CS-AWS-EC2-001",
                        title=f"EBS volume {volume_id} is not encrypted",
                        description="The volume reports Encrypted=false.",
                        severity="high",
                        evidence={"resource": volume_id, "encrypted": encrypted, "size_gib": volume.get("Size")},
                        resource_id=volume_id,
                        resource_type="ebs_volume",
                        resource_name=volume_id,
                        region=cloud_account.region,
                    )
                )

    def _scan_rds(self, session, cloud_account, rules, result):
        try:
            client = session.client("rds")
            paginator = client.get_paginator("describe_db_instances")
            databases = []
            for page in paginator.paginate():
                databases.extend(page.get("DBInstances", []))
        except (ClientError, BotoCoreError) as exc:
            self._record_error(result, "rds", exc)
            return
        for database in databases:
            identifier = database["DBInstanceIdentifier"]
            publicly_accessible = bool(database.get("PubliclyAccessible"))
            encrypted = bool(database.get("StorageEncrypted"))
            self._add_resource(
                result,
                cloud_account,
                identifier,
                "rds_instance",
                identifier,
                database.get("AvailabilityZone", cloud_account.region),
                {
                    "publicly_accessible": publicly_accessible,
                    "storage_encrypted": encrypted,
                    "engine": database.get("Engine"),
                },
            )
            if publicly_accessible:
                result.findings.append(
                    FindingDraft(
                        rule_id="CS-AWS-RDS-001",
                        title=f"RDS instance {identifier} is publicly accessible",
                        description="The database endpoint is reachable from outside the VPC.",
                        severity="critical",
                        evidence={"resource": identifier, "publicly_accessible": True},
                        resource_id=identifier,
                        resource_type="rds_instance",
                        resource_name=identifier,
                        region=cloud_account.region,
                    )
                )
            if not encrypted:
                result.findings.append(
                    FindingDraft(
                        rule_id="CS-AWS-RDS-002",
                        title=f"RDS instance {identifier} storage is not encrypted",
                        description="The database instance reports StorageEncrypted=false.",
                        severity="high",
                        evidence={"resource": identifier, "storage_encrypted": False},
                        resource_id=identifier,
                        resource_type="rds_instance",
                        resource_name=identifier,
                        region=cloud_account.region,
                    )
                )

    def _scan_iam(self, session, cloud_account, rules, result):
        try:
            client = session.client("iam")
            paginator = client.get_paginator("list_policies")
            policies = []
            for page in paginator.paginate(Scope="Local"):
                policies.extend(page.get("Policies", []))
        except (ClientError, BotoCoreError) as exc:
            self._record_error(result, "iam", exc)
            return
        from iam_analyzer.analyzer import analyze_policy_document

        for policy in policies:
            arn = policy["Arn"]
            try:
                version = client.get_policy_version(
                    PolicyArn=arn,
                    VersionId=policy["DefaultVersionId"],
                )
                document = version["PolicyVersion"]["Document"]
            except (ClientError, BotoCoreError, KeyError) as exc:
                self._record_error(result, "iam", exc)
                continue
            self._add_resource(
                result,
                cloud_account,
                arn,
                "iam_policy",
                policy.get("PolicyName", arn),
                "global",
                {"scope": "Local", "default_version_id": policy.get("DefaultVersionId")},
            )
            for item in analyze_policy_document(document, principal=arn):
                if item.get("rule_id") not in rules:
                    continue
                result.findings.append(
                    FindingDraft(
                        rule_id=item["rule_id"],
                        title=item["title"],
                        description=item.get("description", ""),
                        severity=item.get("severity", "high"),
                        evidence={"resource": arn, **item.get("evidence", {})},
                        resource_id=arn,
                        resource_type="iam_policy",
                        resource_name=policy.get("PolicyName", arn),
                        region="global",
                        remediation=item.get("remediation", {}),
                    )
                )
