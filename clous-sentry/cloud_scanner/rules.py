from .models import ScanRule

BENCHMARK = "CIS AWS Foundations Benchmark v2.0"

RULE_DEFINITIONS = [
    {
        "rule_id": "CS-AWS-S3-001",
        "title": "S3 bucket allows public access",
        "description": "A bucket is publicly accessible through policy, ACL, or missing account-level and bucket-level public access blocks.",
        "service": "s3",
        "category": "Data exposure",
        "severity": ScanRule.Severity.CRITICAL,
        "cis_control": "2.1.5",
        "remediation": {
            "before": "PublicAccessBlockConfiguration: all false or absent; bucket policy permits Principal: *",
            "after": "BlockPublicAcls, IgnorePublicAcls, BlockPublicPolicy, RestrictPublicBuckets: true",
            "steps": [
                "Verify the bucket does not intentionally serve public content.",
                "Apply account-level and bucket-level S3 Block Public Access.",
                "Remove wildcard principals from the bucket policy and ACLs.",
            ],
            "approval_required": True,
        },
    },
    {
        "rule_id": "CS-AWS-S3-002",
        "title": "S3 bucket encryption at rest is not configured",
        "description": "The bucket has no default server-side encryption configuration.",
        "service": "s3",
        "category": "Encryption",
        "severity": ScanRule.Severity.HIGH,
        "cis_control": "2.1.1",
        "remediation": {
            "before": "ServerSideEncryptionConfiguration: absent",
            "after": "SSE-S3 AES256 or SSE-KMS with a managed customer key",
            "steps": ["Enable default encryption on the bucket.", "Apply encryption to existing objects."],
            "approval_required": True,
        },
    },
    {
        "rule_id": "CS-AWS-S3-003",
        "title": "S3 bucket versioning is disabled",
        "description": "Versioning is not enabled, reducing recovery options after destructive changes or ransomware events.",
        "service": "s3",
        "category": "Resilience",
        "severity": ScanRule.Severity.LOW,
        "cis_control": "",
        "remediation": {
            "before": "VersioningConfiguration.Status: Suspended",
            "after": "VersioningConfiguration.Status: Enabled",
            "steps": ["Enable bucket versioning.", "Add a lifecycle policy for noncurrent versions."],
            "approval_required": True,
        },
    },
    {
        "rule_id": "CS-AWS-SG-001",
        "title": "Security group exposes management ports to the internet",
        "description": "An inbound rule allows SSH or RDP from 0.0.0.0/0 or ::/0.",
        "service": "ec2",
        "category": "Network exposure",
        "severity": ScanRule.Severity.CRITICAL,
        "cis_control": "5.2",
        "remediation": {
            "before": "Ingress: tcp/22 or tcp/3389 from 0.0.0.0/0",
            "after": "Ingress limited to approved CIDR blocks or AWS Systems Manager Session Manager",
            "steps": ["Remove unrestricted management ingress.", "Restrict access to a bastion or approved CIDR."],
            "approval_required": True,
        },
    },
    {
        "rule_id": "CS-AWS-EC2-001",
        "title": "Unencrypted EBS volume detected",
        "description": "An Elastic Block Store volume is not encrypted at rest.",
        "service": "ec2",
        "category": "Encryption",
        "severity": ScanRule.Severity.HIGH,
        "cis_control": "2.2.1",
        "remediation": {
            "before": "Volume.Encrypted: false",
            "after": "Volume.Encrypted: true with a customer-managed KMS key",
            "steps": ["Create an encrypted snapshot.", "Restore an encrypted volume.", "Replace the original volume after approval."],
            "approval_required": True,
        },
    },
    {
        "rule_id": "CS-AWS-EC2-002",
        "title": "Public EC2 instance has broadly open ports",
        "description": "An instance with a public IP is attached to a security group allowing all traffic or management ports from the internet.",
        "service": "ec2",
        "category": "Network exposure",
        "severity": ScanRule.Severity.CRITICAL,
        "cis_control": "5.2",
        "remediation": {
            "before": "PublicIp present and inbound rule allows 0.0.0.0/0 on sensitive ports",
            "after": "Public exposure removed or restricted to approved ports and CIDRs",
            "steps": ["Confirm business need for public access.", "Restrict inbound rules.", "Place the instance behind a load balancer."],
            "approval_required": True,
        },
    },
    {
        "rule_id": "CS-AWS-RDS-001",
        "title": "RDS instance is publicly accessible",
        "description": "A database instance has a publicly reachable endpoint.",
        "service": "rds",
        "category": "Data exposure",
        "severity": ScanRule.Severity.CRITICAL,
        "cis_control": "2.3.1",
        "remediation": {
            "before": "DBInstance.PubliclyAccessible: true",
            "after": "DBInstance.PubliclyAccessible: false in private subnets",
            "steps": ["Confirm application connectivity path.", "Disable public accessibility.", "Review security group ingress."],
            "approval_required": True,
        },
    },
    {
        "rule_id": "CS-AWS-RDS-002",
        "title": "RDS storage encryption is disabled",
        "description": "A database instance does not have storage encryption enabled.",
        "service": "rds",
        "category": "Encryption",
        "severity": ScanRule.Severity.HIGH,
        "cis_control": "2.3.2",
        "remediation": {
            "before": "DBInstance.StorageEncrypted: false",
            "after": "DBInstance.StorageEncrypted: true",
            "steps": ["Create an encrypted snapshot.", "Restore a new encrypted instance.", "Migrate after approval."],
            "approval_required": True,
        },
    },
    {
        "rule_id": "CS-AWS-IAM-001",
        "title": "IAM policy grants wildcard administrative permissions",
        "description": "An attached policy allows all actions on all resources, violating least privilege.",
        "service": "iam",
        "category": "Identity and access",
        "severity": ScanRule.Severity.CRITICAL,
        "cis_control": "1.1",
        "remediation": {
            "before": '{"Effect":"Allow","Action":"*","Resource":"*"}',
            "after": '{"Effect":"Allow","Action":["s3:GetObject"],"Resource":"arn:aws:s3:::approved-bucket/*"}',
            "steps": ["Review access analytics.", "Replace wildcard actions with required actions.", "Scope resources and add conditions."],
            "approval_required": True,
        },
    },
    {
        "rule_id": "CS-AWS-IAM-002",
        "title": "IAM role trust policy allows any principal",
        "description": "A trust policy permits Principal: * to assume the role.",
        "service": "iam",
        "category": "Identity and access",
        "severity": ScanRule.Severity.CRITICAL,
        "cis_control": "1.2",
        "remediation": {
            "before": '{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}',
            "after": '{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::APPROVED:root"},"Condition":{"StringEquals":{"sts:ExternalId":"..."}}}',
            "steps": ["Identify approved trusted principals.", "Add an ExternalId condition.", "Remove wildcard principals."],
            "approval_required": True,
        },
    },
    {
        "rule_id": "CS-AWS-IAM-003",
        "title": "IAM policy uses broad service wildcards",
        "description": "A policy grants service-wide wildcard actions without resource scoping or conditions.",
        "service": "iam",
        "category": "Identity and access",
        "severity": ScanRule.Severity.HIGH,
        "cis_control": "1.3",
        "remediation": {
            "before": '{"Effect":"Allow","Action":"iam:*","Resource":"*"}',
            "after": '{"Effect":"Allow","Action":["iam:ListUsers","iam:GetUser"],"Resource":"*"}',
            "steps": ["Replace service wildcards with explicit actions.", "Apply resource constraints where supported."],
            "approval_required": True,
        },
    },
]


def ensure_rules():
    rules = {}
    for definition in RULE_DEFINITIONS:
        rule, _ = ScanRule.objects.get_or_create(
            rule_id=definition["rule_id"],
            defaults={
                "title": definition["title"],
                "description": definition["description"],
                "provider": "aws",
                "service": definition["service"],
                "category": definition["category"],
                "severity": definition["severity"],
                "cis_control": definition["cis_control"],
                "benchmark": BENCHMARK,
                "remediation": definition["remediation"],
                "enabled": True,
            },
        )
        rules[rule.rule_id] = rule
    return rules


def get_rule_map():
    return {rule.rule_id: rule for rule in ScanRule.objects.filter(enabled=True)}
