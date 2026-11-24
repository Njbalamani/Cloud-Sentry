from .models import ComplianceControl

FRAMEWORK = "CIS AWS Foundations Benchmark v2.0"

CONTROL_DEFINITIONS = [
    {
        "control_id": "2.1.5",
        "title": "Ensure S3 buckets block public access",
        "description": "S3 buckets must not be publicly accessible through policies, ACLs, or missing public access blocks.",
        "severity": "critical",
        "rule_ids": ["CS-AWS-S3-001"],
    },
    {
        "control_id": "2.1.1",
        "title": "Ensure S3 bucket encryption is configured",
        "description": "S3 buckets should use default server-side encryption.",
        "severity": "high",
        "rule_ids": ["CS-AWS-S3-002"],
    },
    {
        "control_id": "5.2",
        "title": "Restrict management ports from the internet",
        "description": "Security groups must not allow unrestricted internet access to SSH or RDP.",
        "severity": "critical",
        "rule_ids": ["CS-AWS-SG-001", "CS-AWS-EC2-002"],
    },
    {
        "control_id": "2.2.1",
        "title": "Ensure EBS volumes are encrypted",
        "description": "EBS volumes should be encrypted at rest.",
        "severity": "high",
        "rule_ids": ["CS-AWS-EC2-001"],
    },
    {
        "control_id": "2.3.1",
        "title": "Ensure RDS instances are not publicly accessible",
        "description": "Database instances should remain private to approved networks.",
        "severity": "critical",
        "rule_ids": ["CS-AWS-RDS-001"],
    },
    {
        "control_id": "2.3.2",
        "title": "Ensure RDS storage encryption is enabled",
        "description": "RDS instances should use storage encryption.",
        "severity": "high",
        "rule_ids": ["CS-AWS-RDS-002"],
    },
    {
        "control_id": "1.1",
        "title": "Avoid wildcard administrative IAM policies",
        "description": "Policies must not grant unrestricted administrative access.",
        "severity": "critical",
        "rule_ids": ["CS-AWS-IAM-001"],
    },
    {
        "control_id": "1.2",
        "title": "Restrict role trust principals",
        "description": "Trust policies must not allow public principals.",
        "severity": "critical",
        "rule_ids": ["CS-AWS-IAM-002"],
    },
    {
        "control_id": "1.3",
        "title": "Apply least privilege to IAM policies",
        "description": "Policies should avoid service-wide wildcards and unscoped privileged actions.",
        "severity": "high",
        "rule_ids": ["CS-AWS-IAM-003"],
    },
]


def ensure_controls():
    controls = []
    for definition in CONTROL_DEFINITIONS:
        control, _ = ComplianceControl.objects.get_or_create(
            framework=FRAMEWORK,
            control_id=definition["control_id"],
            defaults={
                "title": definition["title"],
                "description": definition["description"],
                "severity": definition["severity"],
                "rule_ids": definition["rule_ids"],
                "enabled": True,
            },
        )
        controls.append(control)
    return controls
