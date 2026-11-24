PRIVILEGED_PREFIXES = ("iam:", "s3:", "ec2:", "rds:", "kms:", "sts:", "organizations:")


def as_list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def statements(document):
    if not isinstance(document, dict):
        return []
    value = document.get("Statement", [])
    return [item for item in as_list(value) if isinstance(item, dict)]


def is_wildcard(value):
    values = [str(item).lower() for item in as_list(value)]
    return "*" in values


def has_service_wildcard(actions):
    return any(str(action).lower().endswith(":*") for action in as_list(actions))


def has_privileged_action(actions):
    for action in as_list(actions):
        lower = str(action).lower()
        if lower.startswith(PRIVILEGED_PREFIXES):
            return True
    return False


def principal_is_public(statement):
    principal = statement.get("Principal")
    if principal == "*" or is_wildcard(principal):
        return True
    if isinstance(principal, dict):
        for value in principal.values():
            if is_wildcard(value):
                return True
    return False


def build_finding(rule_id, title, description, severity, evidence, before, after, steps, risk_hint):
    return {
        "rule_id": rule_id,
        "title": title,
        "description": description,
        "severity": severity,
        "evidence": evidence,
        "risk_hint": risk_hint,
        "recommendation": {
            "before": before,
            "after": after,
            "steps": steps,
            "approval_required": True,
        },
    }


def analyze_policy_document(document, principal=""):
    findings = []
    for index, statement in enumerate(statements(document)):
        effect = str(statement.get("Effect", "")).lower()
        if effect != "allow":
            continue
        actions = as_list(statement.get("Action"))
        resources = as_list(statement.get("Resource"))
        evidence = {"statement_index": index, "actions": actions[:12], "resources": resources[:12]}
        if principal:
            evidence["principal"] = principal
        if is_wildcard(actions) and is_wildcard(resources):
            findings.append(
                build_finding(
                    rule_id="CS-AWS-IAM-001",
                    title="Policy grants unrestricted administrative access",
                    description="A single Allow statement uses Action '*' on Resource '*'.",
                    severity="critical",
                    evidence=evidence,
                    before={"Action": actions, "Resource": resources, "Effect": "Allow"},
                    after={"Action": ["explicit:RequiredAction"], "Resource": ["arn:aws:service:region:account:resource"]},
                    steps=[
                        "Review CloudTrail and IAM Access Analyzer data for actually used actions.",
                        "Replace wildcard actions with the minimum required action list.",
                        "Replace wildcard resources with specific ARNs.",
                        "Add conditions for source IP, MFA, or tags where supported.",
                    ],
                    risk_hint=95,
                )
            )
            continue
        assume_role_actions = [action for action in actions if str(action).lower() == "sts:assumerole"]
        if assume_role_actions and principal_is_public(statement):
            findings.append(
                build_finding(
                    rule_id="CS-AWS-IAM-002",
                    title="Role trust policy allows any principal",
                    description="The trust statement allows a public principal to assume the role.",
                    severity="critical",
                    evidence={**evidence, "principal_public": True},
                    before={"Principal": statement.get("Principal"), "Action": "sts:AssumeRole"},
                    after={"Principal": {"AWS": "arn:aws:iam::APPROVED_ACCOUNT:root"}, "Condition": {"StringEquals": {"sts:ExternalId": "APPROVED_EXTERNAL_ID"}}},
                    steps=[
                        "Identify the approved trusted account and principal.",
                        "Add an ExternalId condition.",
                        "Remove wildcard principals from the trust policy.",
                    ],
                    risk_hint=92,
                )
            )
            continue
        if has_service_wildcard(actions):
            findings.append(
                build_finding(
                    rule_id="CS-AWS-IAM-003",
                    title="Policy uses broad service wildcard actions",
                    description="A statement grants service-wide wildcard permissions without explicit action scoping.",
                    severity="high",
                    evidence=evidence,
                    before={"Action": actions, "Resource": resources, "Effect": "Allow"},
                    after={"Action": ["explicit:RequiredAction"], "Resource": resources or ["arn:aws:service:region:account:resource"]},
                    steps=[
                        "Replace service wildcards with explicit actions.",
                        "Scope resources to the specific ARNs required by the workload.",
                    ],
                    risk_hint=74,
                )
            )
            continue
        if is_wildcard(resources) and has_privileged_action(actions):
            findings.append(
                build_finding(
                    rule_id="CS-AWS-IAM-003",
                    title="Privileged actions are allowed on all resources",
                    description="Sensitive actions are allowed against Resource '*'.",
                    severity="high",
                    evidence=evidence,
                    before={"Action": actions, "Resource": "*", "Effect": "Allow"},
                    after={"Action": actions, "Resource": ["arn:aws:service:region:account:resource"]},
                    steps=["Scope each sensitive action to approved resource ARNs.", "Apply conditions where the service supports them."],
                    risk_hint=70,
                )
            )
            continue
        if "NotAction" in statement or "NotResource" in statement:
            findings.append(
                build_finding(
                    rule_id="CS-AWS-IAM-003",
                    title="Policy uses negative access controls",
                    description="Allow statements with NotAction or NotResource can grant broader access than intended.",
                    severity="high",
                    evidence={
                        **evidence,
                        "not_action": as_list(statement.get("NotAction"))[:12],
                        "not_resource": as_list(statement.get("NotResource"))[:12],
                    },
                    before={"NotAction": statement.get("NotAction"), "NotResource": statement.get("NotResource")},
                    after={"Action": ["explicit:RequiredAction"], "Resource": ["approved:resource:arn"]},
                    steps=["Rewrite the statement with explicit Action and Resource values."],
                    risk_hint=68,
                )
            )
    return findings


def least_privilege_summary(findings):
    recommendations = []
    for finding in findings:
        recommendations.append(
            {
                "finding": finding["title"],
                "severity": finding["severity"],
                **finding["recommendation"],
            }
        )
    return recommendations
