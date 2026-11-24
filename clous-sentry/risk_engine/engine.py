import json
import threading
import urllib.request

import numpy as np
from django.conf import settings
from sklearn.ensemble import RandomForestClassifier

from .models import RiskAssessment

SEVERITY_WEIGHTS = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_BASE_SCORES = {"info": 10, "low": 25, "medium": 50, "high": 75, "critical": 95}
MODEL_VERSION = "cloudsentry-hybrid-v1"
RESOURCE_CRITICALITY = {
    "rds_instance": 3,
    "iam_policy": 3,
    "security_group": 3,
    "s3_bucket": 2,
    "ec2_instance": 2,
    "ebs_volume": 1,
}
_MODEL = None
_MODEL_LOCK = threading.Lock()


def synthetic_training_data():
    rows = []
    labels = []
    for severity in range(5):
        for public in (0, 1):
            for encryption in (0, 1):
                for iam_wildcard in (0, 1):
                    for privileged in (0, 1):
                        criticality = min(3, max(1, severity))
                        rows.append([severity, public, encryption, iam_wildcard, privileged, criticality])
                        weighted = severity * 2 + public * 2 + encryption + iam_wildcard * 2 + privileged + criticality
                        labels.append(min(3, weighted // 4))
    return np.array(rows, dtype=float), np.array(labels, dtype=int)


def get_model():
    global _MODEL
    if _MODEL is None:
        with _MODEL_LOCK:
            if _MODEL is None:
                rows, labels = synthetic_training_data()
                model = RandomForestClassifier(
                    n_estimators=64,
                    max_depth=6,
                    random_state=42,
                    class_weight="balanced_subsample",
                )
                model.fit(rows, labels)
                _MODEL = model
    return _MODEL


def band_for_score(score):
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def extract_features(finding):
    evidence = finding.evidence or {}
    title = (finding.title or "").lower()
    evidence_text = json.dumps(evidence).lower()
    severity_weight = SEVERITY_WEIGHTS.get(finding.severity, 2)
    public = bool(
        evidence.get("public_access")
        or evidence.get("policy_is_public")
        or evidence.get("acl_all_users")
        or evidence.get("publicly_accessible")
        or evidence.get("public_ip_configured")
        or evidence.get("broad_management_ingress")
    )
    encryption_missing = bool(
        evidence.get("encrypted") is False
        or evidence.get("storage_encrypted") is False
        or evidence.get("encryption_config") == []
        or "unencrypted" in title
        or "no default encryption" in title
    )
    iam_wildcard = bool(
        finding.rule
        and finding.rule.service == "iam"
        and ("*" in evidence_text or "wildcard" in title or "all resources" in title)
    )
    privileged = bool(
        (finding.rule and finding.rule.category == "Identity and access")
        or "administrative" in title
        or "privileged" in evidence_text
    )
    resource_type = finding.resource.resource_type if finding.resource else evidence.get("resource_type", "")
    criticality = RESOURCE_CRITICALITY.get(resource_type, 1)
    return [severity_weight, int(public), int(encryption_missing), int(iam_wildcard), int(privileged), criticality]


def feature_labels(features):
    return {
        "severity_weight": features[0],
        "public_exposure": features[1],
        "encryption_gap": features[2],
        "iam_wildcard": features[3],
        "privileged_access": features[4],
        "resource_criticality": features[5],
    }


class GeminiExplainer:
    def explain(self, finding, local_explanation, score):
        settings_bundle = settings.CLOUDSENTRY
        if not settings_bundle["AI_EXPLANATIONS_ENABLED"] or not settings_bundle["GEMINI_API_KEY"]:
            return local_explanation, RiskAssessment.Source.LOCAL
        model = settings_bundle["GEMINI_MODEL"]
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={settings_bundle['GEMINI_API_KEY']}"
        payload = {
            "contents": [
                {
                    "parts": [
                        {
                            "text": (
                                "Explain this cloud security finding for a security analyst. "
                                "Do not reveal credentials. Be concise and actionable.\n"
                                f"Title: {finding.title}\n"
                                f"Severity: {finding.severity}\n"
                                f"Score: {score}\n"
                                f"Evidence: {json.dumps(finding.evidence)[:2000]}\n"
                                f"Remediation steps: {json.dumps(finding.remediation)[:2000]}"
                            )
                        }
                    ]
                }
            ]
        }
        try:
            request = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=12) as response:
                body = json.loads(response.read().decode("utf-8"))
            text = body["candidates"][0]["content"]["parts"][0]["text"]
            return str(text)[:3000], RiskAssessment.Source.GEMINI
        except Exception:
            return local_explanation, RiskAssessment.Source.LOCAL


class RiskEngine:
    def score_finding(self, finding):
        features = extract_features(finding)
        model = get_model()
        probabilities = model.predict_proba([features])[0]
        classes = list(model.classes_)
        expected_band = sum(
            index * probability for index, probability in zip(classes, probabilities, strict=True)
        ) / max(len(classes) - 1, 1)
        severity_base = SEVERITY_BASE_SCORES.get(finding.severity, 50)
        public_bonus = 10 if features[1] else 0
        encryption_bonus = 7 if features[2] else 0
        iam_bonus = 9 if features[3] else 0
        privileged_bonus = 6 if features[4] else 0
        rule_score = min(100, severity_base + public_bonus + encryption_bonus + iam_bonus + privileged_bonus)
        score = round(min(100, max(5, rule_score * 0.6 + expected_band * 100 * 0.4)), 1)
        band = band_for_score(score)
        factors = feature_labels(features)
        local_explanation = self.build_explanation(finding, factors, band, score)
        explanation, source = GeminiExplainer().explain(finding, local_explanation, score)
        remediation_summary = " ".join(
            str(step) for step in (finding.remediation or {}).get("steps", [])[:3]
        )[:1000]
        assessment = RiskAssessment.objects.create(
            finding=finding,
            score=score,
            severity_band=band,
            model_version=MODEL_VERSION,
            factors=factors,
            explanation=explanation,
            remediation_summary=remediation_summary,
            source=source,
        )
        finding.risk_score = score
        finding.save(update_fields=["risk_score", "updated_at"])
        return assessment

    def build_explanation(self, finding, factors, band, score):
        reasons = []
        if factors["public_exposure"]:
            reasons.append("the resource is exposed to untrusted networks")
        if factors["encryption_gap"]:
            reasons.append("encryption at rest is missing or not verifiable")
        if factors["iam_wildcard"]:
            reasons.append("identity permissions are overly broad")
        if factors["privileged_access"]:
            reasons.append("privileged or administrative access is involved")
        if not reasons:
            reasons.append("the configuration deviates from the expected secure baseline")
        return (
            f"CloudSentry classified this finding as {band} with a score of {score:.1f}/100 because "
            f"{'; '.join(reasons)}. The score combines rule severity with a local scikit-learn model "
            "trained on deterministic synthetic examples, not on customer scan results. "
            "Review the evidence and apply the least-privilege or secure-configuration recommendation."
        )
