from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass
class FindingDraft:
    rule_id: str
    title: str
    description: str = ""
    severity: str = "medium"
    evidence: dict[str, Any] = field(default_factory=dict)
    resource_id: str = ""
    resource_type: str = ""
    resource_name: str = ""
    region: str = ""
    remediation: dict[str, Any] = field(default_factory=dict)
    is_demo: bool = False


@dataclass
class ScanResult:
    resources: list = field(default_factory=list)
    findings: list[FindingDraft] = field(default_factory=list)
    errors: list[dict[str, str]] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=dict)


class BaseScanner(ABC):
    mode = "live"

    @abstractmethod
    def scan(self, cloud_account, rules):
        raise NotImplementedError
