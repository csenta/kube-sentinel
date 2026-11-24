"""
Domain Data Models for KubeSentinel.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class FindingCategory(str, Enum):
    POD_SECURITY = "POD_SECURITY"
    RBAC_ESCALATION = "RBAC_ESCALATION"
    NETWORK_POLICY = "NETWORK_POLICY"


@dataclass
class WorkloadContainer:
    name: str
    image: str
    privileged: bool = False
    allow_privilege_escalation: bool | None = None
    run_as_non_root: bool | None = None
    read_only_root_filesystem: bool | None = None
    capabilities_add: list[str] = field(default_factory=list)
    capabilities_drop: list[str] = field(default_factory=list)
    security_context: dict[str, Any] = field(default_factory=dict)


@dataclass
class WorkloadResource:
    kind: str  # Deployment, DaemonSet, StatefulSet, Pod, Job, CronJob
    name: str
    namespace: str
    host_network: bool = False
    host_pid: bool = False
    host_ipc: bool = False
    service_account_name: str = "default"
    containers: list[WorkloadContainer] = field(default_factory=list)
    pod_security_context: dict[str, Any] = field(default_factory=dict)
    raw_manifest: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyRule:
    api_groups: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    verbs: list[str] = field(default_factory=list)
    resource_names: list[str] = field(default_factory=list)


@dataclass
class RBACRole:
    kind: str  # Role or ClusterRole
    name: str
    namespace: str = ""
    rules: list[PolicyRule] = field(default_factory=list)


@dataclass
class RBACSubject:
    kind: str  # ServiceAccount, User, Group
    name: str
    namespace: str = ""


@dataclass
class RBACBinding:
    kind: str  # RoleBinding or ClusterRoleBinding
    name: str
    namespace: str = ""
    role_kind: str = ""
    role_name: str = ""
    subjects: list[RBACSubject] = field(default_factory=list)


@dataclass
class AuditFinding:
    id: str
    rule_id: str
    category: FindingCategory
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    resource_kind: str
    resource_name: str
    namespace: str
    description: str
    remediation_advice: str
    details: dict[str, Any] = field(default_factory=dict)


@dataclass
class HardenedPatch:
    resource_kind: str
    resource_name: str
    namespace: str
    patched_yaml: str
    modifications_made: list[str] = field(default_factory=list)


@dataclass
class AuditReport:
    manifest_name: str
    total_resources: int
    findings: list[AuditFinding] = field(default_factory=list)
    patches: list[HardenedPatch] = field(default_factory=list)
    security_score: int = 100  # 0 to 100
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest_name": self.manifest_name,
            "total_resources": self.total_resources,
            "security_score": self.security_score,
            "timestamp": self.timestamp,
            "findings_count": len(self.findings),
            "findings": [
                {
                    "id": f.id,
                    "rule_id": f.rule_id,
                    "category": f.category.value,
                    "severity": f.severity,
                    "resource": f"{f.resource_kind}/{f.resource_name}",
                    "namespace": f.namespace or "cluster-wide",
                    "description": f.description,
                    "remediation": f.remediation_advice,
                    "details": f.details,
                }
                for f in self.findings
            ],
            "patches_count": len(self.patches),
        }
