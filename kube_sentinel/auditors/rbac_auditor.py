"""
RBAC Privilege Escalation Graph Auditor for KubeSentinel.
Detects dangerous permissions and privilege escalation chains in Roles and ClusterRoles.
"""

import uuid
from kube_sentinel.core.models import AuditFinding, FindingCategory
from kube_sentinel.core.rbac_graph import RBACGraphEngine


class RBACEscalationAuditor:
    """Audits Kubernetes RBAC policies for privilege escalation paths and over-permissive bindings."""

    @staticmethod
    def audit_rbac(graph_engine: RBACGraphEngine) -> list[AuditFinding]:
        findings: list[AuditFinding] = []

        for subj_key, roles in graph_engine.get_all_bound_subjects():
            for role in roles:
                # 1. Wildcard resources and verbs
                for rule in role.rules:
                    has_wildcard_res = "*" in rule.resources
                    has_wildcard_verb = "*" in rule.verbs

                    if has_wildcard_res and has_wildcard_verb:
                        findings.append(
                            AuditFinding(
                                id=f"rbac_{uuid.uuid4().hex[:8]}",
                                rule_id="RBAC-001-WILDCARD",
                                category=FindingCategory.RBAC_ESCALATION,
                                severity="CRITICAL",
                                resource_kind=role.kind,
                                resource_name=role.name,
                                namespace=role.namespace,
                                description=f"Subject '{subj_key}' bound to '{role.kind}/{role.name}' with wildcard permissions ('*' verbs on '*' resources). Equivalent to full cluster compromise.",
                                remediation_advice="Apply least-privilege principles by scoping exact resources and verbs required.",
                                details={"subject": subj_key, "role": role.name},
                            )
                        )

                    # 2. Bind and Escalate permissions (Privilege Escalation Vector)
                    # Allows granting permissions not held or binding to arbitrary clusterroles
                    verbs_set = set(rule.verbs)
                    res_set = set(rule.resources)

                    if {"bind", "escalate"}.intersection(verbs_set) or "*" in verbs_set:
                        if {"roles", "clusterroles", "*"}.intersection(res_set):
                            findings.append(
                                AuditFinding(
                                    id=f"rbac_{uuid.uuid4().hex[:8]}",
                                    rule_id="RBAC-002-BIND-ESCALATE",
                                    category=FindingCategory.RBAC_ESCALATION,
                                    severity="CRITICAL",
                                    resource_kind=role.kind,
                                    resource_name=role.name,
                                    namespace=role.namespace,
                                    description=f"Subject '{subj_key}' has 'bind' or 'escalate' verbs on (Cluster)Roles. Allows subject to grant themselves cluster-admin permissions bypassing authorization.",
                                    remediation_advice="Remove 'bind' and 'escalate' verbs from non-admin service accounts.",
                                    details={"subject": subj_key, "verbs": list(verbs_set)},
                                )
                            )

                    # 3. Impersonate (Privilege Escalation Vector)
                    if "impersonate" in verbs_set or "*" in verbs_set:
                        if {"users", "groups", "serviceaccounts", "*"}.intersection(res_set):
                            findings.append(
                                AuditFinding(
                                    id=f"rbac_{uuid.uuid4().hex[:8]}",
                                    rule_id="RBAC-003-IMPERSONATE",
                                    category=FindingCategory.RBAC_ESCALATION,
                                    severity="CRITICAL",
                                    resource_kind=role.kind,
                                    resource_name=role.name,
                                    namespace=role.namespace,
                                    description=f"Subject '{subj_key}' can impersonate users or groups. Allows executing API requests with 'system:masters' cluster privileges.",
                                    remediation_advice="Revoke 'impersonate' verbs from application roles.",
                                    details={"subject": subj_key},
                                )
                            )

                    # 4. Pod Exec and Ephemeral Containers (Code Execution Vector)
                    if {"create", "*"}.intersection(verbs_set):
                        if {"pods/exec", "pods/ephemeralcontainers", "*"}.intersection(res_set):
                            findings.append(
                                AuditFinding(
                                    id=f"rbac_{uuid.uuid4().hex[:8]}",
                                    rule_id="RBAC-004-POD-EXEC",
                                    category=FindingCategory.RBAC_ESCALATION,
                                    severity="HIGH",
                                    resource_kind=role.kind,
                                    resource_name=role.name,
                                    namespace=role.namespace,
                                    description=f"Subject '{subj_key}' has 'pods/exec' create privileges. Allows executing arbitrary commands inside running containers with different identities.",
                                    remediation_advice="Restrict 'pods/exec' access strictly to administrative bastion tools.",
                                    details={"subject": subj_key},
                                )
                            )

                    # 5. Secret Read (Credential Harvesting Vector)
                    if {"get", "list", "watch", "*"}.intersection(verbs_set):
                        if {"secrets", "*"}.intersection(res_set):
                            findings.append(
                                AuditFinding(
                                    id=f"rbac_{uuid.uuid4().hex[:8]}",
                                    rule_id="RBAC-005-SECRET-READ",
                                    category=FindingCategory.RBAC_ESCALATION,
                                    severity="HIGH",
                                    resource_kind=role.kind,
                                    resource_name=role.name,
                                    namespace=role.namespace,
                                    description=f"Subject '{subj_key}' has broad read permissions ('get', 'list') on 'secrets'. Can steal cluster tokens and credentials.",
                                    remediation_advice="Scope secret access to specific 'resourceNames' or use External Secrets Operator.",
                                    details={"subject": subj_key},
                                )
                            )

        return findings
