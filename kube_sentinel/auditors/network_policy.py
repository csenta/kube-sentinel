"""
NetworkPolicy Isolation and Lateral Movement Auditor for KubeSentinel.
"""

from typing import Any
import uuid
from kube_sentinel.core.models import AuditFinding, FindingCategory, WorkloadResource


class NetworkPolicyAuditor:
    """Audits namespaces and workloads for missing network isolation and unrestricted lateral movement."""

    @staticmethod
    def audit_isolation(
        workloads: list[WorkloadResource],
        network_policies: list[dict[str, Any]],
    ) -> list[AuditFinding]:
        findings: list[AuditFinding] = []

        # Map namespaces that have at least one default-deny or broad network policy
        protected_namespaces: set[str] = set()

        for np in network_policies:
            ns = np.get("metadata", {}).get("namespace", "default")
            spec = np.get("spec", {})
            pod_selector = spec.get("podSelector", {})
            # If podSelector is empty ({}), it applies to all pods in the namespace
            if pod_selector == {} or not pod_selector:
                protected_namespaces.add(ns)

        # Check workloads in namespaces lacking network policies
        evaluated_namespaces: set[str] = set()

        for w in workloads:
            if w.namespace not in protected_namespaces and w.namespace not in evaluated_namespaces:
                evaluated_namespaces.add(w.namespace)
                findings.append(
                    AuditFinding(
                        id=f"net_{uuid.uuid4().hex[:8]}",
                        rule_id="NET-001-MISSING-DEFAULT-DENY",
                        category=FindingCategory.NETWORK_POLICY,
                        severity="HIGH",
                        resource_kind="Namespace",
                        resource_name=w.namespace,
                        namespace=w.namespace,
                        description=f"Namespace '{w.namespace}' contains active workloads but lacks a default-deny NetworkPolicy. Workloads are exposed to unrestricted pod-to-pod lateral traffic.",
                        remediation_advice="Deploy a default-deny NetworkPolicy (`spec.podSelector: {}` with `policyTypes: [\"Ingress\", \"Egress\"]`) and explicitly allow required traffic.",
                    )
                )

        return findings
