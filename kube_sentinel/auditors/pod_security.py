"""
Pod Security Standards (PSS) & CIS Benchmark Workload Auditor for KubeSentinel.
"""

import uuid
from kube_sentinel.core.models import AuditFinding, FindingCategory, WorkloadResource

DANGEROUS_CAPS = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "DAC_OVERRIDE", "SYS_MODULE", "ALL"}


class PodSecurityAuditor:
    """Audits Kubernetes workloads against PSS Restricted/Baseline profiles and CIS Kubernetes Benchmark."""

    @staticmethod
    def audit_workloads(workloads: list[WorkloadResource]) -> list[AuditFinding]:
        findings: list[AuditFinding] = []

        for w in workloads:
            # 1. Host Namespaces (hostNetwork, hostPID, hostIPC)
            if w.host_network:
                findings.append(
                    AuditFinding(
                        id=f"pss_{uuid.uuid4().hex[:8]}",
                        rule_id="PSS-002-HOSTNET",
                        category=FindingCategory.POD_SECURITY,
                        severity="HIGH",
                        resource_kind=w.kind,
                        resource_name=w.name,
                        namespace=w.namespace,
                        description=f"Workload '{w.name}' sets 'hostNetwork: true'. Pod shares the host network namespace, exposing node interfaces and local loopback traffic.",
                        remediation_advice="Set 'spec.template.spec.hostNetwork: false' or remove the directive.",
                    )
                )

            if w.host_pid:
                findings.append(
                    AuditFinding(
                        id=f"pss_{uuid.uuid4().hex[:8]}",
                        rule_id="PSS-002-HOSTPID",
                        category=FindingCategory.POD_SECURITY,
                        severity="HIGH",
                        resource_kind=w.kind,
                        resource_name=w.name,
                        namespace=w.namespace,
                        description=f"Workload '{w.name}' sets 'hostPID: true'. Containers can view and signal all processes running on the host node.",
                        remediation_advice="Set 'spec.template.spec.hostPID: false' or remove the directive.",
                    )
                )

            if w.host_ipc:
                findings.append(
                    AuditFinding(
                        id=f"pss_{uuid.uuid4().hex[:8]}",
                        rule_id="PSS-002-HOSTIPC",
                        category=FindingCategory.POD_SECURITY,
                        severity="HIGH",
                        resource_kind=w.kind,
                        resource_name=w.name,
                        namespace=w.namespace,
                        description=f"Workload '{w.name}' sets 'hostIPC: true'. Containers share IPC with the host node.",
                        remediation_advice="Set 'spec.template.spec.hostIPC: false' or remove the directive.",
                    )
                )

            # 2. Container Security Contexts
            for c in w.containers:
                # Privileged mode
                if c.privileged:
                    findings.append(
                        AuditFinding(
                            id=f"pss_{uuid.uuid4().hex[:8]}",
                            rule_id="PSS-001-PRIV",
                            category=FindingCategory.POD_SECURITY,
                            severity="CRITICAL",
                            resource_kind=w.kind,
                            resource_name=w.name,
                            namespace=w.namespace,
                            description=f"Container '{c.name}' in workload '{w.name}' runs in privileged mode ('privileged: true'). Gives container full root access to the host kernel and devices.",
                            remediation_advice="Set 'securityContext.privileged: false' and grant only required specific capabilities.",
                            details={"container": c.name},
                        )
                    )

                # Allow Privilege Escalation
                if c.allow_privilege_escalation is not False:
                    findings.append(
                        AuditFinding(
                            id=f"pss_{uuid.uuid4().hex[:8]}",
                            rule_id="PSS-003-NO-NEW-PRIVS",
                            category=FindingCategory.POD_SECURITY,
                            severity="HIGH",
                            resource_kind=w.kind,
                            resource_name=w.name,
                            namespace=w.namespace,
                            description=f"Container '{c.name}' does not disable privilege escalation ('allowPrivilegeEscalation: false'). Child processes can gain more privileges than parent (setuid binaries).",
                            remediation_advice="Explicitly set 'securityContext.allowPrivilegeEscalation: false'.",
                            details={"container": c.name},
                        )
                    )

                # Run As Non-Root
                pod_non_root = w.pod_security_context.get("runAsNonRoot", False)
                if not (c.run_as_non_root is True or pod_non_root is True):
                    findings.append(
                        AuditFinding(
                            id=f"pss_{uuid.uuid4().hex[:8]}",
                            rule_id="PSS-004-NON-ROOT",
                            category=FindingCategory.POD_SECURITY,
                            severity="HIGH",
                            resource_kind=w.kind,
                            resource_name=w.name,
                            namespace=w.namespace,
                            description=f"Container '{c.name}' may run as root ('runAsNonRoot' is missing or false).",
                            remediation_advice="Set 'securityContext.runAsNonRoot: true' and configure 'runAsUser: 10001'.",
                            details={"container": c.name},
                        )
                    )

                # Read-only Root Filesystem
                if c.read_only_root_filesystem is not True:
                    findings.append(
                        AuditFinding(
                            id=f"pss_{uuid.uuid4().hex[:8]}",
                            rule_id="PSS-005-RO-ROOTFS",
                            category=FindingCategory.POD_SECURITY,
                            severity="MEDIUM",
                            resource_kind=w.kind,
                            resource_name=w.name,
                            namespace=w.namespace,
                            description=f"Container '{c.name}' does not enforce read-only root filesystem ('readOnlyRootFilesystem: true').",
                            remediation_advice="Set 'securityContext.readOnlyRootFilesystem: true' and mount temporary writable directories using emptyDir volumes.",
                            details={"container": c.name},
                        )
                    )

                # Capability Drops
                dropped = [cap.upper() for cap in c.capabilities_drop]
                if "ALL" not in dropped:
                    findings.append(
                        AuditFinding(
                            id=f"pss_{uuid.uuid4().hex[:8]}",
                            rule_id="PSS-006-DROP-CAPS",
                            category=FindingCategory.POD_SECURITY,
                            severity="MEDIUM",
                            resource_kind=w.kind,
                            resource_name=w.name,
                            namespace=w.namespace,
                            description=f"Container '{c.name}' does not drop all default Linux capabilities ('drop: [\"ALL\"]').",
                            remediation_advice="Add 'securityContext.capabilities.drop: [\"ALL\"]'.",
                            details={"container": c.name},
                        )
                    )

                # Dangerous Added Capabilities
                added = {cap.upper().replace("CAP_", "") for cap in c.capabilities_add}
                dangerous_intersection = added.intersection(DANGEROUS_CAPS)
                if dangerous_intersection:
                    findings.append(
                        AuditFinding(
                            id=f"pss_{uuid.uuid4().hex[:8]}",
                            rule_id="PSS-007-DANGEROUS-CAPS",
                            category=FindingCategory.POD_SECURITY,
                            severity="HIGH",
                            resource_kind=w.kind,
                            resource_name=w.name,
                            namespace=w.namespace,
                            description=f"Container '{c.name}' requests dangerous Linux capability: {list(dangerous_intersection)}.",
                            remediation_advice="Remove dangerous capabilities from 'securityContext.capabilities.add'.",
                            details={"container": c.name, "capabilities": list(dangerous_intersection)},
                        )
                    )

        return findings
