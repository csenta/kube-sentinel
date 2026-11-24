"""
Multi-Document Manifest Stream Parser for KubeSentinel.
Ingests Kubernetes YAML and JSON manifests, organizing workloads, RBAC policies, and NetworkPolicies.
"""

import os
from typing import Any
import yaml

from kube_sentinel.core.models import (
    PolicyRule,
    RBACBinding,
    RBACRole,
    RBACSubject,
    WorkloadContainer,
    WorkloadResource,
)


class ManifestParser:
    """Parses multi-document Kubernetes YAML or JSON into typed domain structures."""

    @staticmethod
    def parse_file(file_path: str) -> tuple[list[WorkloadResource], list[RBACRole], list[RBACBinding], list[dict[str, Any]]]:
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Kubernetes manifest not found: {file_path}")

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        return ManifestParser.parse_string(content)

    @staticmethod
    def parse_string(content: str) -> tuple[list[WorkloadResource], list[RBACRole], list[RBACBinding], list[dict[str, Any]]]:
        workloads: list[WorkloadResource] = []
        roles: list[RBACRole] = []
        bindings: list[RBACBinding] = []
        network_policies: list[dict[str, Any]] = []

        try:
            documents = list(yaml.safe_load_all(content))
        except Exception as e:
            raise ValueError(f"Failed to parse Kubernetes YAML: {e}")

        for doc in documents:
            if not isinstance(doc, dict):
                continue

            kind = doc.get("kind", "")
            metadata = doc.get("metadata", {})
            name = metadata.get("name", "unnamed")
            namespace = metadata.get("namespace", "default")

            if kind in ("Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob", "Pod"):
                workload = ManifestParser._extract_workload(doc, kind, name, namespace)
                if workload:
                    workloads.append(workload)

            elif kind in ("Role", "ClusterRole"):
                role = ManifestParser._extract_role(doc, kind, name, namespace)
                if role:
                    roles.append(role)

            elif kind in ("RoleBinding", "ClusterRoleBinding"):
                binding = ManifestParser._extract_binding(doc, kind, name, namespace)
                if binding:
                    bindings.append(binding)

            elif kind == "NetworkPolicy":
                network_policies.append(doc)

        return workloads, roles, bindings, network_policies

    @staticmethod
    def _extract_workload(doc: dict[str, Any], kind: str, name: str, namespace: str) -> WorkloadResource | None:
        spec = doc.get("spec", {})
        pod_spec = spec
        if kind in ("Deployment", "DaemonSet", "StatefulSet", "Job"):
            pod_spec = spec.get("template", {}).get("spec", {})
        elif kind == "CronJob":
            pod_spec = spec.get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})

        host_net = pod_spec.get("hostNetwork", False)
        host_pid = pod_spec.get("hostPID", False)
        host_ipc = pod_spec.get("hostIPC", False)
        sa_name = pod_spec.get("serviceAccountName", "default")
        pod_sec_ctx = pod_spec.get("securityContext", {})

        containers: list[WorkloadContainer] = []
        raw_containers = pod_spec.get("containers", [])
        if not isinstance(raw_containers, list):
            raw_containers = []

        for c in raw_containers:
            c_name = c.get("name", "")
            c_image = c.get("image", "")
            c_sec = c.get("securityContext", {})

            privileged = c_sec.get("privileged", False)
            allow_priv_esc = c_sec.get("allowPrivilegeEscalation")
            run_as_non_root = c_sec.get("runAsNonRoot")
            read_only_root = c_sec.get("readOnlyRootFilesystem")

            caps = c_sec.get("capabilities", {})
            add_caps = caps.get("add", []) if isinstance(caps.get("add"), list) else []
            drop_caps = caps.get("drop", []) if isinstance(caps.get("drop"), list) else []

            containers.append(
                WorkloadContainer(
                    name=c_name,
                    image=c_image,
                    privileged=privileged,
                    allow_privilege_escalation=allow_priv_esc,
                    run_as_non_root=run_as_non_root,
                    read_only_root_filesystem=read_only_root,
                    capabilities_add=add_caps,
                    capabilities_drop=drop_caps,
                    security_context=c_sec,
                )
            )

        return WorkloadResource(
            kind=kind,
            name=name,
            namespace=namespace,
            host_network=host_net,
            host_pid=host_pid,
            host_ipc=host_ipc,
            service_account_name=sa_name,
            containers=containers,
            pod_security_context=pod_sec_ctx,
            raw_manifest=doc,
        )

    @staticmethod
    def _extract_role(doc: dict[str, Any], kind: str, name: str, namespace: str) -> RBACRole:
        rules: list[PolicyRule] = []
        for r in doc.get("rules", []):
            if isinstance(r, dict):
                rules.append(
                    PolicyRule(
                        api_groups=r.get("apiGroups", []),
                        resources=r.get("resources", []),
                        verbs=r.get("verbs", []),
                        resource_names=r.get("resourceNames", []),
                    )
                )
        ns = "" if kind == "ClusterRole" else namespace
        return RBACRole(kind=kind, name=name, namespace=ns, rules=rules)

    @staticmethod
    def _extract_binding(doc: dict[str, Any], kind: str, name: str, namespace: str) -> RBACBinding:
        role_ref = doc.get("roleRef", {})
        role_kind = role_ref.get("kind", "")
        role_name = role_ref.get("name", "")

        subjects: list[RBACSubject] = []
        for s in doc.get("subjects", []):
            if isinstance(s, dict):
                subjects.append(
                    RBACSubject(
                        kind=s.get("kind", "ServiceAccount"),
                        name=s.get("name", ""),
                        namespace=s.get("namespace", namespace if kind == "RoleBinding" else ""),
                    )
                )

        ns = "" if kind == "ClusterRoleBinding" else namespace
        return RBACBinding(
            kind=kind,
            name=name,
            namespace=ns,
            role_kind=role_kind,
            role_name=role_name,
            subjects=subjects,
        )
