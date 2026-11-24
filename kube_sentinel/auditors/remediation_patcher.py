"""
Automated Remediation Patch Synthesizer for KubeSentinel.
Generates hardened, least-privilege Kubernetes workload manifests adhering to PSS Restricted profile.
"""

import copy
from typing import Any
import yaml

from kube_sentinel.core.models import HardenedPatch, WorkloadResource


class RemediationPatcher:
    """Generates drop-in hardened YAML manifests fixing security context and host namespace violations."""

    @staticmethod
    def patch_workload(workload: WorkloadResource) -> HardenedPatch:
        patched_doc = copy.deepcopy(workload.raw_manifest)
        modifications: list[str] = []

        spec = patched_doc.get("spec", {})
        pod_spec = spec
        if workload.kind in ("Deployment", "DaemonSet", "StatefulSet", "Job"):
            pod_spec = spec.setdefault("template", {}).setdefault("spec", {})
        elif workload.kind == "CronJob":
            pod_spec = spec.setdefault("jobTemplate", {}).setdefault("spec", {}).setdefault("template", {}).setdefault("spec", {})

        # 1. Disable Host Namespaces
        if pod_spec.get("hostNetwork", False):
            pod_spec["hostNetwork"] = False
            modifications.append("Disabled hostNetwork")

        if pod_spec.get("hostPID", False):
            pod_spec["hostPID"] = False
            modifications.append("Disabled hostPID")

        if pod_spec.get("hostIPC", False):
            pod_spec["hostIPC"] = False
            modifications.append("Disabled hostIPC")

        # Set Pod Security Context defaults
        pod_sec = pod_spec.setdefault("securityContext", {})
        if "runAsNonRoot" not in pod_sec:
            pod_sec["runAsNonRoot"] = True
            modifications.append("Enforced pod-level runAsNonRoot: true")
        if "seccompProfile" not in pod_sec:
            pod_sec["seccompProfile"] = {"type": "RuntimeDefault"}
            modifications.append("Configured seccompProfile: RuntimeDefault")

        # 2. Harden Containers
        containers = pod_spec.get("containers", [])
        for c in containers:
            c_name = c.get("name", "container")
            sec = c.setdefault("securityContext", {})

            if sec.get("privileged", False):
                sec["privileged"] = False
                modifications.append(f"[{c_name}] Removed privileged mode")

            if sec.get("allowPrivilegeEscalation") is not False:
                sec["allowPrivilegeEscalation"] = False
                modifications.append(f"[{c_name}] Set allowPrivilegeEscalation: false")

            if sec.get("readOnlyRootFilesystem") is not True:
                sec["readOnlyRootFilesystem"] = True
                modifications.append(f"[{c_name}] Enforced readOnlyRootFilesystem: true")

            if sec.get("runAsNonRoot") is not True:
                sec["runAsNonRoot"] = True
                modifications.append(f"[{c_name}] Set runAsNonRoot: true")

            caps = sec.setdefault("capabilities", {})
            drop_caps = caps.get("drop", [])
            if not isinstance(drop_caps, list):
                drop_caps = []
            if "ALL" not in [d.upper() for d in drop_caps]:
                drop_caps.append("ALL")
                caps["drop"] = drop_caps
                modifications.append(f"[{c_name}] Added drop: ['ALL'] capabilities")

            # Remove dangerous capabilities from add
            if "add" in caps and isinstance(caps["add"], list):
                safe_add = [cap for cap in caps["add"] if cap.upper() not in ("SYS_ADMIN", "NET_ADMIN", "ALL")]
                if len(safe_add) != len(caps["add"]):
                    caps["add"] = safe_add
                    modifications.append(f"[{c_name}] Stripped dangerous capabilities from add")

        patched_yaml = yaml.dump(patched_doc, sort_keys=False)
        return HardenedPatch(
            resource_kind=workload.kind,
            resource_name=workload.name,
            namespace=workload.namespace,
            patched_yaml=patched_yaml,
            modifications_made=modifications,
        )
