# KubeSentinel API Reference

## Python Library Usage

```python
from kube_sentinel.core.manifest_parser import ManifestParser
from kube_sentinel.core.rbac_graph import RBACGraphEngine
from kube_sentinel.auditors.pod_security import PodSecurityAuditor
from kube_sentinel.auditors.rbac_auditor import RBACEscalationAuditor
from kube_sentinel.auditors.network_policy import NetworkPolicyAuditor
from kube_sentinel.auditors.remediation_patcher import RemediationPatcher
from kube_sentinel.reporters.cli_reporter import CLIReporter

# 1. Parse Kubernetes Manifests
workloads, roles, bindings, net_policies = ManifestParser.parse_file("manifest.yaml")

# 2. Audit Pod Security Standards (PSS)
pss_findings = PodSecurityAuditor.audit_workloads(workloads)

# 3. Model and Audit RBAC Privilege Escalation
rbac_graph = RBACGraphEngine(roles, bindings)
rbac_findings = RBACEscalationAuditor.audit_rbac(rbac_graph)

# 4. Audit Network Isolation
net_findings = NetworkPolicyAuditor.audit_isolation(workloads, net_policies)

# 5. Synthesize Hardened YAML Patches
patches = [RemediationPatcher.patch_workload(w) for w in workloads]
```
