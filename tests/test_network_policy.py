import unittest
from kube_sentinel.auditors.network_policy import NetworkPolicyAuditor
from kube_sentinel.core.manifest_parser import ManifestParser


class TestNetworkPolicyAuditor(unittest.TestCase):
    def test_missing_default_deny(self):
        # Vulnerable workload manifest has no NetworkPolicy in 'production' namespace
        path = "/home/emprogue/Projects/kube-sentinel/examples/vulnerable_workload.yaml"
        workloads, _, _, net = ManifestParser.parse_file(path)
        findings = NetworkPolicyAuditor.audit_isolation(workloads, net)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].rule_id, "NET-001-MISSING-DEFAULT-DENY")

    def test_namespace_with_default_deny(self):
        # Hardened manifest defines default-deny in 'production'
        path = "/home/emprogue/Projects/kube-sentinel/examples/hardened_workload.yaml"
        workloads, _, _, net = ManifestParser.parse_file(path)
        findings = NetworkPolicyAuditor.audit_isolation(workloads, net)
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
