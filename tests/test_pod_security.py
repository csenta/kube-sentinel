import unittest
from kube_sentinel.auditors.pod_security import PodSecurityAuditor
from kube_sentinel.core.manifest_parser import ManifestParser
import os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestPodSecurityAuditor(unittest.TestCase):
    def test_detect_pss_violations(self):
        path = os.path.join(_ROOT, "examples", "vulnerable_workload.yaml")
        workloads, _, _, _ = ManifestParser.parse_file(path)
        findings = PodSecurityAuditor.audit_workloads(workloads)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("PSS-001-PRIV", rule_ids)
        self.assertIn("PSS-002-HOSTNET", rule_ids)
        self.assertIn("PSS-002-HOSTPID", rule_ids)
        self.assertIn("PSS-004-NON-ROOT", rule_ids)
        self.assertIn("PSS-005-RO-ROOTFS", rule_ids)
        self.assertIn("PSS-006-DROP-CAPS", rule_ids)
        self.assertIn("PSS-007-DANGEROUS-CAPS", rule_ids)

    def test_clean_hardened_workload(self):
        path = os.path.join(_ROOT, "examples", "hardened_workload.yaml")
        workloads, _, _, _ = ManifestParser.parse_file(path)
        findings = PodSecurityAuditor.audit_workloads(workloads)
        # Should have 0 PSS violations
        self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
