import unittest
import yaml
from kube_sentinel.auditors.remediation_patcher import RemediationPatcher
from kube_sentinel.core.manifest_parser import ManifestParser
import os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestRemediationPatcher(unittest.TestCase):
    def test_remediation_patching(self):
        path = os.path.join(_ROOT, "examples", "vulnerable_workload.yaml")
        workloads, _, _, _ = ManifestParser.parse_file(path)
        patch = RemediationPatcher.patch_workload(workloads[0])

        self.assertGreater(len(patch.modifications_made), 3)

        # Parse patched YAML
        doc = yaml.safe_load(patch.patched_yaml)
        pod_spec = doc["spec"]["template"]["spec"]
        self.assertFalse(pod_spec["hostPID"])
        self.assertFalse(pod_spec["hostNetwork"])

        container_sec = pod_spec["containers"][0]["securityContext"]
        self.assertFalse(container_sec["privileged"])
        self.assertFalse(container_sec["allowPrivilegeEscalation"])
        self.assertTrue(container_sec["readOnlyRootFilesystem"])
        self.assertTrue(container_sec["runAsNonRoot"])
        self.assertIn("ALL", container_sec["capabilities"]["drop"])


if __name__ == "__main__":
    unittest.main()
