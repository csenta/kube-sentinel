import os
import unittest
from kube_sentinel.core.manifest_parser import ManifestParser


class TestManifestParser(unittest.TestCase):
    def setUp(self):
        self.vuln_path = "/home/emprogue/Projects/kube-sentinel/examples/vulnerable_workload.yaml"
        self.rbac_path = "/home/emprogue/Projects/kube-sentinel/examples/rbac_escalation.yaml"
        self.hard_path = "/home/emprogue/Projects/kube-sentinel/examples/hardened_workload.yaml"

    def test_parse_vulnerable_workload(self):
        self.assertTrue(os.path.isfile(self.vuln_path))
        workloads, roles, bindings, net = ManifestParser.parse_file(self.vuln_path)
        self.assertEqual(len(workloads), 1)
        w = workloads[0]
        self.assertEqual(w.name, "legacy-api-backend")
        self.assertTrue(w.host_pid)
        self.assertTrue(w.host_network)
        self.assertEqual(len(w.containers), 1)
        self.assertTrue(w.containers[0].privileged)
        self.assertIn("SYS_ADMIN", w.containers[0].capabilities_add)

    def test_parse_rbac_manifest(self):
        workloads, roles, bindings, net = ManifestParser.parse_file(self.rbac_path)
        self.assertEqual(len(roles), 1)
        self.assertEqual(roles[0].name, "dev-operator-role")
        self.assertEqual(len(bindings), 1)
        self.assertEqual(bindings[0].name, "dev-operator-binding")

    def test_parse_hardened_workload_and_network(self):
        workloads, roles, bindings, net = ManifestParser.parse_file(self.hard_path)
        self.assertEqual(len(workloads), 1)
        self.assertEqual(len(net), 1)
        self.assertEqual(net[0]["metadata"]["name"], "default-deny-all")


if __name__ == "__main__":
    unittest.main()
