import unittest
from kube_sentinel.core.manifest_parser import ManifestParser
from kube_sentinel.core.rbac_graph import RBACGraphEngine
from kube_sentinel.core.models import RBACSubject


class TestRBACGraph(unittest.TestCase):
    def test_bipartite_rbac_graph(self):
        path = "/home/emprogue/Projects/kube-sentinel/examples/rbac_escalation.yaml"
        _, roles, bindings, _ = ManifestParser.parse_file(path)
        graph = RBACGraphEngine(roles, bindings)

        subj = RBACSubject(kind="ServiceAccount", name="dev-sa", namespace="development")
        rules = graph.get_effective_rules(subj)
        self.assertEqual(len(rules), 3)

        resources_granted = [r for rule in rules for r in rule.resources]
        self.assertIn("secrets", resources_granted)
        self.assertIn("clusterroles", resources_granted)


if __name__ == "__main__":
    unittest.main()
