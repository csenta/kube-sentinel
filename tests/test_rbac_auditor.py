import unittest
from kube_sentinel.auditors.rbac_auditor import RBACEscalationAuditor
from kube_sentinel.core.manifest_parser import ManifestParser
from kube_sentinel.core.rbac_graph import RBACGraphEngine
import os
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestRBACEscalationAuditor(unittest.TestCase):
    def test_detect_privilege_escalation(self):
        path = os.path.join(_ROOT, "examples", "rbac_escalation.yaml")
        _, roles, bindings, _ = ManifestParser.parse_file(path)
        graph = RBACGraphEngine(roles, bindings)
        findings = RBACEscalationAuditor.audit_rbac(graph)

        rule_ids = [f.rule_id for f in findings]
        self.assertIn("RBAC-002-BIND-ESCALATE", rule_ids)
        self.assertIn("RBAC-004-POD-EXEC", rule_ids)
        self.assertIn("RBAC-005-SECRET-READ", rule_ids)


if __name__ == "__main__":
    unittest.main()
