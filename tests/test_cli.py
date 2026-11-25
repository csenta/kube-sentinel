import argparse
import os
import tempfile
import unittest
from kube_sentinel.cli import handle_rbac, handle_remediate, handle_scan
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class TestCLI(unittest.TestCase):
    def setUp(self):
        self.vuln_path = os.path.join(_ROOT, "examples", "vulnerable_workload.yaml")
        self.rbac_path = os.path.join(_ROOT, "examples", "rbac_escalation.yaml")

    def test_cli_scan(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as f_json:
            out_json = f_json.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".html") as f_html:
            out_html = f_html.name

        try:
            args = argparse.Namespace(
                input=self.vuln_path,
                output_json=out_json,
                output_html=out_html,
                fail_on_severity=None,
            )
            code = handle_scan(args)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(out_json))
            self.assertTrue(os.path.isfile(out_html))
        finally:
            for p in (out_json, out_html):
                if os.path.exists(p):
                    os.remove(p)

    def test_cli_remediate(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".yaml") as f_yaml:
            out_yaml = f_yaml.name

        try:
            args = argparse.Namespace(
                input=self.vuln_path,
                output=out_yaml,
            )
            code = handle_remediate(args)
            self.assertEqual(code, 0)
            self.assertTrue(os.path.isfile(out_yaml))
        finally:
            if os.path.exists(out_yaml):
                os.remove(out_yaml)

    def test_cli_rbac(self):
        args = argparse.Namespace(
            input=self.rbac_path,
        )
        code = handle_rbac(args)
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
