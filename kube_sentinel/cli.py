"""
Unified Command-Line Interface for KubeSentinel.
"""

import argparse
import json
import os
import sys

from kube_sentinel.auditors.network_policy import NetworkPolicyAuditor
from kube_sentinel.auditors.pod_security import PodSecurityAuditor
from kube_sentinel.auditors.rbac_auditor import RBACEscalationAuditor
from kube_sentinel.auditors.remediation_patcher import RemediationPatcher
from kube_sentinel.core.manifest_parser import ManifestParser
from kube_sentinel.core.models import AuditReport
from kube_sentinel.core.rbac_graph import RBACGraphEngine
from kube_sentinel.reporters.cli_reporter import CLIReporter
from kube_sentinel.reporters.html_reporter import HTMLReporter


def compute_security_score(findings) -> int:
    score = 100
    for f in findings:
        if f.severity == "CRITICAL":
            score -= 25
        elif f.severity == "HIGH":
            score -= 15
        elif f.severity == "MEDIUM":
            score -= 8
        else:
            score -= 3
    return max(0, score)


def run_k8s_audit(input_path: str) -> AuditReport:
    workloads, roles, bindings, net_policies = ManifestParser.parse_file(input_path)
    total_resources = len(workloads) + len(roles) + len(bindings) + len(net_policies)

    # 1. Pod Security Standards audit
    pss_findings = PodSecurityAuditor.audit_workloads(workloads)

    # 2. RBAC Escalation Graph audit
    rbac_graph = RBACGraphEngine(roles, bindings)
    rbac_findings = RBACEscalationAuditor.audit_rbac(rbac_graph)

    # 3. Network Policy Isolation audit
    net_findings = NetworkPolicyAuditor.audit_isolation(workloads, net_policies)

    all_findings = pss_findings + rbac_findings + net_findings

    # 4. Synthesize hardened patches for workloads with PSS issues
    patches = [RemediationPatcher.patch_workload(w) for w in workloads]

    sec_score = compute_security_score(all_findings)

    return AuditReport(
        manifest_name=os.path.basename(input_path),
        total_resources=total_resources,
        findings=all_findings,
        patches=patches,
        security_score=sec_score,
    )


def handle_scan(args: argparse.Namespace) -> int:
    try:
        report = run_k8s_audit(args.input)
    except Exception as e:
        print(f"[ERROR] Audit failed on {args.input}: {e}")
        return 1

    # 1. Console summary
    CLIReporter.print_summary(report)

    # 2. JSON export
    if args.output_json:
        with open(args.output_json, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, indent=2)
        print(f"📄 JSON report saved to {args.output_json}")

    # 3. HTML export
    if args.output_html:
        html = HTMLReporter.generate(report)
        with open(args.output_html, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"📊 Interactive HTML report saved to {args.output_html}")

    # 4. CI quality gate
    if args.fail_on_severity:
        threshold = args.fail_on_severity.upper()
        severity_order = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        thresh_val = severity_order.get(threshold, 3)

        violates = any(severity_order.get(f.severity, 0) >= thresh_val for f in report.findings)
        if violates:
            print(f"❌ CI Gate Failed: Found findings matching or exceeding severity '{threshold}'!")
            return 2

    return 0


def handle_remediate(args: argparse.Namespace) -> int:
    try:
        workloads, _, _, _ = ManifestParser.parse_file(args.input)
    except Exception as e:
        print(f"[ERROR] Failed to parse {args.input}: {e}")
        return 1

    if not workloads:
        print(f"No workloads found in {args.input} to patch.")
        return 0

    patches = [RemediationPatcher.patch_workload(w) for w in workloads]
    combined_yaml = "\n---\n".join(p.patched_yaml for p in patches)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(combined_yaml)
        print(f"✅ Hardened manifest written to {args.output} ({len(patches)} workloads patched)")
    else:
        print(combined_yaml)

    return 0


def handle_rbac(args: argparse.Namespace) -> int:
    try:
        _, roles, bindings, _ = ManifestParser.parse_file(args.input)
        graph = RBACGraphEngine(roles, bindings)
        findings = RBACEscalationAuditor.audit_rbac(graph)
    except Exception as e:
        print(f"[ERROR] RBAC audit failed: {e}")
        return 1

    print(f"\n🔐 [KubeSentinel] RBAC Privilege Analysis for {args.input}")
    print("=" * 70)
    print(f"  Active Roles:    {len(roles)}")
    print(f"  Active Bindings: {len(bindings)}")
    print(f"  Escalation Risks Detected: {len(findings)}\n")

    for idx, f in enumerate(findings, 1):
        print(f"[{idx:02d}] 🚨 {f.severity} | {f.rule_id} | {f.resource_name}")
        print(f"     {f.description}")
        print(f"     Remedy: {f.remediation_advice}\n")

    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="kube-sentinel",
        description="KubeSentinel: Autonomous Cloud-Native Kubernetes Security Posture Management & RBAC Privilege Escalation Graph Auditor",
    )
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    # scan
    p_scan = subparsers.add_parser("scan", help="Audit Kubernetes manifests for PSS, RBAC, and Network violations")
    p_scan.add_argument("--input", "-i", required=True, help="Path to Kubernetes YAML or JSON manifest")
    p_scan.add_argument("--output-json", default="", help="Path to write JSON report")
    p_scan.add_argument("--output-html", default="", help="Path to write HTML dashboard")
    p_scan.add_argument(
        "--fail-on-severity",
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        default=None,
        help="Exit code 2 if findings >= severity threshold",
    )

    # remediate
    p_remedy = subparsers.add_parser("remediate", help="Synthesize drop-in hardened Kubernetes YAML manifests")
    p_remedy.add_argument("--input", "-i", required=True, help="Path to Kubernetes YAML manifest")
    p_remedy.add_argument("--output", "-o", default="", help="Path to save hardened YAML manifest")

    # rbac
    p_rbac = subparsers.add_parser("rbac", help="Inspect RBAC privilege escalation chains")
    p_rbac.add_argument("--input", "-i", required=True, help="Path to Kubernetes manifest")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "scan":
        return handle_scan(args)
    elif args.command == "remediate":
        return handle_remediate(args)
    elif args.command == "rbac":
        return handle_rbac(args)

    return 0


if __name__ == "__main__":
    sys.exit(main())
