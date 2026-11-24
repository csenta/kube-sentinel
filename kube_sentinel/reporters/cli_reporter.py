"""
Console Summary Reporter for KubeSentinel.
"""

from kube_sentinel.core.models import AuditReport


class CLIReporter:
    """Outputs colored ASCII summaries of Kubernetes security posture audits."""

    @staticmethod
    def print_summary(report: AuditReport):
        print("\n" + "=" * 80)
        print("☸️  [KUBESENTINEL] KUBERNETES SECURITY POSTURE & RBAC AUDIT REPORT")
        print("=" * 80)
        print(f"  Target Manifest:         {report.manifest_name}")
        print(f"  Evaluated Resources:     {report.total_resources}")
        print(f"  Security Misconfigs:     {len(report.findings)}")
        print(f"  Remediation Patches:     {len(report.patches)}")

        score_color = "🟢" if report.security_score >= 80 else ("🟡" if report.security_score >= 50 else "🔴")
        print(f"  Cluster Security Score:  {score_color} {report.security_score}/100")
        print("-" * 80)

        if not report.findings:
            print("  ✅ All workloads and RBAC policies comply with PSS Restricted standard!")
        else:
            for idx, f in enumerate(report.findings, 1):
                badge = {
                    "CRITICAL": "💥 CRITICAL",
                    "HIGH": "🚨 HIGH    ",
                    "MEDIUM": "⚠️  MEDIUM  ",
                    "LOW": "ℹ️  LOW     ",
                }.get(f.severity, f.severity)
                res_display = f"{f.resource_kind}/{f.resource_name}"
                ns_display = f"ns:{f.namespace}" if f.namespace else "cluster-scope"

                print(f"[{idx:02d}] {badge} | {f.category.value:<16} | {res_display:<26} ({ns_display})")
                print(f"     Rule:        {f.rule_id}")
                print(f"     Issue:       {f.description}")
                print(f"     Remediation: {f.remediation_advice}")
                print()

        if report.patches:
            print("🔧 SYNTHESIZED HARDENED PATCHES READY:")
            for p in report.patches:
                print(f"  • {p.resource_kind}/{p.resource_name} ({p.namespace}): {len(p.modifications_made)} security enhancements applied.")

        print("=" * 80 + "\n")
