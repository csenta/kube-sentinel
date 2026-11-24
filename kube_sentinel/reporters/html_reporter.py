"""
Standalone Interactive HTML5 Dashboard Generator for KubeSentinel.
"""

import json
from kube_sentinel.core.models import AuditReport


class HTMLReporter:
    """Generates standalone visual security audit dashboard with dark mode styling."""

    @staticmethod
    def generate(report: AuditReport, title: str = "KubeSentinel Security Audit Dashboard") -> str:
        report_json = json.dumps(report.to_dict())

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{title}</title>
  <style>
    :root {{
      --bg: #0d1117;
      --card-bg: #161b22;
      --border: #30363d;
      --text: #c9d1d9;
      --text-bright: #f0f6fc;
      --text-muted: #8b949e;
      --critical: #f85149;
      --high: #db6d28;
      --medium: #d29922;
      --low: #58a6ff;
      --success: #3fb950;
      --accent: #388bfd;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; }}
    body {{ background: var(--bg); color: var(--text); padding: 2rem; }}
    .container {{ max-width: 1200px; margin: 0 auto; }}
    header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
    h1 {{ font-size: 1.8rem; font-weight: 700; color: #58a6ff; display: flex; align-items: center; gap: 0.5rem; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .stat-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 6px; padding: 1.25rem; }}
    .stat-title {{ color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; }}
    .stat-val {{ font-size: 2rem; font-weight: 700; margin-top: 0.4rem; }}
    .security-score {{ color: {("#3fb950" if report.security_score >= 80 else ("#d29922" if report.security_score >= 50 else "#f85149"))}; }}
    .section {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 6px; padding: 1.5rem; margin-bottom: 2rem; }}
    .section-title {{ font-size: 1.2rem; font-weight: 600; margin-bottom: 1rem; color: var(--text-bright); }}
    table {{ width: 100%; border-collapse: collapse; margin-top: 0.5rem; }}
    th, td {{ padding: 0.85rem; text-align: left; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
    th {{ color: var(--text-muted); font-weight: 600; text-transform: uppercase; font-size: 0.75rem; }}
    tr:hover {{ background: rgba(255, 255, 255, 0.02); }}
    .badge {{ display: inline-block; padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }}
    .badge-critical {{ background: rgba(248, 81, 73, 0.2); color: var(--critical); border: 1px solid var(--critical); }}
    .badge-high {{ background: rgba(219, 109, 40, 0.2); color: var(--high); border: 1px solid var(--high); }}
    .badge-medium {{ background: rgba(210, 153, 34, 0.2); color: var(--medium); border: 1px solid var(--medium); }}
    .badge-low {{ background: rgba(88, 166, 255, 0.2); color: var(--low); border: 1px solid var(--low); }}
    code {{ font-family: monospace; background: rgba(110, 118, 129, 0.2); padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.85rem; }}
    .remedy-box {{ font-size: 0.85rem; color: #7ee787; margin-top: 0.35rem; }}
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div>
        <h1>☸️ KubeSentinel Posture Audit</h1>
        <p style="color: var(--text-muted); margin-top: 0.25rem;">Kubernetes Security Posture Management & RBAC Privilege Escalation Graph</p>
      </div>
      <div style="font-size: 0.85rem; color: var(--text-muted);">
        Manifest: <strong>{report.manifest_name}</strong> | {report.timestamp}
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-title">Security Score</div>
        <div class="stat-val security-score">{report.security_score} / 100</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Resources Scanned</div>
        <div class="stat-val">{report.total_resources}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Misconfigurations</div>
        <div class="stat-val" style="color: {("#f85149" if report.findings else "#3fb950")};">{len(report.findings)}</div>
      </div>
      <div class="stat-card">
        <div class="stat-title">Remediation Patches</div>
        <div class="stat-val" style="color: var(--accent);">{len(report.patches)}</div>
      </div>
    </div>

    <!-- Findings Table -->
    <div class="section">
      <div class="section-title">
        <span>Security & RBAC Findings ({len(report.findings)})</span>
      </div>
      <table>
        <thead>
          <tr>
            <th>Severity</th>
            <th>Category</th>
            <th>Resource</th>
            <th>Namespace</th>
            <th>Description & Remediation</th>
          </tr>
        </thead>
        <tbody>
"""

        for f in report.findings:
            b_class = f"badge-{f.severity.lower()}"
            html += f"""          <tr>
            <td><span class="badge {b_class}">{f.severity}</span></td>
            <td><code>{f.category.value}</code></td>
            <td><strong>{f.resource_kind}</strong>/{f.resource_name}</td>
            <td><code>{f.namespace or 'cluster-scope'}</code></td>
            <td>
              <div>{f.description}</div>
              <div class="remedy-box"><strong>Fix:</strong> {f.remediation_advice}</div>
            </td>
          </tr>
"""

        if not report.findings:
            html += "<tr><td colspan='5' style='text-align: center; color: var(--success);'>✅ Cluster resources in full compliance!</td></tr>"

        html += f"""        </tbody>
      </table>
    </div>

    <!-- Patches Summary -->
    <div class="section">
      <div class="section-title">
        <span>Hardened Remediation Patches ({len(report.patches)})</span>
      </div>
      <ul>
"""
        for p in report.patches:
            html += f"""        <li style="margin-bottom: 0.75rem;">
          <strong>{p.resource_kind}/{p.resource_name}</strong> (ns: <code>{p.namespace}</code>)
          <ul style="margin-left: 1.5rem; margin-top: 0.25rem; font-size: 0.85rem; color: var(--text-muted);">
"""
            for mod in p.modifications_made:
                html += f"            <li>{mod}</li>\n"
            html += "          </ul>\n        </li>\n"

        if not report.patches:
            html += "<p style='color: var(--text-muted);'>No patches generated.</p>"

        html += f"""      </ul>
    </div>

  </div>
  <script>
    const reportData = {report_json};
    console.log("KubeSentinel Report Initialized:", reportData);
  </script>
</body>
</html>"""
        return html
