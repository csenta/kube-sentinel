# KubeSentinel Roadmap

## Phase 1: Ingestion & Topology Modeling (Completed)
- [x] Multi-document Kubernetes YAML and JSON stream parser.
- [x] Workload normalization (Deployment, DaemonSet, StatefulSet, Job, Pod).
- [x] Bipartite RBAC graph builder (Subjects $\leftrightarrow$ Bindings $\leftrightarrow$ Roles).

## Phase 2: Auditing & Threat Analysis (Completed)
- [x] Pod Security Standards (Restricted & Baseline) validation engine.
- [x] RBAC privilege escalation pathfinder (impersonation, bind/escalate, secret access, wildcard abuse).
- [x] Network policy ingress/egress isolation gap analyzer.
- [x] Automated least-privilege remediation patch synthesizer.

## Phase 3: Developer Experience & CI/CD (Completed)
- [x] CLI subcommands: `audit`, `rbac`, `remediate`, and `scan`.
- [x] Interactive HTML5 executive dashboard with dark mode and search.
- [x] Machine-readable JSON output and CI break-build gate (`--fail-on-severity`).
- [x] Multi-stage containerization and automated GitHub Actions verification.
