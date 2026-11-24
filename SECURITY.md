# Security Policy

## Security Model

KubeSentinel is a defensive static analysis platform designed to identify misconfigurations in Kubernetes infrastructure.

### Safe by Design
- **Read-Only Analysis**: Performs offline static analysis on manifests without executing code or calling cluster APIs unauthenticated.
- **Air-Gapped Operation**: Does not send manifests, secrets, or cluster metadata to external networks.

## Reporting a Vulnerability

If you identify a security defect in KubeSentinel:
1. Do not open public GitHub issues.
2. Submit details to the repository maintainers through private GitHub security advisories.
