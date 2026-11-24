"""
RBAC Bipartite Graph Engine for KubeSentinel.
Traces Subject-to-Role bindings, resolves effective permissions, and models privilege reachability.
"""

from kube_sentinel.core.models import PolicyRule, RBACBinding, RBACRole, RBACSubject


class RBACGraphEngine:
    """Models subjects, bindings, and roles into a queryable graph of Kubernetes permissions."""

    def __init__(self, roles: list[RBACRole], bindings: list[RBACBinding]):
        self.roles_map: dict[str, RBACRole] = {f"{r.kind}/{r.name}": r for r in roles}
        self.bindings: list[RBACBinding] = bindings
        self.subject_to_roles: dict[str, list[RBACRole]] = {}
        self._build_graph()

    def _build_graph(self):
        for b in self.bindings:
            role_key = f"{b.role_kind}/{b.role_name}"
            role = self.roles_map.get(role_key)
            if not role:
                # If role definition is external (e.g. built-in cluster-admin), create stub
                role = RBACRole(kind=b.role_kind, name=b.role_name, namespace=b.namespace)

            for subj in b.subjects:
                subj_key = f"{subj.kind}/{subj.namespace}/{subj.name}" if subj.namespace else f"{subj.kind}/{subj.name}"
                self.subject_to_roles.setdefault(subj_key, []).append(role)

    def get_effective_rules(self, subject: RBACSubject) -> list[PolicyRule]:
        """Returns all aggregated policy rules granted to a subject."""
        subj_key = f"{subject.kind}/{subject.namespace}/{subject.name}" if subject.namespace else f"{subject.kind}/{subject.name}"
        roles = self.subject_to_roles.get(subj_key, [])
        all_rules: list[PolicyRule] = []
        for r in roles:
            all_rules.extend(r.rules)
        return all_rules

    def get_all_bound_subjects(self) -> list[tuple[str, list[RBACRole]]]:
        """Returns (subject_key, list_of_roles)."""
        return list(self.subject_to_roles.items())
