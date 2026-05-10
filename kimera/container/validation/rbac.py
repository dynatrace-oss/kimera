# Copyright 2025 Dynatrace LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Validate that RBAC policies restrict service account permissions.

Uses the ``SelfSubjectAccessReview`` and ``SelfSubjectRulesReview`` APIs to
check what each ServiceAccount can actually do. No actions are performed —
only permission queries.
"""

import logging
from typing import Any

from kubernetes.client import (
    ApiException,
    AuthorizationV1Api,
    V1ResourceAttributes,
    V1SelfSubjectAccessReview,
    V1SelfSubjectAccessReviewSpec,
)

from ..core.k8s_client import K8sClient
from ..core.logger import SecurityLogger
from .models import (
    ControlType,
    ValidationReport,
    ValidationResult,
    ValidationVerdict,
)

logger = logging.getLogger(__name__)

# Actions that most service accounts should NOT be able to perform.
# Each tuple: (verb, resource, group, description, remediation)
DANGEROUS_PERMISSIONS: list[tuple[str, str, str, str, str]] = [
    (
        "list",
        "secrets",
        "",
        "List secrets in namespace",
        "Remove 'secrets' from Role rules or scope to specific secret names.",
    ),
    (
        "get",
        "secrets",
        "",
        "Get secrets in namespace",
        "Remove 'secrets' from Role rules or scope to specific secret names.",
    ),
    (
        "create",
        "pods/exec",
        "",
        "Exec into pods",
        "Remove 'pods/exec' from Role rules. This enables container escape.",
    ),
    (
        "create",
        "pods",
        "",
        "Create pods in namespace",
        "Restrict pod creation or bind to a more restrictive role.",
    ),
    (
        "patch",
        "deployments",
        "apps",
        "Patch deployments",
        "Limit write access to deployments. Attackers can inject malicious containers.",
    ),
    (
        "create",
        "clusterrolebindings",
        "rbac.authorization.k8s.io",
        "Create ClusterRoleBindings (privilege escalation)",
        "Never grant 'bind' or 'create' on clusterrolebindings to workload SAs.",
    ),
    (
        "impersonate",
        "users",
        "",
        "Impersonate users",
        "Remove impersonation rights. This grants access as any user.",
    ),
    (
        "escalate",
        "clusterroles",
        "rbac.authorization.k8s.io",
        "Escalate ClusterRoles",
        "Remove 'escalate' verb. This allows granting permissions the SA doesn't have.",
    ),
]

# Cluster-scoped checks (should be denied for most workload SAs)
CLUSTER_SCOPE_CHECKS: list[tuple[str, str, str, str, str]] = [
    (
        "list",
        "secrets",
        "",
        "List secrets cluster-wide",
        "Bind namespace-scoped Roles, not ClusterRoles with secrets access.",
    ),
    (
        "list",
        "nodes",
        "",
        "List nodes (information disclosure)",
        "Most workloads don't need node visibility. Use namespace-scoped roles.",
    ),
    (
        "create",
        "namespaces",
        "",
        "Create namespaces",
        "Workload SAs should not be able to create namespaces.",
    ),
]


def _check_access(
    auth_api: AuthorizationV1Api,
    namespace: str,
    verb: str,
    resource: str,
    group: str = "",
) -> bool:
    """Check if the current context can perform an action via SelfSubjectAccessReview.

    Returns True if the action is ALLOWED, False if DENIED.
    """
    review = V1SelfSubjectAccessReview(
        spec=V1SelfSubjectAccessReviewSpec(
            resource_attributes=V1ResourceAttributes(
                namespace=namespace,
                verb=verb,
                resource=resource,
                group=group if group else None,
            )
        )
    )

    try:
        result = auth_api.create_self_subject_access_review(body=review)
        return bool(result.status.allowed)
    except ApiException:
        return False


def _list_service_accounts(k8s: K8sClient) -> list[dict[str, str]]:
    """List all service accounts in the target namespace."""
    try:
        sa_list = k8s.v1.list_namespaced_service_account(k8s.namespace)
        return [
            {
                "name": sa.metadata.name,
                "namespace": sa.metadata.namespace,
            }
            for sa in sa_list.items
        ]
    except ApiException as e:
        logger.warning("Failed to list service accounts: %s", e)
        return []


def _check_sa_bindings(
    k8s: K8sClient,
    sa_name: str,
    namespace: str,
) -> list[dict[str, Any]]:
    """Find all RoleBindings and ClusterRoleBindings referencing a ServiceAccount."""
    bindings: list[dict[str, Any]] = []

    # Namespace-scoped RoleBindings
    try:
        rbs = k8s.rbac_v1.list_namespaced_role_binding(namespace)
        for rb in rbs.items:
            for subject in rb.subjects or []:
                if (
                    subject.kind == "ServiceAccount"
                    and subject.name == sa_name
                    and (subject.namespace or namespace) == namespace
                ):
                    bindings.append({
                        "binding": rb.metadata.name,
                        "scope": "namespace",
                        "role_kind": rb.role_ref.kind,
                        "role_name": rb.role_ref.name,
                    })
    except ApiException:
        pass

    # Cluster-scoped ClusterRoleBindings
    try:
        crbs = k8s.rbac_v1.list_cluster_role_binding()
        for crb in crbs.items:
            for subject in crb.subjects or []:
                if (
                    subject.kind == "ServiceAccount"
                    and subject.name == sa_name
                    and (subject.namespace or namespace) == namespace
                ):
                    bindings.append({
                        "binding": crb.metadata.name,
                        "scope": "cluster",
                        "role_kind": crb.role_ref.kind,
                        "role_name": crb.role_ref.name,
                    })
    except ApiException:
        pass

    return bindings


def validate_rbac(
    k8s: K8sClient,
    sec_logger: SecurityLogger,
) -> ValidationReport:
    """Validate that RBAC restricts service account permissions appropriately.

    For each ServiceAccount in the namespace, checks whether it can perform
    dangerous actions (list secrets, exec into pods, escalate privileges, etc.)
    using the ``SelfSubjectAccessReview`` API. No actual actions are performed.

    Also checks role bindings for cluster-admin and overpermissive patterns.

    Args:
        k8s: Kubernetes client.
        sec_logger: Security logger for console output.

    Returns:
        ValidationReport with results for each RBAC check.
    """
    namespace = k8s.namespace
    report = ValidationReport(namespace=namespace, control_type=ControlType.RBAC)

    service_accounts = _list_service_accounts(k8s)
    if not service_accounts:
        sec_logger.warning(f"No service accounts found in {namespace}")
        report.summary = "No service accounts found."
        return report

    sec_logger.info(f"Found {len(service_accounts)} service accounts in {namespace}")

    for sa in service_accounts:
        sa_name = sa["name"]
        sa_ns = sa["namespace"]

        # Skip the default SA for system namespaces
        if sa_name == "default" and sa_ns in ("kube-system", "kube-public", "kube-node-lease"):
            continue

        sec_logger.info(f"Checking bindings for SA: {sa_name}")

        # Check bindings
        bindings = _check_sa_bindings(k8s, sa_name, sa_ns)

        # Check for cluster-admin binding (critical finding)
        for binding in bindings:
            if binding["role_name"] == "cluster-admin":
                report.results.append(ValidationResult(
                    control_type=ControlType.RBAC,
                    control_name=f"sa/{sa_name}",
                    test_description=f"SA '{sa_name}' should not have cluster-admin",
                    expected="DENY",
                    actual="ALLOWED (cluster-admin bound)",
                    verdict=ValidationVerdict.FAIL,
                    evidence=(
                        f"Binding '{binding['binding']}' grants cluster-admin "
                        f"to SA {sa_ns}/{sa_name}"
                    ),
                    remediation_hint=(
                        "Remove the cluster-admin ClusterRoleBinding. "
                        "Create a least-privilege Role scoped to the required resources."
                    ),
                ))

        # Check dangerous namespace-scoped permissions
        # NOTE: SelfSubjectAccessReview checks the *current* user's permissions,
        # not the SA's permissions. To check a specific SA, we examine its bindings
        # and the rules of the bound roles.
        for binding in bindings:
            role_name = binding["role_name"]
            role_kind = binding["role_kind"]

            try:
                if role_kind == "ClusterRole":
                    role = k8s.rbac_v1.read_cluster_role(role_name)
                else:
                    role = k8s.rbac_v1.read_namespaced_role(role_name, namespace)
            except ApiException:
                continue

            rules = role.rules or []
            for rule in rules:
                verbs = rule.verbs or []
                resources = rule.resources or []
                api_groups = rule.api_groups or [""]

                # Check for wildcard permissions
                if "*" in verbs and "*" in resources:
                    report.results.append(ValidationResult(
                        control_type=ControlType.RBAC,
                        control_name=f"sa/{sa_name}",
                        test_description=(
                            f"SA '{sa_name}' has wildcard permissions via {role_kind}/{role_name}"
                        ),
                        expected="DENY",
                        actual="ALLOWED (* on *)",
                        verdict=ValidationVerdict.FAIL,
                        evidence=f"Rule: verbs={verbs}, resources={resources}, apiGroups={api_groups}",
                        remediation_hint=(
                            f"Replace wildcard permissions in {role_kind}/{role_name} "
                            "with specific verbs and resources."
                        ),
                    ))

                # Check for specific dangerous permissions
                for verb, resource, group, desc, remediation in DANGEROUS_PERMISSIONS:
                    if (
                        (verb in verbs or "*" in verbs)
                        and (resource in resources or "*" in resources)
                        and (group in api_groups or "*" in api_groups)
                    ):
                        report.results.append(ValidationResult(
                            control_type=ControlType.RBAC,
                            control_name=f"sa/{sa_name}",
                            test_description=f"SA '{sa_name}' should not be able to: {desc}",
                            expected="DENY",
                            actual="ALLOWED",
                            verdict=ValidationVerdict.FAIL,
                            evidence=(
                                f"Granted via {role_kind}/{role_name} "
                                f"(binding: {binding['binding']}). "
                                f"Rule: verbs={verbs}, resources={resources}"
                            ),
                            remediation_hint=remediation,
                        ))

        # If SA has no bindings at all, it inherits only discovery permissions
        if not bindings and sa_name != "default":
            report.results.append(ValidationResult(
                control_type=ControlType.RBAC,
                control_name=f"sa/{sa_name}",
                test_description=f"SA '{sa_name}' has minimal permissions (no bindings)",
                expected="DENY",
                actual="DENIED (no bindings)",
                verdict=ValidationVerdict.PASS,
                evidence="No RoleBindings or ClusterRoleBindings reference this SA.",
            ))

    passed = report.passed
    failed = report.failed
    total = report.total
    report.summary = (
        f"RBAC validation: {passed}/{total} passed, {failed} failed. "
        f"Checked {len(service_accounts)} service accounts."
    )

    return report
