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

"""Exploit for overly permissive RBAC configuration.

Demonstrates the impact of granting excessive permissions to ServiceAccounts
by creating an overpermissive SA, binding it to a powerful role, and showing
what an attacker could do from a pod running as that SA.
"""

from typing import Any

from ...domain.models import ExploitResult
from ..core.journal import clear_operation, record_operation
from ..core.k8s_client import K8sClient
from ..core.logger import SecurityLogger, console
from .base import BaseExploit
from .test_loader import load_exploit_tests

# Resources created by this exploit (for cleanup)
_SA_NAME = "kimera-overpermissive-sa"
_ROLE_NAME = "kimera-overpermissive-role"
_BINDING_NAME = "kimera-overpermissive-binding"


class RBACExploit(BaseExploit):
    """Exploit demonstrating overpermissive RBAC configuration.

    Creates a ServiceAccount with broad permissions (list secrets, exec into pods,
    patch deployments) and demonstrates what an attacker can do with it.
    """

    name = "RBAC Abuse"
    risk_level = "CRITICAL"
    vulnerability_type = "rbac-abuse"
    description = """This exploit demonstrates the impact of overpermissive RBAC:

                - Service accounts with cluster-admin or broad roles
                - Ability to list and read secrets across the namespace
                - Ability to exec into other pods (container escape)
                - Ability to create/patch deployments (inject malicious containers)
                - Ability to access the Kubernetes API for lateral movement

                RBAC misconfigurations are the #1 real-world Kubernetes attack
                vector. A compromised pod with an overpermissive SA can escalate
                to full cluster compromise."""

    def __init__(
        self,
        k8s_client: K8sClient,
        service: str | None = None,
        logger: SecurityLogger | None = None,
    ) -> None:
        """Initialize RBAC exploit."""
        super().__init__(k8s_client, service, logger)
        self._created_resources: list[str] = []

    def get_vulnerable_patch(self) -> list[dict[str, Any]]:
        """Patch the deployment to use the overpermissive SA.

        Unlike container-level exploits, this also creates the SA, Role, and
        RoleBinding before patching the deployment.
        """
        return [
            {
                "op": "add",
                "path": "/spec/template/spec/serviceAccountName",
                "value": _SA_NAME,
            },
            {
                "op": "add",
                "path": "/spec/template/spec/automountServiceAccountToken",
                "value": True,
            },
        ]

    def make_vulnerable(self, dry_run: bool = False) -> bool:
        """Create overpermissive RBAC resources and patch the deployment."""
        namespace = self.k8s.namespace
        self.logger.info(f"Creating overpermissive RBAC resources in {namespace}...")

        # Create the ServiceAccount
        sa_body: dict[str, Any] = {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": _SA_NAME,
                "namespace": namespace,
                "labels": {"app.kubernetes.io/managed-by": "kimera"},
            },
        }

        # Create a Role with dangerous permissions
        role_body: dict[str, Any] = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {
                "name": _ROLE_NAME,
                "namespace": namespace,
                "labels": {"app.kubernetes.io/managed-by": "kimera"},
            },
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": ["secrets"],
                    "verbs": ["get", "list", "watch"],
                },
                {
                    "apiGroups": [""],
                    "resources": ["pods", "pods/exec", "pods/log"],
                    "verbs": ["get", "list", "create"],
                },
                {
                    "apiGroups": ["apps"],
                    "resources": ["deployments"],
                    "verbs": ["get", "list", "patch", "update"],
                },
                {
                    "apiGroups": [""],
                    "resources": ["configmaps", "services", "endpoints"],
                    "verbs": ["get", "list"],
                },
            ],
        }

        # Create RoleBinding
        binding_body: dict[str, Any] = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {
                "name": _BINDING_NAME,
                "namespace": namespace,
                "labels": {"app.kubernetes.io/managed-by": "kimera"},
            },
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "name": _SA_NAME,
                    "namespace": namespace,
                }
            ],
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "Role",
                "name": _ROLE_NAME,
            },
        }

        if dry_run:
            self.logger.info(f"DRY RUN: Would create SA {_SA_NAME}, Role {_ROLE_NAME}, "
                             f"RoleBinding {_BINDING_NAME}")
            return True

        # Create resources
        self.k8s.create_service_account(sa_body, namespace)
        self._created_resources.append(f"sa/{_SA_NAME}")

        # Create Role (need to use rbac API directly)
        try:
            self.k8s.rbac_v1.create_namespaced_role(namespace=namespace, body=role_body)
            self.logger.success(f"Created Role {_ROLE_NAME}")
            self._created_resources.append(f"role/{_ROLE_NAME}")
        except Exception as e:
            self.logger.error(f"Failed to create Role: {e}")

        try:
            self.k8s.rbac_v1.create_namespaced_role_binding(
                namespace=namespace, body=binding_body
            )
            self.logger.success(f"Created RoleBinding {_BINDING_NAME}")
            self._created_resources.append(f"rolebinding/{_BINDING_NAME}")
        except Exception as e:
            self.logger.error(f"Failed to create RoleBinding: {e}")

        # Patch deployment to use the overpermissive SA
        patches = self.get_vulnerable_patch()
        if self.k8s.patch_deployment(self.service, patches, dry_run=False):
            self.logger.success(
                f"Patched {self.service} to use SA {_SA_NAME}"
            )
            record_operation(
                "make_vulnerable", self.vulnerability_type, self.service, namespace
            )
            return True

        return False

    def check_vulnerability(self) -> bool:
        """Check if the service is using an overpermissive SA."""
        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return False

        try:
            pod = self.k8s.v1.read_namespaced_pod(pod_name, self.k8s.namespace)
            sa_name = pod.spec.service_account_name or "default"

            # Check if the SA has any RoleBindings with dangerous permissions
            namespace = self.k8s.namespace
            try:
                bindings = self.k8s.rbac_v1.list_namespaced_role_binding(namespace)
                for rb in bindings.items:
                    for subject in rb.subjects or []:
                        if (
                            subject.kind == "ServiceAccount"
                            and subject.name == sa_name
                        ):
                            role_name = rb.role_ref.name
                            try:
                                if rb.role_ref.kind == "ClusterRole":
                                    role = self.k8s.rbac_v1.read_cluster_role(role_name)
                                else:
                                    role = self.k8s.rbac_v1.read_namespaced_role(
                                        role_name, namespace
                                    )
                                for rule in role.rules or []:
                                    resources = rule.resources or []
                                    verbs = rule.verbs or []
                                    if "secrets" in resources and (
                                        "list" in verbs or "get" in verbs or "*" in verbs
                                    ):
                                        return True
                                    if "*" in resources and "*" in verbs:
                                        return True
                            except Exception:  # noqa: S110, S112
                                continue
            except Exception:  # noqa: S110
                pass

            return False

        except Exception as e:
            self.logger.error(f"Error checking RBAC for {self.service}: {e}")
            return False

    def demonstrate(self) -> ExploitResult:
        """Demonstrate RBAC abuse from inside a pod."""
        self.logger.exploit("Demonstrating RBAC abuse risks...")

        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return ExploitResult(success=False, message="Pod not found for service")

        tests, summary_impact = load_exploit_tests(self.vulnerability_type)
        result = self._run_tests(pod_name, tests, "RBAC abuse exploit demonstrated")

        self.logger.exploit("=== Impact Summary ===")
        for item in summary_impact:
            console.print(f"  • {item}")

        return result

    def revert(self, dry_run: bool = False) -> bool:
        """Revert RBAC changes: rollback deployment + delete created resources."""
        namespace = self.k8s.namespace

        if dry_run:
            self.logger.info(
                f"DRY RUN: Would rollback {self.service} and delete "
                f"SA/{_SA_NAME}, Role/{_ROLE_NAME}, RoleBinding/{_BINDING_NAME}"
            )
            return True

        # Rollback deployment first
        self.k8s.rollback_deployment(self.service)

        # Delete RBAC resources
        try:
            self.k8s.rbac_v1.delete_namespaced_role_binding(_BINDING_NAME, namespace)
            self.logger.success(f"Deleted RoleBinding {_BINDING_NAME}")
        except Exception:  # noqa: S110
            pass

        try:
            self.k8s.rbac_v1.delete_namespaced_role(_ROLE_NAME, namespace)
            self.logger.success(f"Deleted Role {_ROLE_NAME}")
        except Exception:  # noqa: S110
            pass

        self.k8s.delete_service_account(_SA_NAME, namespace)

        clear_operation(self.vulnerability_type, self.service, namespace)
        self.logger.success("RBAC exploit reverted")
        return True
