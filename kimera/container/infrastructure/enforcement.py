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

from typing import Any

from kimera.container.core.k8s_client import K8sClient
from kimera.container.core.logger import SecurityLogger, setup_logger

TOOLKIT_LABEL = "app.kubernetes.io/managed-by"
TOOLKIT_LABEL_VALUE = "kimera"

KUBE_ROUTER_NAMESPACE = "kube-system"
KUBE_ROUTER_NAME = "kube-router"
KUBE_ROUTER_IMAGE = "docker.io/cloudnativelabs/kube-router:v2.1.3"


class PolicyEnforcementManager:
    """Manages kube-router deployment for NetworkPolicy enforcement.

    Kube-router runs in firewall-only mode alongside existing CNI plugins
    like Flannel. It watches NetworkPolicy resources and translates them
    into iptables/ipsets rules without replacing pod networking.

    This is useful for clusters where the CNI does not enforce
    NetworkPolicies natively (e.g., Flannel with VXLAN).
    """

    def __init__(
        self,
        k8s_client: K8sClient,
        logger: SecurityLogger | None = None,
    ) -> None:
        """Initialize with a K8s client and optional logger."""
        self.k8s = k8s_client
        self.logger = logger or SecurityLogger(setup_logger(__name__))

    def enable(self, dry_run: bool = False) -> bool:
        """Install kube-router in firewall-only mode.

        Creates ServiceAccount, ClusterRole, ClusterRoleBinding, and
        DaemonSet in kube-system. All resources are labeled for safe cleanup.

        Returns True if all resources were created successfully.
        """
        self.logger.info("Installing kube-router for NetworkPolicy enforcement...")

        steps = [
            ("ServiceAccount", self._build_service_account(), self._create_sa),
            ("ClusterRole", self._build_cluster_role(), self._create_cr),
            ("ClusterRoleBinding", self._build_cluster_role_binding(), self._create_crb),
            ("DaemonSet", self._build_daemonset(), self._create_ds),
        ]

        for label, resource, create_fn in steps:
            if not create_fn(resource, dry_run):
                self.logger.error(f"Failed to create {label}")
                return False

        if not dry_run:
            self.k8s.wait_for_daemonset(KUBE_ROUTER_NAME, KUBE_ROUTER_NAMESPACE)
            self.logger.success("kube-router installed — NetworkPolicy enforcement active")

        return True

    def disable(self, dry_run: bool = False) -> bool:
        """Remove kube-router and all associated resources.

        Deletes in reverse order: DaemonSet, ClusterRoleBinding,
        ClusterRole, ServiceAccount. Each deletion is independent
        so partial failures don't block cleanup.

        Returns True if all resources were removed.
        """
        self.logger.info("Removing kube-router...")
        success = True

        if dry_run:
            self.logger.info("DRY RUN: Would remove kube-router and associated RBAC")
            return True

        if not self.k8s.delete_daemonset(KUBE_ROUTER_NAME, KUBE_ROUTER_NAMESPACE):
            success = False
        if not self.k8s.delete_cluster_role_binding(KUBE_ROUTER_NAME):
            success = False
        if not self.k8s.delete_cluster_role(KUBE_ROUTER_NAME):
            success = False
        if not self.k8s.delete_service_account(KUBE_ROUTER_NAME, KUBE_ROUTER_NAMESPACE):
            success = False

        if success:
            self.logger.success("kube-router removed — NetworkPolicy enforcement disabled")
        else:
            self.logger.warning("Some resources could not be removed; check manually")

        return success

    def is_enabled(self) -> bool:
        """Check if kube-router is running with ready pods."""
        ds = self.k8s.get_daemonset(KUBE_ROUTER_NAME, KUBE_ROUTER_NAMESPACE)
        if not ds or not ds.status:
            return False
        desired = ds.status.desired_number_scheduled or 0
        ready = ds.status.number_ready or 0
        return desired > 0 and ready == desired

    def get_status(self) -> dict[str, Any]:
        """Return detailed kube-router status."""
        ds = self.k8s.get_daemonset(KUBE_ROUTER_NAME, KUBE_ROUTER_NAMESPACE)
        if not ds or not ds.status:
            return {"installed": False}

        return {
            "installed": True,
            "desired": ds.status.desired_number_scheduled or 0,
            "ready": ds.status.number_ready or 0,
            "available": ds.status.number_available or 0,
            "image": KUBE_ROUTER_IMAGE,
        }

    # --- Resource creation helpers ---

    def _create_sa(self, body: dict[str, Any], dry_run: bool) -> bool:
        return self.k8s.create_service_account(body, KUBE_ROUTER_NAMESPACE, dry_run)

    def _create_cr(self, body: dict[str, Any], dry_run: bool) -> bool:
        return self.k8s.create_cluster_role(body, dry_run)

    def _create_crb(self, body: dict[str, Any], dry_run: bool) -> bool:
        return self.k8s.create_cluster_role_binding(body, dry_run)

    def _create_ds(self, body: dict[str, Any], dry_run: bool) -> bool:
        return self.k8s.create_daemonset(body, KUBE_ROUTER_NAMESPACE, dry_run)

    # --- Manifest builders ---

    def _build_service_account(self) -> dict[str, Any]:
        """Build ServiceAccount for kube-router."""
        return {
            "apiVersion": "v1",
            "kind": "ServiceAccount",
            "metadata": {
                "name": KUBE_ROUTER_NAME,
                "namespace": KUBE_ROUTER_NAMESPACE,
                "labels": _common_labels(),
            },
        }

    def _build_cluster_role(self) -> dict[str, Any]:
        """Build ClusterRole with permissions required by kube-router."""
        return {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {
                "name": KUBE_ROUTER_NAME,
                "labels": _common_labels(),
            },
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": ["namespaces", "pods", "services", "nodes", "endpoints"],
                    "verbs": ["list", "get", "watch"],
                },
                {
                    "apiGroups": ["networking.k8s.io"],
                    "resources": ["networkpolicies"],
                    "verbs": ["list", "get", "watch"],
                },
                {
                    "apiGroups": ["extensions"],
                    "resources": ["networkpolicies"],
                    "verbs": ["list", "get", "watch"],
                },
                {
                    "apiGroups": ["discovery.k8s.io"],
                    "resources": ["endpointslices"],
                    "verbs": ["list", "get", "watch"],
                },
            ],
        }

    def _build_cluster_role_binding(self) -> dict[str, Any]:
        """Build ClusterRoleBinding linking the SA to the ClusterRole."""
        return {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {
                "name": KUBE_ROUTER_NAME,
                "labels": _common_labels(),
            },
            "roleRef": {
                "apiGroup": "rbac.authorization.k8s.io",
                "kind": "ClusterRole",
                "name": KUBE_ROUTER_NAME,
            },
            "subjects": [
                {
                    "kind": "ServiceAccount",
                    "name": KUBE_ROUTER_NAME,
                    "namespace": KUBE_ROUTER_NAMESPACE,
                },
            ],
        }

    def _build_daemonset(self) -> dict[str, Any]:
        """Build kube-router DaemonSet in firewall-only mode."""
        return {
            "apiVersion": "apps/v1",
            "kind": "DaemonSet",
            "metadata": {
                "name": KUBE_ROUTER_NAME,
                "namespace": KUBE_ROUTER_NAMESPACE,
                "labels": _common_labels(),
            },
            "spec": {
                "selector": {
                    "matchLabels": {"k8s-app": KUBE_ROUTER_NAME},
                },
                "template": {
                    "metadata": {
                        "labels": {
                            "k8s-app": KUBE_ROUTER_NAME,
                            **_common_labels(),
                        },
                    },
                    "spec": {
                        "priorityClassName": "system-node-critical",
                        "serviceAccountName": KUBE_ROUTER_NAME,
                        "hostNetwork": True,
                        "tolerations": [
                            {"operator": "Exists", "effect": "NoSchedule"},
                            {"key": "CriticalAddonsOnly", "operator": "Exists"},
                            {"operator": "Exists", "effect": "NoExecute"},
                        ],
                        "containers": [
                            {
                                "name": KUBE_ROUTER_NAME,
                                "image": KUBE_ROUTER_IMAGE,
                                "args": [
                                    "--run-router=false",
                                    "--run-firewall=true",
                                    "--run-service-proxy=false",
                                ],
                                "securityContext": {"privileged": True},
                                "env": [
                                    {
                                        "name": "NODE_NAME",
                                        "valueFrom": {
                                            "fieldRef": {"fieldPath": "spec.nodeName"},
                                        },
                                    },
                                ],
                                "resources": {
                                    "requests": {"cpu": "100m", "memory": "128Mi"},
                                    "limits": {"cpu": "250m", "memory": "256Mi"},
                                },
                                "livenessProbe": {
                                    "httpGet": {"path": "/healthz", "port": 20244},
                                    "initialDelaySeconds": 10,
                                    "periodSeconds": 3,
                                },
                                "volumeMounts": [
                                    {
                                        "name": "lib-modules",
                                        "mountPath": "/lib/modules",
                                        "readOnly": True,
                                    },
                                    {
                                        "name": "xtables-lock",
                                        "mountPath": "/run/xtables.lock",
                                    },
                                ],
                            },
                        ],
                        "volumes": [
                            {
                                "name": "lib-modules",
                                "hostPath": {"path": "/lib/modules"},
                            },
                            {
                                "name": "xtables-lock",
                                "hostPath": {
                                    "path": "/run/xtables.lock",
                                    "type": "FileOrCreate",
                                },
                            },
                        ],
                    },
                },
            },
        }


def _common_labels() -> dict[str, str]:
    """Labels applied to all kube-router resources for identification and cleanup."""
    return {
        TOOLKIT_LABEL: TOOLKIT_LABEL_VALUE,
        "app.kubernetes.io/name": "kube-router",
        "app.kubernetes.io/component": "network-policy-enforcement",
    }
