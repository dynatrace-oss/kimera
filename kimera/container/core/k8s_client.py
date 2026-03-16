#
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
#

import json
import subprocess
import sys
import time
from typing import Any

import jsonpatch
from kubernetes import client, config
from kubernetes.client import V1DaemonSet, V1Deployment, V1NetworkPolicy, V1Pod
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

from kimera.container.core.exceptions import K8sError

from .logger import SecurityLogger, setup_logger


class K8sClient:
    """Wrapper for Kubernetes client operations."""

    def __init__(
        self,
        namespace: str = "default",
        logger: SecurityLogger | None = None,
        verbose: bool = False,
    ):
        """Initialize Kubernetes client with specified namespace and logger."""
        self.namespace = namespace
        self.logger = logger or SecurityLogger(setup_logger(__name__))
        self.verbose = verbose

        # Initialize Kubernetes client
        try:
            config.load_incluster_config()
        except config.ConfigException:
            try:
                config.load_kube_config()
            except config.ConfigException as e:
                raise K8sError("Cannot connect to Kubernetes cluster") from e

        self.v1 = client.CoreV1Api()
        self.apps_v1 = client.AppsV1Api()
        self.networking_v1 = client.NetworkingV1Api()
        self.rbac_v1 = client.RbacAuthorizationV1Api()

    def get_deployment(self, name: str) -> V1Deployment | None:
        """Get a deployment by name."""
        try:
            deployment = self.apps_v1.read_namespaced_deployment(name, self.namespace)
            return deployment
        except ApiException as e:
            if e.status == 404:
                return None
            raise K8sError(f"Failed to get deployment {name}: {e}") from e

    def find_pod_for_service(self, service: str) -> str | None:
        """Find running pod for a service."""
        strategies = [
            # Strategy 1: Label app.kubernetes.io/name
            {"app.kubernetes.io/name": service.replace("unguard-", "")},
            # Strategy 2: Label app
            {"app": service},
            {"app": service.replace("unguard-", "")},
            # Strategy 3: Other common patterns
            {"component": service.replace("unguard-", "")},
            {"service": service},
            {"name": service},
        ]

        for labels in strategies:
            pods = self._get_pods_by_labels(labels)
            if pods:
                return str(pods[0].metadata.name)

        # Strategy 4: Name prefix
        try:
            all_pods = self.v1.list_namespaced_pod(self.namespace)
            for pod in all_pods.items:
                if pod.metadata.name.startswith(service) and pod.status.phase == "Running":
                    return str(pod.metadata.name)
        except ApiException:
            pass

        return None

    def _get_pods_by_labels(self, labels: dict[str, str]) -> list[V1Pod]:
        """Get pods by label selector."""
        label_selector = ",".join(f"{k}={v}" for k, v in labels.items())
        try:
            pod_list = self.v1.list_namespaced_pod(self.namespace, label_selector=label_selector)
            return [p for p in pod_list.items if p.status.phase == "Running"]
        except ApiException:
            return []

    def exec_in_pod(self, pod_name: str, command: str, container: str | None = None) -> str:
        """Execute command in pod."""
        try:
            pod = self.v1.read_namespaced_pod(pod_name, self.namespace)
            container_names = [c.name for c in pod.spec.containers]

            if not container and len(container_names) > 1:
                self.logger.warning(
                    "Multiple containers found. Using the first container by default."
                )

            exec_command = ["/bin/sh", "-c", command]
            kwargs = {
                "name": pod_name,
                "namespace": self.namespace,
                "command": exec_command,
                "stderr": True,
                "stdin": False,
                "stdout": True,
                "tty": False,
                "_preload_content": False,
            }

            if container:
                kwargs["container"] = container
            elif len(container_names) > 1:
                kwargs["container"] = container_names[0]

            resp = stream(self.v1.connect_get_namespaced_pod_exec, **kwargs)
            output = ""

            # Fix: Properly handle stream output
            while resp.is_open():
                resp.update(timeout=1)
                if resp.peek_stdout():
                    data = resp.read_stdout()
                    output += data
                    # Print output in real-time if verbose
                    if self.verbose:
                        print(data, end="")
                if resp.peek_stderr():
                    data = resp.read_stderr()
                    output += data
                    if self.verbose:
                        print(data, end="", file=sys.stderr)

            resp.close()
            return output.strip()  # Fix: Strip trailing whitespace
        except ApiException as e:
            raise K8sError(f"Failed to exec in pod {pod_name}: {e}") from e

    def patch_deployment(
        self, name: str, patches: list[dict[str, Any]], dry_run: bool = False
    ) -> bool:
        """Apply JSON patch to deployment with verbose logging."""
        try:
            # Get current deployment
            deployment = self.get_deployment(name)
            if not deployment:
                raise K8sError(f"Deployment {name} not found")

            deployment_dict = client.ApiClient().sanitize_for_serialization(deployment)

            if self.verbose:
                self.logger.info(f"Current deployment state for {name}:")
                self._log_deployment_security_context(deployment_dict)

            if self.verbose or dry_run:
                self.logger.info(f"Patches to be applied to {name}:")
                for patch in patches:
                    self.logger.info(f"  {json.dumps(patch, indent=2)}")

            try:
                patched = jsonpatch.apply_patch(deployment_dict, patches)
            except jsonpatch.JsonPatchException as e:
                self.logger.error(f"Patch validation failed: {e}")
                return False

            if self.verbose:
                self.logger.info(f"Patched deployment state for {name}:")
                self._log_deployment_security_context(patched)

            if not dry_run:
                self.apps_v1.patch_namespaced_deployment(
                    name=name, namespace=self.namespace, body=patched
                )
                self.logger.success(f"Patched {name}")

                # Wait for rollout
                self.wait_for_rollout(name)
            else:
                self.logger.info(f"DRY RUN: Would patch {name}")

            return True

        except ApiException as e:
            self.logger.error(f"Failed to patch {name}: {e}")
            return False

    def _log_deployment_security_context(self, deployment_dict: dict[str, Any]) -> None:
        """Log security-relevant parts of deployment."""
        try:
            spec = deployment_dict.get("spec", {}).get("template", {}).get("spec", {})

            self.logger.info("  Pod-level security:")
            self.logger.info(f"    hostPID: {spec.get('hostPID', False)}")
            self.logger.info(f"    hostNetwork: {spec.get('hostNetwork', False)}")
            self.logger.info(f"    hostIPC: {spec.get('hostIPC', False)}")

            containers = spec.get("containers", [])
            for i, container in enumerate(containers):
                self.logger.info(f"  Container {i} ({container.get('name', 'unnamed')}):")
                sec_ctx = container.get("securityContext", {})
                if sec_ctx:
                    self.logger.info(f"    privileged: {sec_ctx.get('privileged', False)}")
                    self.logger.info(f"    runAsNonRoot: {sec_ctx.get('runAsNonRoot', 'not set')}")
                    self.logger.info(f"    runAsUser: {sec_ctx.get('runAsUser', 'not set')}")
                    self.logger.info(
                        f"    allowPrivilegeEscalation: {sec_ctx.get('allowPrivilegeEscalation', 'not set')}"
                    )
                    caps = sec_ctx.get("capabilities", {})
                    if caps:
                        self.logger.info(f"    capabilities.add: {caps.get('add', [])}")
                        self.logger.info(f"    capabilities.drop: {caps.get('drop', [])}")
                else:
                    self.logger.info("    No security context defined")

                resources = container.get("resources", {})
                if resources:
                    limits = resources.get("limits", {})
                    requests = resources.get("requests", {})
                    self.logger.info(f"    resources.limits: {limits}")
                    self.logger.info(f"    resources.requests: {requests}")
                else:
                    self.logger.info("    No resource limits defined")
        except Exception as e:
            self.logger.error(f"Error logging deployment state: {e}")

    def wait_for_rollout(self, deployment_name: str, timeout: int = 120) -> bool:
        """Wait for deployment rollout to complete."""
        self.logger.info(f"Waiting for {deployment_name} rollout...")
        start_time = time.time()

        while time.time() - start_time < timeout:
            deployment = self.get_deployment(deployment_name)
            if not deployment:
                return False

            if deployment.status:
                updated = deployment.status.updated_replicas or 0
                ready = deployment.status.ready_replicas or 0
            else:
                updated = 0
                ready = 0

            replicas = deployment.spec.replicas or 0

            if updated == replicas and ready == replicas and replicas > 0:
                self.logger.success(f"{deployment_name} rollout complete")
                return True

            time.sleep(5)

        self.logger.warning(f"Timeout waiting for {deployment_name} rollout")
        return False

    def rollback_deployment(self, name: str, revision: int | None = None) -> bool:
        """Rollback deployment to previous or specific revision."""
        try:
            cmd = [
                "kubectl",
                "rollout",
                "undo",
                f"deployment/{name}",
                "-n",
                self.namespace,
            ]
            if revision:
                cmd.extend(["--to-revision", str(revision)])
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                self.logger.success(f"Rolled back {name} to revision {revision or 'previous'}.")
                return True
            else:
                self.logger.error(f"Failed to rollback {name}: {result.stderr}")
                return False
        except Exception as e:
            self.logger.error(f"Error during rollback: {e}")
            return False

    def deployment_exists(self, name: str, namespace: str | None = None) -> bool:
        """Check if a deployment exists in the specified namespace."""
        ns = namespace or self.namespace
        try:
            self.apps_v1.read_namespaced_deployment(name, ns)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise K8sError(f"Failed to check deployment {name}: {e}") from e

    def delete_deployment(self, name: str, namespace: str | None = None) -> bool:
        """Delete a deployment."""
        ns = namespace or self.namespace
        try:
            self.apps_v1.delete_namespaced_deployment(
                name=name, namespace=ns, body=client.V1DeleteOptions()
            )
            self.logger.success(f"Deleted deployment {name}")
            return True
        except ApiException as e:
            if e.status == 404:
                self.logger.warning(f"Deployment {name} not found")
                return False
            self.logger.error(f"Failed to delete deployment {name}: {e}")
            return False

    def namespace_exists(self, name: str) -> bool:
        """Check if a namespace exists."""
        try:
            self.v1.read_namespace(name)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise K8sError(f"Failed to check namespace {name}: {e}") from e

    def list_network_policies(self, namespace: str | None = None) -> list[V1NetworkPolicy]:
        """List all network policies in a namespace."""
        ns = namespace or self.namespace
        try:
            result = self.networking_v1.list_namespaced_network_policy(ns)
            return list(result.items)
        except ApiException as e:
            raise K8sError(f"Failed to list network policies in {ns}: {e}") from e

    def create_network_policy(
        self,
        body: dict[str, Any],
        namespace: str | None = None,
        dry_run: bool = False,
    ) -> bool:
        """Create a network policy from a dict body."""
        ns = namespace or self.namespace
        name = body.get("metadata", {}).get("name", "unknown")
        try:
            if dry_run:
                self.logger.info(f"DRY RUN: Would create NetworkPolicy {name} in {ns}")
                return True

            self.networking_v1.create_namespaced_network_policy(namespace=ns, body=body)
            self.logger.success(f"Created NetworkPolicy {name} in {ns}")
            return True
        except ApiException as e:
            if e.status == 409:
                self.logger.info(f"NetworkPolicy {name} already exists in {ns}")
                return True
            self.logger.error(f"Failed to create NetworkPolicy {name}: {e}")
            return False

    def delete_network_policy(self, name: str, namespace: str | None = None) -> bool:
        """Delete a network policy by name."""
        ns = namespace or self.namespace
        try:
            self.networking_v1.delete_namespaced_network_policy(name=name, namespace=ns)
            self.logger.success(f"Deleted NetworkPolicy {name} from {ns}")
            return True
        except ApiException as e:
            if e.status == 404:
                self.logger.info(f"NetworkPolicy {name} not found in {ns}")
                return True
            self.logger.error(f"Failed to delete NetworkPolicy {name}: {e}")
            return False

    def network_policy_exists(self, name: str, namespace: str | None = None) -> bool:
        """Check if a network policy exists."""
        ns = namespace or self.namespace
        try:
            self.networking_v1.read_namespaced_network_policy(name=name, namespace=ns)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise K8sError(f"Failed to check NetworkPolicy {name}: {e}") from e

    # --- DaemonSet operations ---

    def get_daemonset(self, name: str, namespace: str | None = None) -> V1DaemonSet | None:
        """Get a DaemonSet by name."""
        ns = namespace or self.namespace
        try:
            return self.apps_v1.read_namespaced_daemon_set(name, ns)
        except ApiException as e:
            if e.status == 404:
                return None
            raise K8sError(f"Failed to get DaemonSet {name}: {e}") from e

    def create_daemonset(
        self,
        body: dict[str, Any],
        namespace: str | None = None,
        dry_run: bool = False,
    ) -> bool:
        """Create a DaemonSet from a dict body."""
        ns = namespace or self.namespace
        name = body.get("metadata", {}).get("name", "unknown")
        try:
            if dry_run:
                self.logger.info(f"DRY RUN: Would create DaemonSet {name} in {ns}")
                return True
            self.apps_v1.create_namespaced_daemon_set(namespace=ns, body=body)
            self.logger.success(f"Created DaemonSet {name} in {ns}")
            return True
        except ApiException as e:
            if e.status == 409:
                self.logger.info(f"DaemonSet {name} already exists in {ns}")
                return True
            self.logger.error(f"Failed to create DaemonSet {name}: {e}")
            return False

    def delete_daemonset(self, name: str, namespace: str | None = None) -> bool:
        """Delete a DaemonSet by name."""
        ns = namespace or self.namespace
        try:
            self.apps_v1.delete_namespaced_daemon_set(name=name, namespace=ns)
            self.logger.success(f"Deleted DaemonSet {name} from {ns}")
            return True
        except ApiException as e:
            if e.status == 404:
                self.logger.info(f"DaemonSet {name} not found in {ns}")
                return True
            self.logger.error(f"Failed to delete DaemonSet {name}: {e}")
            return False

    def daemonset_exists(self, name: str, namespace: str | None = None) -> bool:
        """Check if a DaemonSet exists."""
        ns = namespace or self.namespace
        try:
            self.apps_v1.read_namespaced_daemon_set(name, ns)
            return True
        except ApiException as e:
            if e.status == 404:
                return False
            raise K8sError(f"Failed to check DaemonSet {name}: {e}") from e

    def wait_for_daemonset(
        self, name: str, namespace: str | None = None, timeout: int = 120
    ) -> bool:
        """Wait for all DaemonSet pods to be ready."""
        ns = namespace or self.namespace
        self.logger.info(f"Waiting for DaemonSet {name} to be ready...")
        start_time = time.time()

        while time.time() - start_time < timeout:
            ds = self.get_daemonset(name, ns)
            if not ds or not ds.status:
                time.sleep(5)
                continue

            desired = ds.status.desired_number_scheduled or 0
            ready = ds.status.number_ready or 0

            if desired > 0 and ready == desired:
                self.logger.success(f"DaemonSet {name} ready ({ready}/{desired} pods)")
                return True

            time.sleep(5)

        self.logger.warning(f"Timeout waiting for DaemonSet {name}")
        return False

    # --- ServiceAccount operations ---

    def create_service_account(
        self,
        body: dict[str, Any],
        namespace: str | None = None,
        dry_run: bool = False,
    ) -> bool:
        """Create a ServiceAccount from a dict body."""
        ns = namespace or self.namespace
        name = body.get("metadata", {}).get("name", "unknown")
        try:
            if dry_run:
                self.logger.info(f"DRY RUN: Would create ServiceAccount {name} in {ns}")
                return True
            self.v1.create_namespaced_service_account(namespace=ns, body=body)
            self.logger.success(f"Created ServiceAccount {name} in {ns}")
            return True
        except ApiException as e:
            if e.status == 409:
                self.logger.info(f"ServiceAccount {name} already exists in {ns}")
                return True
            self.logger.error(f"Failed to create ServiceAccount {name}: {e}")
            return False

    def delete_service_account(self, name: str, namespace: str | None = None) -> bool:
        """Delete a ServiceAccount by name."""
        ns = namespace or self.namespace
        try:
            self.v1.delete_namespaced_service_account(name=name, namespace=ns)
            self.logger.success(f"Deleted ServiceAccount {name} from {ns}")
            return True
        except ApiException as e:
            if e.status == 404:
                self.logger.info(f"ServiceAccount {name} not found in {ns}")
                return True
            self.logger.error(f"Failed to delete ServiceAccount {name}: {e}")
            return False

    # --- ClusterRole operations ---

    def create_cluster_role(self, body: dict[str, Any], dry_run: bool = False) -> bool:
        """Create a ClusterRole from a dict body."""
        name = body.get("metadata", {}).get("name", "unknown")
        try:
            if dry_run:
                self.logger.info(f"DRY RUN: Would create ClusterRole {name}")
                return True
            self.rbac_v1.create_cluster_role(body=body)
            self.logger.success(f"Created ClusterRole {name}")
            return True
        except ApiException as e:
            if e.status == 409:
                self.logger.info(f"ClusterRole {name} already exists")
                return True
            self.logger.error(f"Failed to create ClusterRole {name}: {e}")
            return False

    def delete_cluster_role(self, name: str) -> bool:
        """Delete a ClusterRole by name."""
        try:
            self.rbac_v1.delete_cluster_role(name=name)
            self.logger.success(f"Deleted ClusterRole {name}")
            return True
        except ApiException as e:
            if e.status == 404:
                self.logger.info(f"ClusterRole {name} not found")
                return True
            self.logger.error(f"Failed to delete ClusterRole {name}: {e}")
            return False

    # --- ClusterRoleBinding operations ---

    def create_cluster_role_binding(self, body: dict[str, Any], dry_run: bool = False) -> bool:
        """Create a ClusterRoleBinding from a dict body."""
        name = body.get("metadata", {}).get("name", "unknown")
        try:
            if dry_run:
                self.logger.info(f"DRY RUN: Would create ClusterRoleBinding {name}")
                return True
            self.rbac_v1.create_cluster_role_binding(body=body)
            self.logger.success(f"Created ClusterRoleBinding {name}")
            return True
        except ApiException as e:
            if e.status == 409:
                self.logger.info(f"ClusterRoleBinding {name} already exists")
                return True
            self.logger.error(f"Failed to create ClusterRoleBinding {name}: {e}")
            return False

    def delete_cluster_role_binding(self, name: str) -> bool:
        """Delete a ClusterRoleBinding by name."""
        try:
            self.rbac_v1.delete_cluster_role_binding(name=name)
            self.logger.success(f"Deleted ClusterRoleBinding {name}")
            return True
        except ApiException as e:
            if e.status == 404:
                self.logger.info(f"ClusterRoleBinding {name} not found")
                return True
            self.logger.error(f"Failed to delete ClusterRoleBinding {name}: {e}")
            return False
