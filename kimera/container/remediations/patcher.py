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

import os
import subprocess
from typing import Any

from ..core.k8s_client import K8sClient
from ..core.logger import SecurityLogger
from ..make_vulnerable.base import BaseExploit
from ..make_vulnerable.privileged_containers import PrivilegedContainersExploit


class SecurityPatcher:
    """Handles security patching operations."""

    def __init__(self, k8s_client: K8sClient, logger: SecurityLogger):
        """Initialize SecurityPatcher with Kubernetes client and logger."""
        self.k8s = k8s_client
        self.logger = logger

    def apply_all_remediations(
        self,
        exploit_mappings: dict[str, str],
        exploit_classes: dict[str, type[BaseExploit]],
        dry_run: bool = False,
    ) -> None:
        """Apply all security remediations."""
        self.logger.secure("Applying comprehensive security remediations...")
        for exploit_type, service in exploit_mappings.items():
            if exploit_type in exploit_classes:
                self.logger.secure(f"Applying security fix for {exploit_type} on {service}...")
                exploit_class = exploit_classes[exploit_type]
                exploit = exploit_class(self.k8s, service, self.logger)
                exploit.make_secure(dry_run=dry_run)
        if not dry_run:
            self.logger.secure("All security remediations applied!")

    def secure_service(self, service: str, dry_run: bool = False, timeout: int = 120) -> bool:
        """Remove all vulnerabilities from a service."""
        self.logger.info(f"Securing {service}...")
        patches = self._get_secure_patches()
        self._ensure_security_context(service)
        if self.k8s.patch_deployment(service, patches, dry_run):
            if not dry_run:
                self.logger.success(f"Successfully secured {service}")
                self.k8s.wait_for_rollout(service, timeout)
            return True
        return False

    def prepare_offline(self, output_dir: str = "offline-resources") -> None:
        """Prepare resources for offline environments."""
        self.logger.info("Preparing resources for offline use...")
        os.makedirs(output_dir, exist_ok=True)
        # Save manifests
        manifests = {
            "unguard": "https://raw.githubusercontent.com/dynatrace-oss/unguard/main/chart/unguard/values.yaml"
        }
        for name, url in manifests.items():
            self.logger.info(f"Downloading manifest for {name}...")
            manifest_path = os.path.join(output_dir, f"{name}.yaml")
            try:
                subprocess.run(["curl", "-o", manifest_path, url], check=True)
                self.logger.success(f"Saved {name} manifest to {manifest_path}")
            except subprocess.CalledProcessError:
                self.logger.error(f"Failed to download manifest for {name}")
        # Pull container images
        images = ["ghcr.io/dynatrace-oss/unguard:v1.0.0"]
        for image in images:
            self.logger.info(f"Pulling container image: {image}...")
            try:
                subprocess.run(["docker", "pull", image], check=True)
                self.logger.success(f"Pulled image: {image}")
                subprocess.run(
                    [
                        "docker",
                        "save",
                        "-o",
                        os.path.join(output_dir, f"{image.replace('/', '_')}.tar"),
                        image,
                    ],
                    check=True,
                )
                self.logger.success(f"Saved image {image} to {output_dir}")
            except subprocess.CalledProcessError:
                self.logger.error(f"Failed to pull or save image: {image}")

    def rollback_service(self, service: str, namespace: str, timeout: int = 120) -> bool:
        """Rollback a service to the previous revision."""
        self.logger.info(f"Rolling back {service}...")
        if not self.k8s.deployment_exists(service, namespace):
            self.logger.error(f"Deployment {service} not found")
            return False
        if self.k8s.rollback_deployment(service):
            self.k8s.wait_for_rollout(service, timeout)
            self.logger.success(f"Rolled back {service}")
            return True
        self.logger.error(f"Failed to rollback {service}")
        return False

    def cleanup_services(
        self, services: list[str], namespace: str, action: str = "rollback"
    ) -> None:
        """Perform cleanup actions on services."""
        self.logger.info(f"Starting cleanup with action: {action}")
        for service in services:
            if action == "rollback":
                self.rollback_service(service, namespace)
            elif action == "delete":
                self.k8s.delete_deployment(service, namespace)
            else:
                self.logger.error(f"Unknown cleanup action: {action}")
        self.logger.info("Cleanup completed.")

    def _ensure_security_context(self, service: str) -> None:
        """Ensure security context exists for all containers in a deployment."""
        deployment = self.k8s.get_deployment(service)
        if not deployment:
            return
        for idx, container in enumerate(deployment.spec.template.spec.containers):
            if not hasattr(container, "security_context") or not container.security_context:
                self.k8s.patch_deployment(
                    service,
                    [
                        {
                            "op": "add",
                            "path": f"/spec/template/spec/containers/{idx}/securityContext",
                            "value": {},
                        }
                    ],
                )
            if (
                container.security_context
                and container.security_context.allow_privilege_escalation is None
            ):
                self.k8s.patch_deployment(
                    service,
                    [
                        {
                            "op": "add",
                            "path": f"/spec/template/spec/containers/{idx}/securityContext/allowPrivilegeEscalation",
                            "value": False,
                        }
                    ],
                )

    def _validate_namespace(self, namespace: str) -> bool:
        """Validate if the namespace exists."""
        if not self.k8s.namespace_exists(namespace):
            self.logger.error(f"Namespace {namespace} does not exist")
            return False
        return True

    def _validate_patch(self, patch: list[dict[str, Any]] | None) -> bool:
        """Validate the patch structure."""
        try:
            if patch is None:
                return False

            for operation in patch:
                if not isinstance(operation, dict):
                    raise ValueError(f"Invalid patch operation type: {type(operation)}")
                if not all(key in operation for key in ["op", "path"]):
                    raise ValueError(f"Invalid patch operation: {operation}")
            return True
        except Exception as e:
            self.logger.error(f"Invalid patch: {e}")
            return False

    def _get_secure_patches(self) -> list[dict[str, Any]]:
        """Get secure patches using a representative exploit class."""
        dummy_exploit = PrivilegedContainersExploit(self.k8s, "dummy", self.logger)
        return dummy_exploit.get_secure_patch()
