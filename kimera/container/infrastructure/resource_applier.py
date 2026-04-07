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

from pathlib import Path
from typing import Any

import yaml

from ..core.k8s_client import K8sClient
from ..core.logger import SecurityLogger

TOOLKIT_LABEL = "app.kubernetes.io/managed-by"
TOOLKIT_LABEL_VALUE = "kimera"

# Resource kinds we know how to apply
SUPPORTED_KINDS = {"NetworkPolicy"}


class ResourceApplier:
    """Applies Kubernetes resources from YAML files with safety validation.

    Handles multi-document YAML, injects kimera management labels, validates
    resources, and records operations in the journal for clean revert.
    """

    def __init__(self, k8s: K8sClient, logger: SecurityLogger) -> None:
        """Initialize with Kubernetes client and logger."""
        self.k8s = k8s
        self.logger = logger

    def apply_from_file(
        self,
        path: str | Path,
        namespace: str | None = None,
        dry_run: bool = False,
    ) -> tuple[int, int]:
        """Apply Kubernetes resources from a YAML file.

        Args:
            path: Path to multi-document YAML file.
            namespace: Target namespace (injected if not set on resources).
            dry_run: If True, validate but do not apply.

        Returns:
            Tuple of (applied_count, total_count).
        """
        ns = namespace or self.k8s.namespace
        resources = self._parse_yaml(path)

        if not resources:
            self.logger.warning(f"No valid resources found in {path}")
            return 0, 0

        applied = 0
        for resource in resources:
            self._inject_label(resource)
            self._inject_namespace(resource, ns)

            if self._apply_resource(resource, ns, dry_run):
                applied += 1

        if not dry_run:
            self.logger.success(f"Applied {applied}/{len(resources)} resources from {path}")

        return applied, len(resources)

    def _parse_yaml(self, path: str | Path) -> list[dict[str, Any]]:
        """Parse a multi-document YAML file into a list of resource dicts."""
        path = Path(path)
        if not path.exists():
            self.logger.error(f"File not found: {path}")
            return []

        try:
            text = path.read_text()
        except OSError as e:
            self.logger.error(f"Failed to read {path}: {e}")
            return []

        resources: list[dict[str, Any]] = []
        try:
            for doc in yaml.safe_load_all(text):
                if doc is None:
                    continue
                if not self._validate_resource(doc):
                    continue
                resources.append(doc)
        except yaml.YAMLError as e:
            self.logger.error(f"Invalid YAML in {path}: {e}")
            return []

        return resources

    def _validate_resource(self, resource: dict[str, Any]) -> bool:
        """Validate a resource dict has required Kubernetes fields."""
        missing = []
        if "apiVersion" not in resource:
            missing.append("apiVersion")
        if "kind" not in resource:
            missing.append("kind")
        if not resource.get("metadata", {}).get("name"):
            missing.append("metadata.name")

        if missing:
            self.logger.warning(f"Skipping resource: missing {', '.join(missing)}")
            return False

        kind = resource["kind"]
        if kind not in SUPPORTED_KINDS:
            self.logger.warning(f"Unsupported resource kind: {kind} — skipping")
            return False

        return True

    def _inject_label(self, resource: dict[str, Any]) -> None:
        """Ensure the kimera managed-by label is present."""
        metadata = resource.setdefault("metadata", {})
        labels = metadata.setdefault("labels", {})

        if labels.get(TOOLKIT_LABEL) != TOOLKIT_LABEL_VALUE:
            labels[TOOLKIT_LABEL] = TOOLKIT_LABEL_VALUE
            name = metadata.get("name", "unknown")
            self.logger.info(f"Injected {TOOLKIT_LABEL}: {TOOLKIT_LABEL_VALUE} on {name}")

    def _inject_namespace(self, resource: dict[str, Any], namespace: str) -> None:
        """Set the namespace on a resource if not already set."""
        metadata = resource.setdefault("metadata", {})
        if not metadata.get("namespace"):
            metadata["namespace"] = namespace

    def apply_exploit_patches(
        self,
        path: str | Path,
        namespace: str | None = None,
        dry_run: bool = False,
    ) -> tuple[int, int]:
        """Apply exploit patches from a YAML file to deployments.

        Each YAML document must have ``target.deployment``, ``type``, and ``patches``
        fields. Patches are applied via ``K8sClient.patch_deployment()``.

        Args:
            path: Path to multi-document exploit YAML file.
            namespace: Fallback namespace (used if not set on target).
            dry_run: If True, validate but do not apply.

        Returns:
            Tuple of (applied_count, total_count).
        """
        path = Path(path)

        if not path.exists():
            self.logger.error(f"File not found: {path}")
            return 0, 0

        try:
            text = path.read_text()
            docs = [d for d in yaml.safe_load_all(text) if d is not None]
        except (OSError, yaml.YAMLError) as e:
            self.logger.error(f"Failed to read {path}: {e}")
            return 0, 0

        if not docs:
            self.logger.warning(f"No exploit patches found in {path}")
            return 0, 0

        applied = 0
        for doc in docs:
            target = doc.get("target", {})
            deployment = target.get("deployment")
            patches = doc.get("patches", [])

            if not deployment or not patches:
                self.logger.warning("Skipping document: missing target.deployment or patches")
                continue

            exploit_type = doc.get("type", "unknown")
            self.logger.info(f"Applying {exploit_type} patches to {deployment}...")

            if self.k8s.patch_deployment(deployment, patches, dry_run):
                applied += 1
                if not dry_run:
                    self.logger.success(f"Applied {exploit_type} exploit to {deployment}")

        if not dry_run:
            self.logger.success(f"Applied {applied}/{len(docs)} exploit patches from {path}")

        return applied, len(docs)

    def _apply_resource(self, resource: dict[str, Any], namespace: str, dry_run: bool) -> bool:
        """Apply a single resource to the cluster."""
        kind = resource["kind"]
        name = resource["metadata"]["name"]

        if kind == "NetworkPolicy":
            return self.k8s.create_network_policy(resource, namespace, dry_run=dry_run)

        self.logger.warning(f"Cannot apply {kind}/{name} — unsupported kind")
        return False
