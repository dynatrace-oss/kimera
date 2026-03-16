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

from abc import ABC, abstractmethod
from typing import Any

from kimera.container.core.k8s_client import K8sClient
from kimera.container.core.logger import SecurityLogger, setup_logger
from kimera.domain.models import (
    ExploitMetadata,
    ExploitResult,
    VulnerabilityCheck,
)


class BaseExploitPlugin(ABC):
    """Base class for exploit plugins.

    Provides common functionality for all exploit plugins:
    - Kubernetes client integration
    - Logging
    - Common utility methods
    - Template methods for exploit workflow

    Subclasses must implement:
    - _metadata property
    - get_vulnerable_patches()
    - get_secure_patches()
    - demonstrate()
    """

    def __init__(
        self,
        k8s_client: K8sClient | None = None,
        logger: SecurityLogger | None = None,
    ) -> None:
        """Initialize plugin with Kubernetes client and logger.

        Args:
            k8s_client: Kubernetes client instance
            logger: Security logger instance
        """
        self.k8s = k8s_client or self._create_k8s_client()
        self.logger = logger or SecurityLogger(setup_logger(__name__))

    def _create_k8s_client(self) -> K8sClient:
        """Create default Kubernetes client.

        Returns:
            Configured K8s client
        """
        return K8sClient(logger=self.logger)

    @property
    @abstractmethod
    def _metadata(self) -> ExploitMetadata:
        """Get exploit metadata.

        Returns:
            Exploit metadata
        """
        ...

    @property
    def metadata(self) -> ExploitMetadata:
        """Get exploit metadata (public interface).

        Returns:
            Exploit metadata
        """
        return self._metadata

    @abstractmethod
    def get_vulnerable_patches(self) -> list[dict[str, Any]]:
        """Get JSON patches to make service vulnerable.

        Returns:
            List of JSON patch operations
        """
        ...

    @abstractmethod
    def get_secure_patches(self) -> list[dict[str, Any]]:
        """Get JSON patches to secure service.

        Returns:
            List of JSON patch operations
        """
        ...

    @abstractmethod
    def demonstrate(self, target: str) -> ExploitResult:
        """Execute exploitation demonstration.

        Args:
            target: Target service name

        Returns:
            Results with evidence and impact
        """
        ...

    def check_vulnerability(self, target: str) -> VulnerabilityCheck:
        """Check if target has this vulnerability.

        Args:
            target: Target service name

        Returns:
            Vulnerability check result
        """
        pod_name = self.k8s.find_pod_for_service(target)
        if not pod_name:
            return VulnerabilityCheck(
                vulnerable=False,
                details=f"No pod found for service {target}",
                severity=self.metadata.risk_level,
                remediation_available=False,
            )

        try:
            is_vulnerable = self._check_vulnerability_impl(target, pod_name)
            return VulnerabilityCheck(
                vulnerable=is_vulnerable,
                details=f"Service {target} vulnerability check completed",
                severity=self.metadata.risk_level,
                remediation_available=True,
            )
        except Exception as e:
            return VulnerabilityCheck(
                vulnerable=False,
                details=f"Error checking vulnerability: {e}",
                severity=self.metadata.risk_level,
                remediation_available=False,
            )

    def _check_vulnerability_impl(self, target: str, pod_name: str) -> bool:
        """Implementation of vulnerability check.

        Subclasses can override this for custom vulnerability checks.

        Args:
            target: Target service name
            pod_name: Pod name

        Returns:
            True if vulnerable
        """
        return False

    def apply_vulnerable_config(self, target: str, dry_run: bool = False) -> bool:
        """Introduce vulnerability into target.

        Args:
            target: Target service name
            dry_run: Preview changes without applying

        Returns:
            True if successful, False otherwise
        """
        self.logger.info(f"Applying vulnerable configuration to {target}...")
        patches = self.get_vulnerable_patches()

        if self.k8s.patch_deployment(target, patches, dry_run):
            if not dry_run:
                self.logger.success(f"Applied vulnerable configuration to {target}")
            return True
        return False

    def remediate(self, target: str, dry_run: bool = False) -> bool:
        """Apply secure configuration.

        Args:
            target: Target service name
            dry_run: Preview changes without applying

        Returns:
            True if successful, False otherwise
        """
        self.logger.info(f"Applying secure configuration to {target}...")
        patches = self.get_secure_patches()

        # Ensure security context exists
        self._ensure_security_context(target)

        if self.k8s.patch_deployment(target, patches, dry_run):
            if not dry_run:
                self.logger.success(f"Applied secure configuration to {target}")
            return True
        return False

    def _ensure_security_context(self, target: str) -> None:
        """Ensure security context exists before patching.

        Args:
            target: Target service name
        """
        deployment = self.k8s.get_deployment(target)
        if not deployment:
            return

        if deployment.spec and deployment.spec.template and deployment.spec.template.spec:
            containers = deployment.spec.template.spec.containers or []
            for i, container in enumerate(containers):
                if not container.security_context:
                    self.k8s.patch_deployment(
                        target,
                        [
                            {
                                "op": "add",
                                "path": f"/spec/template/spec/containers/{i}/securityContext",
                                "value": {},
                            }
                        ],
                    )

    def show_info(self) -> None:
        """Display exploit information."""
        meta = self.metadata

        print("=" * 60)
        print(f"{meta.display_name}")
        print("=" * 60)
        print(f"Risk Level: {meta.risk_level}")
        print(f"Version: {meta.version}")
        print(f"Author: {meta.author}")
        print()
        print("Description:")
        print(f"  {meta.description}")
        print()

        if meta.mitre_tactics:
            print("MITRE ATT&CK Tactics:")
            for tactic in meta.mitre_tactics:
                print(f"  • {tactic}")
            print()

        if meta.mitre_techniques:
            print("MITRE ATT&CK Techniques:")
            for technique in meta.mitre_techniques:
                print(f"  • {technique}")
            print()

        if meta.cis_controls:
            print("CIS Kubernetes Benchmark Controls:")
            for control in meta.cis_controls:
                print(f"  • {control}")
            print()

        if meta.cve_ids:
            print("Related CVEs:")
            for cve in meta.cve_ids:
                print(f"  • {cve}")
            print()

        print("=" * 60)
