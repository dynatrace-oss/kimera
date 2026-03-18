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

import time
from abc import ABC, abstractmethod
from typing import Any

from ...domain.models import ExploitResult, SecurityTest
from ..core.journal import clear_operation, record_operation
from ..core.k8s_client import K8sClient
from ..core.logger import SecurityLogger, console, setup_logger


class BaseExploit(ABC):
    """Base class for all security exploits."""

    name: str = ""
    risk_level: str = "MEDIUM"
    vulnerability_type: str = ""
    description: str = ""

    def __init__(
        self,
        k8s_client: K8sClient,
        service: str | None = None,
        logger: SecurityLogger | None = None,
    ):
        """Initialize exploit with Kubernetes client, service, and logger."""
        self.k8s = k8s_client
        self.service = service or self.get_default_service()
        if not self.service:
            raise ValueError(
                f"No service specified for {self.name}. "
                "Use --service or configure exploit_mappings in your profile."
            )
        self.logger = logger or SecurityLogger(setup_logger(__name__))

    def get_default_service(self) -> str:
        """Get the default service for this exploit.

        Returns empty string by default. Override in subclasses or pass
        a service to ``__init__`` / configure via ``exploit_mappings``.
        """
        return ""

    @abstractmethod
    def get_vulnerable_patch(self) -> list[dict[str, Any]]:
        """Get JSON patch to make service vulnerable."""
        pass

    @abstractmethod
    def get_secure_patch(self) -> list[dict[str, Any]]:
        """Get JSON patch to secure service."""
        pass

    @abstractmethod
    def check_vulnerability(self) -> bool:
        """Check if service is vulnerable."""
        pass

    @abstractmethod
    def demonstrate(self) -> ExploitResult:
        """Demonstrate the exploit."""
        pass

    def show_info(self) -> None:
        """Display exploit information."""
        console.print(f"""
                {"=" * 45}
                {self.name} Exploit
                {"=" * 45}
                Target: {self.service}
                Risk: {self.risk_level}

                {self.description}
                {"=" * 45}
            """)

    def make_vulnerable(self, dry_run: bool = False) -> bool:
        """Apply vulnerable configuration."""
        self.logger.info(f"Applying vulnerable configuration to {self.service}...")
        patches = self.get_vulnerable_patch()

        if self.k8s.patch_deployment(self.service, patches, dry_run):
            if not dry_run:
                self.logger.success(f"Applied vulnerable configuration to {self.service}")
                record_operation(
                    "make_vulnerable", self.vulnerability_type, self.service, self.k8s.namespace
                )
            return True
        return False

    def make_secure(self, dry_run: bool = False) -> bool:
        """Apply secure configuration.

        Note: This applies a *hardened* configuration which may differ from the
        deployment's original state. To restore the original state, use
        ``kimera rollback`` or ``kimera revert`` instead.
        """
        self.logger.info(f"Applying secure configuration to {self.service}...")
        patches = self.get_secure_patch()

        # Pre-create security context if needed
        self._ensure_security_context()

        if self.k8s.patch_deployment(self.service, patches, dry_run):
            if not dry_run:
                self.logger.success(f"Applied secure configuration to {self.service}")
                record_operation(
                    "make_secure", self.vulnerability_type, self.service, self.k8s.namespace
                )
            return True
        return False

    def revert(self, dry_run: bool = False) -> bool:
        """Revert to the original deployment state via rollback.

        Unlike ``make_secure`` (which applies a hardened config),
        this rolls back to the deployment's previous revision.
        """
        self.logger.info(f"Reverting {self.service} to previous revision...")
        if dry_run:
            self.logger.info(f"DRY RUN: Would rollback {self.service}")
            return True

        success = self.k8s.rollback_deployment(self.service)
        if success:
            # Verify the rollback actually removed the vulnerability
            still_vulnerable = self.check_vulnerability()
            if still_vulnerable:
                self.logger.warning(
                    f"Rollback completed but {self.service} still appears vulnerable. "
                    "The previous revision may itself be vulnerable."
                )
            else:
                self.logger.success(f"Reverted {self.service} — verified not vulnerable")
            clear_operation(self.vulnerability_type, self.service, self.k8s.namespace)
        return success

    def _ensure_security_context(self) -> None:
        """Ensure security context exists before patching."""
        deployment = self.k8s.get_deployment(self.service)
        if not deployment:
            return

        if deployment.spec and deployment.spec.template and deployment.spec.template.spec:
            containers = deployment.spec.template.spec.containers or []
            for i, container in enumerate(containers):
                if not container.security_context:
                    self.k8s.patch_deployment(
                        self.service,
                        [
                            {
                                "op": "add",
                                "path": f"/spec/template/spec/containers/{i}/securityContext",
                                "value": {},
                            }
                        ],
                    )

    def _run_tests(
        self,
        pod_name: str,
        tests: list[SecurityTest],
        message: str = "",
    ) -> ExploitResult:
        """Run a list of security tests in a pod and collect evidence.

        Each test's output is scanned for evidence markers. Matching
        markers are recorded as evidence and impact entries in the
        returned ``ExploitResult``.

        Args:
            pod_name: Name of the pod to execute tests in.
            tests: Security test definitions to run.
            message: Summary message for the result.
        """
        evidence: list[str] = []
        impact: list[str] = []

        for test in tests:
            self.logger.exploit(f"Test: {test.name}")
            try:
                output = self.k8s.exec_in_pod(pod_name, test.script)
                console.print(output, highlight=False)

                for marker in test.evidence_markers:
                    if marker.marker in output:
                        evidence.append(marker.evidence)
                        if marker.impact:
                            impact.append(marker.impact)
            except Exception as e:
                self.logger.error(f"{test.name} failed: {e}")

        return ExploitResult(
            success=bool(evidence),
            message=message or f"{self.name} exploit demonstrated",
            evidence=evidence,
            impact=impact,
        )

    def run_interactive(self) -> None:
        """Run interactive demonstration."""
        self.show_info()

        if not self.check_vulnerability():
            response = input("Service is not vulnerable. Make it vulnerable? (y/n) ")
            if response.lower() == "y":
                self.make_vulnerable()
                console.print()
                time.sleep(2)

        result = self.demonstrate()

        if result.evidence:
            console.print("\nEvidence:")
            for item in result.evidence:
                console.print(f"  • {item}")

        if result.impact:
            console.print("\nImpact:")
            for item in result.impact:
                console.print(f"  • {item}")

    def build_security_context_patch(self, container_idx: int = 0) -> list[dict[str, Any]]:
        """Build a base security context patch."""
        return [
            {
                "op": "add",
                "path": f"/spec/template/spec/containers/{container_idx}/securityContext",
                "value": {},
            }
        ]

    def build_privileged_patch(self, container_idx: int = 0) -> list[dict[str, Any]]:
        """Build patches for privileged mode."""
        patches = self.build_security_context_patch(container_idx)
        patches.extend(
            [
                {
                    "op": "add",
                    "path": f"/spec/template/spec/containers/{container_idx}/securityContext/privileged",
                    "value": True,
                },
                {
                    "op": "add",
                    "path": f"/spec/template/spec/containers/{container_idx}/securityContext/allowPrivilegeEscalation",
                    "value": True,
                },
            ]
        )
        return patches
