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

from rich.panel import Panel

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

    def get_secure_patch(self) -> list[dict[str, Any]]:
        """Return empty list — secure patches are generated dynamically via LLM."""
        return []

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
        content = (
            f"[bold]Target:[/bold] {self.service}\n"
            f"[bold]Risk:[/bold]   {self.risk_level}\n\n"
            f"{self.description}"
        )
        console.print()
        console.print(Panel(content, title=f"[bold]{self.name}[/bold]", border_style="red"))

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
        """Print remediation guidance for this exploit type.

        Remediations are generated dynamically via ``kimera generate`` and
        applied via ``kimera apply``. This method provides the commands needed.
        """
        ns = self.k8s.namespace
        console.print(f"\n[bold]Remediation: {self.name}[/bold]\n")
        console.print(f"  kimera -n {ns} generate --type {self.vulnerability_type} --apply\n")
        console.print("[dim]Or generate to file first:[/dim]")
        console.print(f"  kimera -n {ns} generate --type {self.vulnerability_type} -o fix.yaml")
        console.print(f"  kimera -n {ns} apply fix.yaml\n")
        return True

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
        self._display_results(result)

    def _display_results(self, result: ExploitResult) -> None:
        """Display consolidated exploit findings."""
        if result.evidence:
            console.print("\n[bold]Evidence:[/bold]")
            for item in result.evidence:
                console.print(f"  [green]•[/green] {item}")

        if result.impact:
            console.print("\n[bold]Impact:[/bold]")
            for item in result.impact:
                console.print(f"  [red]•[/red] {item}")
