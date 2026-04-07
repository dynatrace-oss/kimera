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
from kimera.container.core.logger import SecurityLogger, console, setup_logger

CILIUM_NAMESPACE = "kube-system"
CILIUM_DAEMONSET = "cilium"

_CILIUM_INSTALL_GUIDANCE = """\
[bold]Cilium is not running in this cluster.[/bold]

NetworkPolicies created by Kimera will be accepted by the Kubernetes API
but will have [yellow]no enforcement effect[/yellow] until a policy-enforcing
CNI is installed.

[bold]Install Cilium (Helm — recommended):[/bold]

  helm repo add cilium https://helm.cilium.io/
  helm install cilium cilium/cilium --version 1.16.5 \\
    --namespace kube-system \\
    --set ipam.mode=kubernetes

[bold]Install Cilium (Cilium CLI):[/bold]

  cilium install --version 1.16.5

After installation, verify with:

  cilium status --wait
  kubectl get daemonset cilium -n kube-system

Then apply network policies:

  kimera -n <namespace> secure missing-network-policies
"""

_CILIUM_UNINSTALL_GUIDANCE = """\
To remove Cilium and disable NetworkPolicy enforcement:

  [bold]Via Helm:[/bold]
  helm uninstall cilium -n kube-system

  [bold]Via Cilium CLI:[/bold]
  cilium uninstall
"""


class PolicyEnforcementManager:
    """Detects Cilium NetworkPolicy enforcement and provides installation guidance.

    Kimera applies NetworkPolicy resources through the Kubernetes API and does
    not install or manage the CNI itself. This manager checks whether Cilium
    is running and gives operators the commands needed to enable enforcement.
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
        """Check for Cilium and print installation guidance if not found.

        Kimera does not install CNI plugins — that is a cluster admin operation.
        This method checks whether Cilium is already running and gives the
        operator the commands to install it if not.

        Args:
            dry_run: If True, skip the cluster check and return True.

        Returns:
            True if Cilium is running, False if guidance was printed.
        """
        if dry_run:
            self.logger.info("DRY RUN: Would check for Cilium enforcement")
            return True

        if self.is_enabled():
            self.logger.success("Cilium is running — NetworkPolicy enforcement is active")
            return True

        console.print(_CILIUM_INSTALL_GUIDANCE)
        return False

    def disable(self, dry_run: bool = False) -> None:
        """Print guidance for removing Cilium.

        Kimera does not uninstall CNI plugins — that is a cluster admin operation.
        This method provides the commands needed to remove Cilium.

        Args:
            dry_run: If True, skip output.
        """
        if dry_run:
            self.logger.info("DRY RUN: Would print Cilium removal guidance")
            return

        console.print(_CILIUM_UNINSTALL_GUIDANCE)

    def is_enabled(self) -> bool:
        """Check if the Cilium DaemonSet is running with all pods ready.

        Returns:
            True if Cilium is installed and all desired pods are ready.
        """
        ds = self.k8s.get_daemonset(CILIUM_DAEMONSET, CILIUM_NAMESPACE)
        if not ds or not ds.status:
            return False
        desired = ds.status.desired_number_scheduled or 0
        ready = ds.status.number_ready or 0
        return desired > 0 and ready == desired

    def get_status(self) -> dict[str, Any]:
        """Return detailed Cilium enforcement status.

        Returns:
            Dict with ``installed`` bool and, when installed, pod counts
            and the DaemonSet image.
        """
        ds = self.k8s.get_daemonset(CILIUM_DAEMONSET, CILIUM_NAMESPACE)
        if not ds or not ds.status:
            return {"installed": False}

        containers = ds.spec.template.spec.containers if ds.spec and ds.spec.template else []
        image = containers[0].image if containers else "unknown"

        return {
            "installed": True,
            "desired": ds.status.desired_number_scheduled or 0,
            "ready": ds.status.number_ready or 0,
            "available": ds.status.number_available or 0,
            "image": image,
        }
