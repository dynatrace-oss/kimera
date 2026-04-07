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

from ...domain.models import ExploitResult
from ..core.logger import console
from .base import BaseExploit
from .test_loader import load_exploit_tests


class HostNamespaceSharingExploit(BaseExploit):
    """Exploit for host namespace sharing misconfiguration."""

    name = "Host Namespace Sharing"
    risk_level = "CRITICAL"
    vulnerability_type = "host-namespace-sharing"
    description = """This exploit demonstrates the risks of sharing host namespaces:

                - hostPID: Access to ALL host processes
                - hostNetwork: Access to host network interfaces
                - hostIPC: Access to host IPC resources

                With host namespace access, container isolation is severely
                compromised, enabling:
                - Lateral movement across containers
                - Access to sensitive process information
                - Network traffic interception
                - Secrets exposure from other containers"""

    def get_vulnerable_patch(self) -> list[dict[str, Any]]:
        """Get patch to enable host namespace sharing."""
        return [
            {"op": "add", "path": "/spec/template/spec/hostPID", "value": True},
            {"op": "add", "path": "/spec/template/spec/hostNetwork", "value": True},
        ]

    def check_vulnerability(self) -> bool:
        """Check if service has host namespace access."""
        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return False

        try:
            pod = self.k8s.v1.read_namespaced_pod(pod_name, self.k8s.namespace)

            if pod.spec.host_pid or pod.spec.host_network or pod.spec.host_ipc:
                return True

            return False

        except Exception as e:
            self.logger.error(f"Error checking vulnerability for {self.service}: {e}")
            return False

    def demonstrate(self) -> ExploitResult:
        """Demonstrate host namespace access risks."""
        self.logger.exploit("Demonstrating host namespace access risks...")

        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return ExploitResult(success=False, message="Pod not found for service")

        tests, summary_impact = load_exploit_tests(self.vulnerability_type)
        result = self._run_tests(pod_name, tests, "Host namespace sharing exploit demonstrated")

        self.logger.exploit("=== Impact Summary ===")
        for item in summary_impact:
            console.print(f"  • {item}")

        return result
