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


class PrivilegedContainersExploit(BaseExploit):
    """Exploit for privileged container misconfiguration."""

    name = "Privileged Container"
    risk_level = "CRITICAL"
    vulnerability_type = "privileged-containers"
    description = """This exploit demonstrates how privileged containers can:
                    - Access ALL host devices and filesystems
                    - Load kernel modules
                    - Modify system settings
                    - Escape to the host system
                    - Access physical memory
                    - Control other containers

                In privileged mode, the container has nearly all the
                capabilities of the host system, making isolation meaningless."""

    def get_vulnerable_patch(self) -> list[dict[str, Any]]:
        """Get patch to enable privileged container mode."""
        return [
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/securityContext",
                "value": {},
            },
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation",
                "value": True,
            },
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/securityContext/privileged",
                "value": True,
            },
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/securityContext/capabilities",
                "value": {"add": ["SYS_ADMIN", "NET_ADMIN", "DAC_OVERRIDE"]},
            },
            {"op": "add", "path": "/spec/template/spec/hostPID", "value": True},
        ]

    def check_vulnerability(self) -> bool:
        """Check if service is running in privileged mode."""
        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return False

        try:
            pod = self.k8s.v1.read_namespaced_pod(pod_name, self.k8s.namespace)
            container = pod.spec.containers[0]

            if container.security_context and container.security_context.privileged:
                return True

            if pod.spec.host_pid:
                return True

            return False

        except Exception as e:
            self.logger.error(f"Error checking vulnerability for {self.service}: {e}")
            return False

    def demonstrate(self) -> ExploitResult:
        """Demonstrate privileged container exploit."""
        self.logger.exploit("Demonstrating privileged container risks...")

        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return ExploitResult(success=False, message="Pod not found for service")

        tests, summary_impact = load_exploit_tests(self.vulnerability_type)
        result = self._run_tests(pod_name, tests, "Privileged container exploit demonstrated")

        self.logger.exploit("=== Impact Summary ===")
        for item in summary_impact:
            console.print(f"  • {item}")

        return result
