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


class DangerousCapabilitiesExploit(BaseExploit):
    """Exploit for dangerous Linux capabilities misconfiguration."""

    name = "Dangerous Capabilities"
    risk_level = "CRITICAL"
    vulnerability_type = "dangerous-capabilities"
    description = """This exploit demonstrates how containers with dangerous capabilities can:
                    - Completely escape container isolation
                    - Access host filesystem and kernel features
                    - Manipulate network configuration
                    - Load kernel modules
                    - Bypass security restrictions

                    The profile service is configured with ALL Linux capabilities (000001ffffffffff),
                    making it FULLY PRIVILEGED with complete access to the host system."""

    def get_vulnerable_patch(self) -> list[dict[str, Any]]:
        """Get patch to add dangerous capabilities to the deployment."""
        return [
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/securityContext",
                "value": {},
            },
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/securityContext/privileged",
                "value": True,
            },
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/securityContext/capabilities",
                "value": {
                    "add": [
                        "SYS_ADMIN",
                        "NET_ADMIN",
                        "SYS_PTRACE",
                        "DAC_OVERRIDE",
                        "DAC_READ_SEARCH",
                        "SYS_MODULE",
                    ]
                },
            },
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation",
                "value": True,
            },
            {"op": "add", "path": "/spec/template/spec/hostPID", "value": True},
        ]

    def get_secure_patch(self) -> list[dict[str, Any]]:
        """Get patch to remove dangerous capabilities from the deployment."""
        return [
            {
                "op": "replace",
                "path": "/spec/template/spec/containers/0/securityContext/privileged",
                "value": False,
            },
            {
                "op": "replace",
                "path": "/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation",
                "value": False,
            },
            {
                "op": "replace",
                "path": "/spec/template/spec/containers/0/securityContext/runAsNonRoot",
                "value": True,
            },
            {
                "op": "replace",
                "path": "/spec/template/spec/containers/0/securityContext/runAsUser",
                "value": 1000,
            },
            {
                "op": "replace",
                "path": "/spec/template/spec/containers/0/securityContext/capabilities",
                "value": {"drop": ["ALL"]},
            },
            {"op": "replace", "path": "/spec/template/spec/hostPID", "value": False},
            {
                "op": "replace",
                "path": "/spec/template/spec/hostNetwork",
                "value": False,
            },
            {"op": "replace", "path": "/spec/template/spec/hostIPC", "value": False},
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/resources",
                "value": {
                    "limits": {"memory": "256Mi", "cpu": "200m"},
                    "requests": {"memory": "128Mi", "cpu": "100m"},
                },
            },
        ]

    def check_vulnerability(self) -> bool:
        """Check if service has dangerous capabilities."""
        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return False

        try:
            pod = self.k8s.v1.read_namespaced_pod(pod_name, self.k8s.namespace)
            container = pod.spec.containers[0]

            if container.security_context and container.security_context.privileged:
                return True

            if (
                container.security_context
                and container.security_context.capabilities
                and container.security_context.capabilities.add
            ):
                dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "ALL"]
                for cap in container.security_context.capabilities.add:
                    if cap in dangerous_caps:
                        return True

            return False

        except Exception as e:
            self.logger.error(f"Error checking vulnerability for {self.service}: {e}")
            return False

    def demonstrate(self) -> ExploitResult:
        """Demonstrate dangerous capabilities exploit."""
        self.logger.exploit(
            "Demonstrating privileged container escape with dangerous capabilities..."
        )

        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return ExploitResult(success=False, message="Pod not found for service")

        tests, summary_impact = load_exploit_tests(self.vulnerability_type)
        result = self._run_tests(pod_name, tests, "Dangerous capabilities exploit demonstrated")

        self.logger.exploit("=== Impact Summary ===")
        for item in summary_impact:
            console.print(f"  • {item}")
            result.add_impact(item)

        return result
