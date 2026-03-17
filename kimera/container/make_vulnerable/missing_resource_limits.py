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


class MissingResourceLimitsExploit(BaseExploit):
    """Exploit for missing resource limits misconfiguration."""

    name = "Missing Resource Limits"
    risk_level = "MEDIUM-HIGH"
    vulnerability_type = "missing-resource-limits"
    description = """This exploit demonstrates how missing resource limits can:

                    - Enable denial-of-service attacks
                    - Cause node instability
                    - Impact other workloads
                    - Lead to cascading failures
                    - Result in excessive cloud costs

                    Without proper limits, a single container can consume
                    all available CPU and memory on a node, affecting all
                    other workloads and potentially crashing the node.

                    NOTE: This demonstration shows the POTENTIAL for resource exhaustion
                    without actually performing it, to maintain cluster stability."""

    def get_vulnerable_patch(self) -> list[dict[str, Any]]:
        """Get patch to remove resource limits."""
        return [{"op": "remove", "path": "/spec/template/spec/containers/0/resources"}]

    def get_secure_patch(self) -> list[dict[str, Any]]:
        """Get patch to add appropriate resource limits."""
        return [
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/securityContext",
                "value": {},
            },
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/securityContext/runAsNonRoot",
                "value": True,
            },
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/securityContext/runAsUser",
                "value": 1000,
            },
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/securityContext/allowPrivilegeEscalation",
                "value": False,
            },
            {
                "op": "add",
                "path": "/spec/template/spec/containers/0/securityContext/capabilities",
                "value": {"drop": ["ALL"]},
            },
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
        """Check if service has resource limits."""
        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return False

        try:
            pod = self.k8s.v1.read_namespaced_pod(pod_name, self.k8s.namespace)
            container = pod.spec.containers[0]

            if not container.resources or not container.resources.limits:
                return True

            return False
        except Exception as e:
            self.logger.error(f"Error checking vulnerability for {self.service}: {e}")
            return False

    def demonstrate(self) -> ExploitResult:
        """Demonstrate actual resource consumption without limits."""
        self.logger.exploit("Demonstrating missing resource limits vulnerability...")

        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return ExploitResult(success=False, message="Pod not found for service")

        tests, summary_impact = load_exploit_tests(self.vulnerability_type)
        result = self._run_tests(
            pod_name,
            tests,
            "Successfully demonstrated missing resource limits vulnerability",
        )

        # Node capacity check uses K8s API (not exec_in_pod)
        self.logger.exploit("Test: Node capacity check")
        try:
            pod = self.k8s.v1.read_namespaced_pod(pod_name, self.k8s.namespace)
            node_name = pod.spec.node_name
            node = self.k8s.v1.read_node(node_name)

            cpu_capacity = node.status.capacity.get("cpu", "unknown")
            memory_bytes = node.status.capacity.get("memory", "0Ki")

            if memory_bytes.endswith("Ki"):
                memory_gb = int(memory_bytes[:-2]) / (1024 * 1024)
            else:
                memory_gb = 0

            console.print(f"\n\\[*] Node: {node_name}")
            console.print(f"\\[*] Total capacity: {cpu_capacity} CPUs, {memory_gb:.1f}GB memory")
            console.print("\\[*] This container could consume ALL of these resources!")

            result.add_evidence(
                f"Access to {cpu_capacity} CPUs and {memory_gb:.1f}GB memory on node"
            )
        except Exception as e:
            self.logger.error(f"Node capacity check failed: {e}")

        # Summary
        self.logger.exploit("\n=== Summary ===")
        console.print("Without resource limits:")
        for item in summary_impact:
            console.print(f"  ✓ {item}")
        console.print("\nRisk: Any container can exhaust node resources causing:")
        console.print("  - Pod evictions")
        console.print("  - Service outages")
        console.print("  - Increased cloud costs")

        return result
