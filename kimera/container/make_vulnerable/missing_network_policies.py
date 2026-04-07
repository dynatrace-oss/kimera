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

from ...domain.models import EvidenceMarker, ExploitResult, SecurityTest
from ..core.journal import clear_operation, record_operation
from ..core.logger import console
from .base import BaseExploit
from .test_loader import load_exploit_tests

# Label used to identify network policies created by this toolkit
TOOLKIT_LABEL = "app.kubernetes.io/managed-by"
TOOLKIT_LABEL_VALUE = "kimera"

# Common data store ports to probe during demonstrations
DATA_STORE_PORTS: dict[int, str] = {
    3306: "MySQL/MariaDB",
    5432: "PostgreSQL",
    6379: "Redis",
    27017: "MongoDB",
}


class MissingNetworkPoliciesExploit(BaseExploit):
    """Exploit demonstrating risks of missing network policies.

    Unlike container-level exploits that patch deployments, this exploit
    operates at the namespace level by creating and removing NetworkPolicy
    resources. The ``make_secure`` method auto-discovers deployments and
    generates restrictive policies; ``make_vulnerable`` removes them,
    restoring the flat network default.
    """

    name = "Missing Network Policies"
    risk_level = "HIGH"
    vulnerability_type = "missing-network-policies"
    description = """Demonstrates risks of missing Kubernetes network policies:

                - Cross-namespace service discovery via DNS
                - Unrestricted lateral movement between pods
                - Data store access from unauthorized namespaces
                - Infrastructure reachability from application pods

                Without network policies, every pod can communicate with
                every other pod across all namespaces by default."""

    def get_vulnerable_patch(self) -> list[dict[str, Any]]:
        """Not used — vulnerability is the absence of network policies."""
        return []

    def check_vulnerability(self) -> bool:
        """Check if the namespace lacks network policies."""
        policies = self.k8s.list_network_policies(self.k8s.namespace)
        if not policies:
            self.logger.warning(f"No NetworkPolicies found in namespace {self.k8s.namespace}")
            return True
        self.logger.info(f"Found {len(policies)} NetworkPolicies in {self.k8s.namespace}")
        return False

    def make_vulnerable(self, dry_run: bool = False) -> bool:
        """Remove toolkit-managed network policies, restoring the flat network."""
        self.logger.info(f"Removing toolkit-managed NetworkPolicies from {self.k8s.namespace}...")
        policies = self.k8s.list_network_policies(self.k8s.namespace)
        removed = 0

        for policy in policies:
            labels = policy.metadata.labels or {}
            if labels.get(TOOLKIT_LABEL) == TOOLKIT_LABEL_VALUE:
                if dry_run:
                    self.logger.info(f"DRY RUN: Would delete NetworkPolicy {policy.metadata.name}")
                else:
                    self.k8s.delete_network_policy(policy.metadata.name, self.k8s.namespace)
                removed += 1

        if removed == 0:
            self.logger.info("No toolkit-managed NetworkPolicies found to remove")
        elif not dry_run:
            self.logger.success(f"Removed {removed} NetworkPolicies — flat network restored")
            record_operation(
                "make_vulnerable", self.vulnerability_type, self.service, self.k8s.namespace
            )
        return True

    def make_secure(self, dry_run: bool = False) -> bool:
        """Print remediation guidance for network policies.

        Extends base guidance with enforcement check since NetworkPolicies
        require a policy-enforcing CNI (Cilium).
        """
        super().make_secure(dry_run=dry_run)
        console.print("[bold]Verify enforcement (Cilium required):[/bold]")
        console.print("  kimera enforce enable\n")
        return True

    def revert(self, dry_run: bool = False) -> bool:
        """Remove toolkit-managed network policies (alias for make_vulnerable)."""
        result = self.make_vulnerable(dry_run=dry_run)
        if result and not dry_run:
            clear_operation(self.vulnerability_type, self.service, self.k8s.namespace)
        return result

    # -- Demonstration -----------------------------------------------------------

    def _discover_services(self) -> list[str]:
        """Discover service names in the namespace via the Kubernetes API."""
        try:
            svc_list = self.k8s.v1.list_namespaced_service(self.k8s.namespace)
            return [svc.metadata.name for svc in svc_list.items]
        except Exception:
            return []

    def _discover_data_store_services(self) -> list[tuple[str, int, str]]:
        """Find services listening on common data store ports."""
        targets: list[tuple[str, int, str]] = []
        try:
            svc_list = self.k8s.v1.list_namespaced_service(self.k8s.namespace)
            for svc in svc_list.items:
                if svc.spec.ports:
                    for port_spec in svc.spec.ports:
                        port_num = port_spec.port
                        if port_num in DATA_STORE_PORTS:
                            targets.append(
                                (svc.metadata.name, port_num, DATA_STORE_PORTS[port_num])
                            )
        except Exception:  # noqa: S110
            return targets
        return targets

    def _build_dynamic_tests(self) -> list[SecurityTest]:
        """Build tests that depend on auto-discovered services."""
        tests: list[SecurityTest] = []

        # Test 1: DNS service enumeration
        svc_names = self._discover_services()
        if svc_names:
            svc_list_str = " ".join(svc_names)
            tests.append(
                SecurityTest(
                    name="DNS service enumeration",
                    script=(
                        'echo "[*] Enumerating services via DNS..."\n'
                        "ns=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)\n"
                        "found=0\n"
                        f"for svc in {svc_list_str}; do\n"
                        '    fqdn="${svc}.${ns}.svc.cluster.local"\n'
                        '    if nslookup "$fqdn" >/dev/null 2>&1; then\n'
                        '        addr=$(nslookup "$fqdn" 2>/dev/null'
                        " | grep \"Address\" | tail -1 | awk '{print $2}')\n"
                        '        echo "  FOUND: ${svc} -> ${addr}"\n'
                        "        found=$((found + 1))\n"
                        "    fi\n"
                        "done\n"
                        'echo "[*] Total services discovered: $found"\n'
                    ),
                    evidence_markers=[
                        EvidenceMarker(
                            "FOUND:",
                            "DNS enumeration discovered services in the namespace",
                            "Attacker can map all services via predictable DNS names",
                        ),
                    ],
                )
            )

        # Test 2: Data store connectivity
        data_stores = self._discover_data_store_services()
        if data_stores:
            probe_cmds = []
            for svc_name, port, label in data_stores:
                probe_cmds.append(
                    f'echo -n "  {label} ({svc_name}:{port}) -> "; '
                    f"if nc -z -w 3 {svc_name} {port} 2>/dev/null; then "
                    f'echo "OPEN"; else echo "CLOSED"; fi'
                )
                # For Redis: send a real DBSIZE command to produce observable traffic
                # that Dynatrace OneAgent records as a Redis protocol interaction
                if port == 6379:
                    probe_cmds.append(
                        f'key_count=$(printf "*1\\r\\n\\$6\\r\\nDBSIZE\\r\\n"'
                        f" | nc -w3 {svc_name} {port} 2>/dev/null"
                        f' | tr -d "\\r" | grep -o "[0-9]*")\n'
                        f'[ -n "$key_count" ] && echo "[*] Redis key count: $key_count"'
                    )
            tests.append(
                SecurityTest(
                    name="Data store accessibility",
                    script=(
                        'echo "[*] Testing data store connectivity..."\n'
                        + "\n".join(probe_cmds)
                        + "\n"
                    ),
                    evidence_markers=[
                        EvidenceMarker(
                            "OPEN",
                            "Data store ports reachable from application pod",
                            "Database/cache accessible from unauthorized service",
                        ),
                    ],
                )
            )

        return tests

    def demonstrate(self) -> ExploitResult:
        """Demonstrate network policy absence by running connectivity tests."""
        self.logger.exploit("Demonstrating missing network policy risks...")

        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return ExploitResult(success=False, message=f"Pod not found for {self.service}")

        # Dynamic tests (service-dependent) + static tests from YAML
        static_tests, summary_impact = load_exploit_tests(self.vulnerability_type)
        all_tests = self._build_dynamic_tests() + static_tests

        result = self._run_tests(
            pod_name, all_tests, "Missing network policies exploit demonstrated"
        )

        self.logger.exploit("=== Impact Summary ===")
        for item in summary_impact:
            console.print(f"  • {item}")

        return result
