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
from .probe_runner import ProbeRunner
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

REDIS_PORT = 6379

# Long enough for a cross-namespace hop, short enough that a namespace of
# unreachable services does not stall the demonstration.
PROBE_TIMEOUT_SECONDS = 3

# Probing every port of every service scales the demonstration with namespace
# size; the first port of each service is what a lateral move would try. The
# bound is reported when it bites — an unreported cap understates the attack
# surface, and every path count downstream inherits the understatement.
MAX_LATERAL_TARGETS = 25


class MissingNetworkPoliciesExploit(BaseExploit):
    """Exploit demonstrating risks of missing network policies.

    Operates at the namespace level rather than patching deployments:
    ``make_vulnerable`` removes NetworkPolicies, restoring the flat network.
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

    def _discover_reachable_services(self) -> list[tuple[str, int]]:
        """Find application services to probe for lateral movement.

        Data stores have their own test; the source workload reaching itself is
        not a lateral move.
        """
        targets: list[tuple[str, int]] = []
        try:
            svc_list = self.k8s.v1.list_namespaced_service(self.k8s.namespace)
        except Exception as e:
            self.logger.warning(f"Could not list services for lateral movement test: {e}")
            return targets

        for svc in svc_list.items:
            name = svc.metadata.name
            if name == self.service or not svc.spec.ports:
                continue
            port = svc.spec.ports[0].port
            if port in DATA_STORE_PORTS:
                continue
            targets.append((name, port))

        if len(targets) > MAX_LATERAL_TARGETS:
            dropped = ", ".join(name for name, _ in targets[MAX_LATERAL_TARGETS:])
            self.logger.warning(
                f"Probing {MAX_LATERAL_TARGETS} of {len(targets)} services; not probed: {dropped}"
            )
        return targets[:MAX_LATERAL_TARGETS]

    def _build_dynamic_tests(self) -> list[SecurityTest]:
        """Build tests that depend on auto-discovered services.

        Probes go through ``ProbeRunner`` like YAML-declared ones — hand-writing
        the shell here would bypass the builders that record attack paths.
        """
        tests: list[SecurityTest] = []
        runner = ProbeRunner()

        svc_names = self._discover_services()
        if svc_names:
            tests.append(
                SecurityTest(
                    name="DNS service enumeration",
                    script=runner.build_script([{"type": "dns_resolve", "hosts": svc_names}]),
                    evidence_markers=[
                        EvidenceMarker(
                            "FOUND:",
                            "DNS enumeration discovered services in the namespace",
                            "Attacker can map all services via predictable DNS names",
                        ),
                    ],
                )
            )

        data_stores = self._discover_data_store_services()
        if data_stores:
            tests.append(
                SecurityTest(
                    name="Data store accessibility",
                    script=runner.build_script(self._data_store_probes(data_stores)),
                    evidence_markers=[
                        EvidenceMarker(
                            "OPEN",
                            "Data store ports reachable from application pod",
                            "Database/cache accessible from unauthorized service",
                        ),
                    ],
                )
            )

        lateral_targets = self._discover_reachable_services()
        if lateral_targets:
            tests.append(
                SecurityTest(
                    name="Lateral movement to application services",
                    script=runner.build_script(
                        [
                            {
                                "type": "port_open",
                                "host": name,
                                "port": port,
                                "timeout": PROBE_TIMEOUT_SECONDS,
                                "label": f"{name}:{port}",
                            }
                            for name, port in lateral_targets
                        ]
                    ),
                    evidence_markers=[
                        EvidenceMarker(
                            "OPEN",
                            "Application services reachable from an unrelated pod",
                            "A compromised pod can reach every service in the namespace",
                        ),
                    ],
                )
            )

        return tests

    @staticmethod
    def _data_store_probes(
        data_stores: list[tuple[str, int, str]],
    ) -> list[dict[str, Any]]:
        """Build the probe list for discovered data stores."""
        probes: list[dict[str, Any]] = []
        for svc_name, port, label in data_stores:
            probes.append(
                {
                    "type": "port_open",
                    "host": svc_name,
                    "port": port,
                    "timeout": PROBE_TIMEOUT_SECONDS,
                    "label": f"{label} ({svc_name}:{port})",
                }
            )
            if port == REDIS_PORT:
                # A real DBSIZE exchange, so it reads as Redis protocol traffic
                # rather than a bare connection. No typed builder writes payloads.
                probes.append(
                    {
                        "type": "command",
                        "run": (
                            f'key_count=$(printf "*1\\r\\n\\$6\\r\\nDBSIZE\\r\\n"'
                            f" | kimera_tcp_send {svc_name} {port} {PROBE_TIMEOUT_SECONDS}"
                            f' | tr -d "\\r" | grep -o "[0-9]*")\n'
                            f'[ -n "$key_count" ] && echo "[*] Redis key count: $key_count"'
                        ),
                    }
                )
        return probes

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
