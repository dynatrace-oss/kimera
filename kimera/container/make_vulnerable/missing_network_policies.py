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

from .base import BaseExploit, ExploitResult

# Label used to identify network policies created by this toolkit
TOOLKIT_LABEL = "app.kubernetes.io/managed-by"
TOOLKIT_LABEL_VALUE = "kimera"


def _build_network_policies(namespace: str) -> list[dict[str, Any]]:
    """Build the set of network policies for the unguard namespace.

    Args:
        namespace: Target namespace for the policies.

    Returns:
        List of NetworkPolicy resource dicts.
    """
    common_labels = {
        "app.kubernetes.io/part-of": "unguard",
        TOOLKIT_LABEL: TOOLKIT_LABEL_VALUE,
    }

    dns_egress_rule = {
        "to": [
            {
                "namespaceSelector": {},
                "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
            }
        ],
        "ports": [{"protocol": "UDP", "port": 53}],
    }

    policies = [
        # 1. Default deny all
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "default-deny-all",
                "namespace": namespace,
                "labels": common_labels,
            },
            "spec": {
                "podSelector": {},
                "policyTypes": ["Ingress", "Egress"],
            },
        },
        # 2. Envoy proxy (API gateway) — accepts external traffic, routes to backends
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-envoy-proxy",
                "namespace": namespace,
                "labels": common_labels,
            },
            "spec": {
                "podSelector": {"matchLabels": {"app.kubernetes.io/name": "envoy-proxy"}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "ports": [
                            {"protocol": "TCP", "port": 8080},
                            {"protocol": "TCP", "port": 8081},
                        ]
                    }
                ],
                "egress": [
                    {
                        "to": [
                            {
                                "podSelector": {
                                    "matchLabels": {"app.kubernetes.io/part-of": "unguard"}
                                }
                            }
                        ],
                        "ports": [{"protocol": "TCP", "port": 80}],
                    },
                    dns_egress_rule,
                ],
            },
        },
        # 3. Frontend — ingress from envoy only
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-frontend",
                "namespace": namespace,
                "labels": common_labels,
            },
            "spec": {
                "podSelector": {"matchLabels": {"app.kubernetes.io/name": "frontend"}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "podSelector": {
                                    "matchLabels": {"app.kubernetes.io/name": "envoy-proxy"}
                                }
                            }
                        ],
                        "ports": [{"protocol": "TCP", "port": 80}],
                    }
                ],
                "egress": [
                    {
                        "to": [
                            {
                                "podSelector": {
                                    "matchLabels": {"app.kubernetes.io/name": "envoy-proxy"}
                                }
                            }
                        ],
                        "ports": [{"protocol": "TCP", "port": 8080}],
                    },
                    dns_egress_rule,
                ],
            },
        },
        # 4. MariaDB — ingress from auth, microblog, like only
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-mariadb",
                "namespace": namespace,
                "labels": common_labels,
            },
            "spec": {
                "podSelector": {"matchLabels": {"app.kubernetes.io/name": "mariadb"}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "podSelector": {
                                    "matchLabels": {"app.kubernetes.io/name": "user-auth-service"}
                                }
                            },
                            {
                                "podSelector": {
                                    "matchLabels": {"app.kubernetes.io/name": "microblog-service"}
                                }
                            },
                            {
                                "podSelector": {
                                    "matchLabels": {"app.kubernetes.io/name": "like-service"}
                                }
                            },
                        ],
                        "ports": [{"protocol": "TCP", "port": 3306}],
                    }
                ],
                "egress": [],
            },
        },
        # 5. Redis — ingress from microblog and status only
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-redis",
                "namespace": namespace,
                "labels": common_labels,
            },
            "spec": {
                "podSelector": {"matchLabels": {"app.kubernetes.io/name": "redis"}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "podSelector": {
                                    "matchLabels": {"app.kubernetes.io/name": "microblog-service"}
                                }
                            },
                            {
                                "podSelector": {
                                    "matchLabels": {"app.kubernetes.io/name": "status-service"}
                                }
                            },
                        ],
                        "ports": [{"protocol": "TCP", "port": 6379}],
                    }
                ],
                "egress": [],
            },
        },
        # 6. Backend services — ingress from envoy, egress to data stores + DNS
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": "allow-backend-services",
                "namespace": namespace,
                "labels": common_labels,
            },
            "spec": {
                "podSelector": {"matchLabels": {"app.kubernetes.io/part-of": "unguard"}},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [
                    {
                        "from": [
                            {
                                "podSelector": {
                                    "matchLabels": {"app.kubernetes.io/name": "envoy-proxy"}
                                }
                            }
                        ],
                        "ports": [{"protocol": "TCP", "port": 80}],
                    }
                ],
                "egress": [
                    {
                        "to": [
                            {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "mariadb"}}}
                        ],
                        "ports": [{"protocol": "TCP", "port": 3306}],
                    },
                    {
                        "to": [
                            {"podSelector": {"matchLabels": {"app.kubernetes.io/name": "redis"}}}
                        ],
                        "ports": [{"protocol": "TCP", "port": 6379}],
                    },
                    {
                        "to": [
                            {
                                "podSelector": {
                                    "matchLabels": {"app.kubernetes.io/name": "envoy-proxy"}
                                }
                            }
                        ],
                        "ports": [{"protocol": "TCP", "port": 8080}],
                    },
                    dns_egress_rule,
                ],
            },
        },
    ]

    return policies


class MissingNetworkPoliciesExploit(BaseExploit):
    """Exploit demonstrating risks of missing network policies.

    Unlike container-level exploits that patch deployments, this exploit
    operates at the namespace level by creating and removing NetworkPolicy
    resources. The ``make_secure`` method creates restrictive policies and
    ``make_vulnerable`` removes them, restoring the flat network default.
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

    def get_default_service(self) -> str:
        """Return a representative service for connectivity tests."""
        return "unguard-ad-service"

    def get_vulnerable_patch(self) -> list[dict[str, Any]]:
        """Not used — vulnerability is the absence of network policies."""
        return []

    def get_secure_patch(self) -> list[dict[str, Any]]:
        """Not used — remediation creates NetworkPolicy resources."""
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
        return True

    def make_secure(self, dry_run: bool = False) -> bool:
        """Create network policies to enforce segmentation."""
        self.logger.info(f"Applying network policies to {self.k8s.namespace}...")
        policies = _build_network_policies(self.k8s.namespace)
        applied = 0

        for policy in policies:
            if self.k8s.create_network_policy(policy, self.k8s.namespace, dry_run=dry_run):
                applied += 1

        if not dry_run:
            self.logger.success(f"Applied {applied}/{len(policies)} NetworkPolicies")

            if applied == len(policies) and not self.k8s.daemonset_exists(
                "kube-router", "kube-system"
            ):
                self.logger.warning(
                    "NetworkPolicies created but enforcement may not be active. "
                    "Run 'kimera enforce enable' to install kube-router."
                )

        return applied == len(policies)

    def demonstrate(self) -> ExploitResult:
        """Demonstrate network policy absence by running connectivity tests."""
        self.logger.exploit("Demonstrating missing network policy risks...")

        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return ExploitResult(
                success=False,
                message=f"Pod not found for {self.service}",
            )

        evidence: list[str] = []
        impact: list[str] = []

        # Test 1: Cross-namespace DNS enumeration
        self.logger.exploit("Test 1: DNS service enumeration")
        try:
            result = self.k8s.exec_in_pod(
                pod_name,
                """
                echo "[*] Enumerating services via DNS..."
                found=0
                for svc in frontend mariadb redis user-auth-service \
                           microblog-service payment-service proxy-service \
                           envoy-proxy ad-service like-service \
                           membership-service status-service; do
                    fqdn="unguard-${svc}.$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace).svc.cluster.local"
                    if nslookup "$fqdn" >/dev/null 2>&1; then
                        addr=$(nslookup "$fqdn" 2>/dev/null | grep "Address" | tail -1 | awk '{print $2}')
                        echo "  FOUND: ${svc} -> ${addr}"
                        found=$((found + 1))
                    fi
                done
                echo "[*] Total services discovered: $found"
                """,
            )
            print(result)

            if "FOUND:" in result:
                count = result.count("FOUND:")
                evidence.append(f"DNS enumeration discovered {count} services")
                impact.append("Attacker can map all services via predictable DNS names")

        except Exception as e:
            self.logger.error(f"Test 1 failed: {e}")

        # Test 2: Data store connectivity
        self.logger.exploit("Test 2: Data store accessibility")
        try:
            result = self.k8s.exec_in_pod(
                pod_name,
                """
                echo "[*] Testing data store connectivity..."

                echo -n "  MariaDB :3306 -> "
                if nc -z -w 3 unguard-mariadb 3306 2>/dev/null; then
                    echo "OPEN"
                else
                    echo "CLOSED"
                fi

                echo -n "  Redis :6379 -> "
                if nc -z -w 3 unguard-redis 6379 2>/dev/null; then
                    echo "OPEN"
                fi

                echo "[*] Redis key count:"
                (echo "DBSIZE"; sleep 1) | nc -w 3 unguard-redis 6379 2>/dev/null \
                  | grep -v "^$" || echo "  Connection failed"
                """,
            )
            print(result)

            if "MariaDB" in result and "OPEN" in result:
                evidence.append("MariaDB :3306 reachable from ad-service")
                impact.append("Database accessible from unauthorized service")

            if "Redis" in result and "OPEN" in result:
                evidence.append("Redis :6379 reachable without authentication")
                impact.append("Cache data (sessions, posts) exposed to all pods")

        except Exception as e:
            self.logger.error(f"Test 2 failed: {e}")

        # Test 3: Infrastructure reachability
        self.logger.exploit("Test 3: Infrastructure access from application pod")
        try:
            result = self.k8s.exec_in_pod(
                pod_name,
                """
                echo "[*] Testing infrastructure reachability..."

                echo -n "  Kubernetes API :6443 -> "
                if nc -z -w 2 kubernetes.default.svc.cluster.local 443 2>/dev/null; then
                    echo "OPEN"
                else
                    echo "CLOSED"
                fi

                echo "[*] Service account token:"
                if [ -f /var/run/secrets/kubernetes.io/serviceaccount/token ]; then
                    echo "  Present ($(wc -c < /var/run/secrets/kubernetes.io/serviceaccount/token) bytes)"
                else
                    echo "  Not mounted"
                fi
                """,
            )
            print(result)

            if "API" in result and "OPEN" in result:
                evidence.append("Kubernetes API server reachable from application pod")
                impact.append("Combined with SA token, enables cluster enumeration")

        except Exception as e:
            self.logger.error(f"Test 3 failed: {e}")

        # Test 4: Cross-namespace access
        self.logger.exploit("Test 4: Cross-namespace reachability")
        try:
            result = self.k8s.exec_in_pod(
                pod_name,
                """
                echo "[*] Testing cross-namespace access..."

                echo -n "  CoreDNS (kube-system) :53 -> "
                if nc -z -w 2 kube-dns.kube-system.svc.cluster.local 53 2>/dev/null; then
                    echo "REACHABLE"
                else
                    echo "BLOCKED"
                fi

                echo -n "  Dynatrace ActiveGate :443 -> "
                if nc -z -w 2 \
                     dt-casp-misconfiguration-demo-activegate.dynatrace.svc.cluster.local \
                     443 2>/dev/null; then
                    echo "REACHABLE"
                else
                    echo "BLOCKED"
                fi
                """,
            )
            print(result)

            if "REACHABLE" in result:
                evidence.append("Cross-namespace services reachable from application pod")
                impact.append("No namespace isolation — blast radius is cluster-wide")

        except Exception as e:
            self.logger.error(f"Test 4 failed: {e}")

        # Summary
        self.logger.exploit("=== Impact Summary ===")
        summary_impact = [
            "Any pod can discover all services via DNS",
            "Data stores (MariaDB, Redis) accessible from any namespace",
            "No network segmentation between services",
            "Infrastructure components (API server, kubelet) reachable",
            "Lateral movement possible across entire cluster",
            "Compromised pod has full network access to all backends",
        ]

        for item in summary_impact:
            print(f"  • {item}")

        return ExploitResult(
            success=bool(evidence),
            message="Missing network policies exploit demonstrated",
            evidence=evidence,
            impact=impact + summary_impact,
        )
