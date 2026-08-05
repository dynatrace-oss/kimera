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


import logging
from typing import Any

from kubernetes.client import ApiException

from ...application.config.schemas import NetworkTopologyEntry
from ..core.k8s_client import K8sClient
from .external_egress import find_external_gaps, unmatched_declarations
from .models import ControlType, ValidationResult, ValidationVerdict
from .reachability import Workload, find_gaps, find_ingress_gaps

logger = logging.getLogger(__name__)


def _discover_namespace_services(
    k8s: K8sClient,
    namespace: str,
) -> list[dict[str, Any]]:
    """Discover services in the namespace for intra-namespace connectivity testing."""
    services: list[dict[str, Any]] = []
    try:
        svc_list = k8s.v1.list_namespaced_service(namespace)
        for svc in svc_list.items:
            if svc.spec.ports:
                for port_spec in svc.spec.ports:
                    services.append(
                        {
                            "name": svc.metadata.name,
                            "port": port_spec.port,
                            "protocol": port_spec.protocol or "TCP",
                        }
                    )
    except ApiException:
        pass
    return services


def _check_default_deny(k8s: K8sClient, namespace: str) -> ValidationResult | None:
    """Check whether a default-deny NetworkPolicy exists."""
    try:
        policies = k8s.list_network_policies(namespace)
    except Exception:
        return None

    if not policies:
        return ValidationResult(
            control_type=ControlType.NETWORK_POLICY,
            control_name="default-deny",
            test_description="Namespace should have a default-deny NetworkPolicy",
            expected="EXISTS",
            actual="MISSING",
            verdict=ValidationVerdict.FAIL,
            evidence=f"No NetworkPolicies found in namespace {namespace}",
            remediation_hint=(
                "Create a default-deny policy:\n"
                "  apiVersion: networking.k8s.io/v1\n"
                "  kind: NetworkPolicy\n"
                "  metadata:\n"
                f"    name: default-deny\n"
                f"    namespace: {namespace}\n"
                "  spec:\n"
                "    podSelector: {}\n"
                "    policyTypes: [Ingress, Egress]"
            ),
        )

    # Check for a policy with empty podSelector and both Ingress+Egress types
    for policy in policies:
        pod_sel = policy.spec.pod_selector
        policy_types = policy.spec.policy_types or []
        is_empty_selector = not pod_sel or not pod_sel.match_labels
        has_both = "Ingress" in policy_types and "Egress" in policy_types
        has_no_rules = not policy.spec.ingress and not policy.spec.egress

        if is_empty_selector and has_both and has_no_rules:
            return ValidationResult(
                control_type=ControlType.NETWORK_POLICY,
                control_name="default-deny",
                test_description="Namespace should have a default-deny NetworkPolicy",
                expected="EXISTS",
                actual="EXISTS",
                verdict=ValidationVerdict.PASS,
                evidence=f"Policy '{policy.metadata.name}' implements default-deny",
            )

    return ValidationResult(
        control_type=ControlType.NETWORK_POLICY,
        control_name="default-deny",
        test_description="Namespace should have a default-deny NetworkPolicy",
        expected="EXISTS",
        actual="PARTIAL (policies exist but no full default-deny)",
        verdict=ValidationVerdict.FAIL,
        evidence=(
            f"Found {len(policies)} policies but none implement full default-deny "
            "(empty podSelector + Ingress + Egress with no rules)."
        ),
        remediation_hint="Add a default-deny policy covering both Ingress and Egress.",
    )


def _check_policy_reachability(
    k8s: K8sClient,
    namespace: str,
    network_topology: dict[str, NetworkTopologyEntry] | None = None,
) -> list[ValidationResult]:
    """Report flows the policy set declares but denies.

    The probe-pod tests below only ever measure an unlabeled pod, so a policy set
    that severs a real workload-to-workload path still passes them. This check
    reads the flows the policy set declares — pod-to-pod, and the external
    destinations the profile declares — and confirms both sides agree.
    """
    try:
        policies_raw = k8s.list_network_policies(namespace)
        pods_raw = k8s.v1.list_namespaced_pod(namespace)
    except ApiException as e:
        logger.warning("Could not read policies or pods for reachability check: %s", e)
        return []

    if not policies_raw:
        return []

    serialize = k8s.v1.api_client.sanitize_for_serialization
    policies = [serialize(p) for p in policies_raw]
    workloads = [
        Workload(name=p.metadata.name, labels=dict(p.metadata.labels or {})) for p in pods_raw.items
    ]

    results = [
        ValidationResult(
            control_type=ControlType.NETWORK_POLICY,
            control_name="policy-reachability",
            test_description=f"{gap.source} -> {gap.destination}:{gap.port} should be permitted",
            expected="REACHABLE",
            actual="EGRESS_DENIED",
            verdict=ValidationVerdict.ERROR,
            evidence=gap.describe(),
            remediation_hint=(
                f"Add an egress rule on {gap.source} permitting "
                f"{gap.destination_selector} on port {gap.port}. A NetworkPolicy allows "
                "a flow only when the source's egress and the destination's ingress "
                "both permit it."
            ),
        )
        for gap in find_gaps(policies, workloads)
    ]

    results.extend(
        ValidationResult(
            control_type=ControlType.NETWORK_POLICY,
            control_name="policy-reachability",
            test_description=(
                f"{gap.source} -> {gap.destination}:{gap.port} is declared and should be reachable"
            ),
            expected="REACHABLE",
            actual="INGRESS_DENIED",
            verdict=ValidationVerdict.ERROR,
            evidence=gap.describe(),
            remediation_hint=(
                f"Add an ingress rule on {gap.destination} admitting {gap.source} on port "
                f"{gap.port}, or drop the egress rule that declares the flow. This is reported "
                "rather than corrected automatically: who may reach a workload is the "
                "destination's decision, and inferring a rule would grant access nobody declared."
            ),
        )
        for gap in find_ingress_gaps(policies, workloads)
    )

    for name in unmatched_declarations(workloads, network_topology or {}):
        logger.warning(
            "Topology key '%s' declares external egress but matches no pod in %s", name, namespace
        )

    results.extend(
        ValidationResult(
            control_type=ControlType.NETWORK_POLICY,
            control_name="external-egress-reachability",
            test_description=(
                f"{gap.workload} -> {gap.cidr}:{gap.port} is declared and should be permitted"
            ),
            expected="REACHABLE",
            actual="EGRESS_DENIED",
            verdict=ValidationVerdict.ERROR,
            evidence=gap.describe(),
            remediation_hint=(
                f"Add an egress rule on {gap.workload} with an ipBlock for {gap.cidr} "
                f"on port {gap.port}. A workload whose external dependency is severed "
                "keeps passing every app-to-app check while failing to start."
            ),
        )
        for gap in find_external_gaps(policies, workloads, network_topology or {})
    )

    if results:
        return results

    return [
        ValidationResult(
            control_type=ControlType.NETWORK_POLICY,
            control_name="policy-reachability",
            test_description="Every flow the policy set declares is permitted end to end",
            expected="REACHABLE",
            actual="REACHABLE",
            verdict=ValidationVerdict.PASS,
            evidence="All declared flows, pod-to-pod and external, have matching egress rules",
            remediation_hint="",
        )
    ]
