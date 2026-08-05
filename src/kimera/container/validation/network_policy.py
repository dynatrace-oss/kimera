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

"""Validate that NetworkPolicies actually block traffic they claim to block.

Deploys an ephemeral probe pod into the namespace, attempts connections that
policies should block, and reports whether the control held. The probe pod
is auto-cleaned after validation.
"""

import logging
import time
from typing import Any

from kubernetes.client import ApiException

from ...application.config.schemas import NetworkTopologyEntry
from ..core.k8s_client import K8sClient
from ..core.logger import SecurityLogger
from ..make_vulnerable.probe_prelude import PROBE_PRELUDE, UNKNOWN_STATE
from .external_egress import find_external_gaps, unmatched_declarations
from .models import (
    ControlType,
    ValidationReport,
    ValidationResult,
    ValidationVerdict,
)
from .reachability import Workload, find_gaps

logger = logging.getLogger(__name__)

PROBE_POD_NAME = "kimera-netpol-probe"
PROBE_IMAGE = "busybox:1.36"
PROBE_LABELS = {
    "app.kubernetes.io/managed-by": "kimera",
    "app.kubernetes.io/component": "netpol-probe",
}

# Targets to test connectivity against
INFRASTRUCTURE_TARGETS: list[dict[str, Any]] = [
    {
        "host": "kubernetes.default.svc.cluster.local",
        "port": 443,
        "label": "Kubernetes API server",
        "should_block": True,
        "remediation": (
            "Add an egress NetworkPolicy denying access to the Kubernetes API server "
            "from application pods, or use a default-deny egress policy."
        ),
    },
]

CROSS_NAMESPACE_TARGETS: list[dict[str, Any]] = [
    {
        "host": "kube-dns.kube-system.svc.cluster.local",
        "port": 53,
        "label": "CoreDNS (kube-system)",
        "should_block": False,  # DNS is usually allowed
        "remediation": "",
    },
    {
        "host": "kube-dns.kube-system.svc.cluster.local",
        "port": 9153,
        "label": "CoreDNS metrics (kube-system)",
        "should_block": True,
        "remediation": (
            "Add an egress NetworkPolicy restricting access to kube-system ports "
            "other than DNS (53/TCP, 53/UDP)."
        ),
    },
]

# Cloud metadata endpoints (SSRF vector)
METADATA_TARGETS: list[dict[str, Any]] = [
    {
        "host": "169.254.169.254",
        "port": 80,
        "label": "Cloud metadata API (SSRF vector)",
        "should_block": True,
        "remediation": (
            "Add a NetworkPolicy egress rule blocking 169.254.169.254/32. "
            "On AWS, also enable IMDSv2 with hop limit 1."
        ),
    },
]


def _deploy_probe_pod(k8s: K8sClient, namespace: str) -> str | None:
    """Deploy an ephemeral busybox probe pod for network testing.

    Returns:
        ``None`` on success, otherwise the reason the pod could not be run. The
        reason is reported as evidence: a probe rejected by admission control and
        a probe that never became ready are different facts about the namespace.
    """
    pod_body: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": PROBE_POD_NAME,
            "namespace": namespace,
            "labels": PROBE_LABELS,
        },
        "spec": {
            "containers": [
                {
                    "name": "probe",
                    "image": PROBE_IMAGE,
                    "command": ["sleep", "300"],
                    "resources": {
                        "limits": {"cpu": "10m", "memory": "16Mi"},
                        "requests": {"cpu": "10m", "memory": "16Mi"},
                    },
                    "securityContext": {
                        "runAsNonRoot": False,
                        "allowPrivilegeEscalation": False,
                    },
                }
            ],
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 0,
            # Auto-cleanup after 5 minutes via activeDeadlineSeconds
            "activeDeadlineSeconds": 300,
        },
    }

    try:
        k8s.v1.create_namespaced_pod(namespace=namespace, body=pod_body)
    except ApiException as e:
        if e.status == 409:
            # Pod already exists — delete and recreate
            try:
                k8s.v1.delete_namespaced_pod(PROBE_POD_NAME, namespace)
                time.sleep(5)
                k8s.v1.create_namespaced_pod(namespace=namespace, body=pod_body)
            except ApiException as retry_error:
                return f"recreate failed: HTTP {retry_error.status} {retry_error.reason}"
        elif e.status in (403, 422):
            # Admission rejected — that's actually useful info
            logger.warning(
                "Probe pod rejected by admission controller: %s. "
                "This may indicate strict policies that also block the probe itself.",
                e.reason,
            )
            return f"rejected by admission control: HTTP {e.status} {e.reason}"
        else:
            return f"create failed: HTTP {e.status} {e.reason}"

    # Wait for pod to be running
    for _ in range(30):
        try:
            pod = k8s.v1.read_namespaced_pod(PROBE_POD_NAME, namespace)
            if pod.status.phase == "Running":
                return None
        except ApiException:
            pass
        time.sleep(2)

    return "probe pod never reached Running within 60s"


def _cleanup_probe_pod(k8s: K8sClient, namespace: str) -> None:
    """Remove the probe pod."""
    try:
        k8s.v1.delete_namespaced_pod(
            PROBE_POD_NAME,
            namespace,
            grace_period_seconds=0,
        )
    except ApiException:
        pass


def _test_connectivity(
    k8s: K8sClient,
    namespace: str,
    host: str,
    port: int,
    timeout: int = 3,
) -> str:
    """Test TCP connectivity from the probe pod.

    Returns:
        ``"OPEN"``, ``"CLOSED"``, or ``UNKNOWN_STATE`` when the probe pod has no
        usable probe tool. ``UNKNOWN_STATE`` must never be collapsed into
        ``"CLOSED"`` — an untested port is not a blocked port.
    """
    cmd = f"{PROBE_PRELUDE}\nkimera_port_open {host} {port} {timeout}"
    try:
        output = k8s.exec_in_pod(PROBE_POD_NAME, cmd, container="probe")
    except Exception:
        return UNKNOWN_STATE
    if "OPEN" in output:
        return "OPEN"
    if "CLOSED" in output:
        return "CLOSED"
    return UNKNOWN_STATE


def _verdict_for(state: str, host: str, port: int) -> tuple[str, ValidationVerdict, str]:
    """Map a probe state to (actual, verdict, evidence).

    An ``UNKNOWN_STATE`` probe never yields PASS or FAIL: nothing was measured, so
    the check is reported as ERROR rather than asserting the control's behaviour.
    """
    if state == UNKNOWN_STATE:
        return (
            "UNKNOWN",
            ValidationVerdict.ERROR,
            f"probe {host}:{port}: {UNKNOWN_STATE} - control not verified",
        )
    reachable = state == "OPEN"
    return (
        "ALLOWED" if reachable else "BLOCKED",
        ValidationVerdict.FAIL if reachable else ValidationVerdict.PASS,
        f"probe {host}:{port}: {state}",
    )


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


def validate_network_policies(
    k8s: K8sClient,
    sec_logger: SecurityLogger,
    network_topology: dict[str, NetworkTopologyEntry] | None = None,
) -> ValidationReport:
    """Validate that NetworkPolicies actually block unauthorized traffic.

    Deploys an ephemeral probe pod, tests connectivity against infrastructure,
    cross-namespace services, and cloud metadata endpoints, then compares
    actual connectivity against what policies should block.

    Args:
        k8s: Kubernetes client.
        sec_logger: Security logger for console output.
        network_topology: Profile topology, so declared external egress is checked
            alongside the pod-to-pod flows.

    Returns:
        ValidationReport with results for each connectivity test.
    """
    namespace = k8s.namespace
    report = ValidationReport(namespace=namespace, control_type=ControlType.NETWORK_POLICY)

    # Check default-deny first (no probe needed)
    default_deny_result = _check_default_deny(k8s, namespace)
    if default_deny_result:
        report.results.append(default_deny_result)

    reachability_results = _check_policy_reachability(k8s, namespace, network_topology)
    report.results.extend(reachability_results)
    broken = [r for r in reachability_results if r.verdict == ValidationVerdict.ERROR]
    if broken:
        sec_logger.warning(
            f"{len(broken)} declared flow(s) are severed: ingress permits them but "
            "the source's egress does not"
        )

    # Count existing policies
    try:
        policies = k8s.list_network_policies(namespace)
        sec_logger.info(f"Found {len(policies)} NetworkPolicies in {namespace}")
        for p in policies:
            sec_logger.info(f"  • {p.metadata.name}")
    except Exception:
        policies = []

    # Deploy probe pod
    sec_logger.info("Deploying network probe pod...")
    probe_failure = _deploy_probe_pod(k8s, namespace)

    if probe_failure is not None:
        sec_logger.warning(
            f"Could not deploy probe pod ({probe_failure}). "
            "Active connectivity tests were NOT executed — no control below was verified."
        )
        # Recorded as ERROR, not omitted: a ratio computed over only the static checks
        # reads as a pass for controls nothing measured.
        report.results.append(
            ValidationResult(
                control_type=ControlType.NETWORK_POLICY,
                control_name="active-connectivity-tests",
                test_description=(
                    "Probe pod reaches blocked targets (metadata, API server, cross-namespace, "
                    "intra-namespace) to prove the policies hold"
                ),
                expected="EXECUTED",
                actual="NOT_EXECUTED",
                verdict=ValidationVerdict.ERROR,
                evidence=f"probe pod could not be run: {probe_failure}",
                remediation_hint=(
                    "Grant the probe pod the security context the namespace's Pod Security "
                    "Admission level requires, or run validation from a namespace that permits "
                    "it. Until it runs, these controls are unverified, not passing."
                ),
            )
        )
        report.summary = (
            f"NetworkPolicy validation: {report.passed}/{report.total} static checks passed; "
            f"active connectivity tests NOT executed ({probe_failure})."
        )
        return report

    try:
        # Test cloud metadata endpoint (SSRF vector)
        for target in METADATA_TARGETS:
            sec_logger.info(f"Testing: {target['label']}...")
            state = _test_connectivity(k8s, namespace, target["host"], target["port"])
            actual, verdict, evidence = _verdict_for(state, target["host"], target["port"])

            if target["should_block"]:
                report.results.append(
                    ValidationResult(
                        control_type=ControlType.NETWORK_POLICY,
                        control_name="cloud-metadata-block",
                        test_description=f"{target['label']} should be blocked",
                        expected="BLOCK",
                        actual=actual,
                        verdict=verdict,
                        evidence=evidence,
                        remediation_hint=target.get("remediation", ""),
                    )
                )

        # Test infrastructure targets
        for target in INFRASTRUCTURE_TARGETS:
            sec_logger.info(f"Testing: {target['label']}...")
            state = _test_connectivity(k8s, namespace, target["host"], target["port"])
            actual, verdict, evidence = _verdict_for(state, target["host"], target["port"])

            if target["should_block"]:
                report.results.append(
                    ValidationResult(
                        control_type=ControlType.NETWORK_POLICY,
                        control_name="infrastructure-isolation",
                        test_description=f"{target['label']} should be blocked from app pods",
                        expected="BLOCK",
                        actual=actual,
                        verdict=verdict,
                        evidence=evidence,
                        remediation_hint=target.get("remediation", ""),
                    )
                )

        # Test cross-namespace connectivity
        for target in CROSS_NAMESPACE_TARGETS:
            sec_logger.info(f"Testing: {target['label']}...")
            state = _test_connectivity(k8s, namespace, target["host"], target["port"])
            actual, verdict, evidence = _verdict_for(state, target["host"], target["port"])

            if target["should_block"]:
                report.results.append(
                    ValidationResult(
                        control_type=ControlType.NETWORK_POLICY,
                        control_name="cross-namespace-isolation",
                        test_description=f"{target['label']} should be blocked",
                        expected="BLOCK",
                        actual=actual,
                        verdict=verdict,
                        evidence=evidence,
                        remediation_hint=target.get("remediation", ""),
                    )
                )

        # Test intra-namespace connectivity (services that should be unreachable
        # from a pod with no matching labels)
        namespace_services = _discover_namespace_services(k8s, namespace)
        if namespace_services and policies:
            sec_logger.info("Testing intra-namespace isolation...")
            # Our probe pod has kimera labels — most policies should not allow it
            # to reach application services
            for svc in namespace_services[:5]:  # Cap at 5 to limit test time
                svc_name = svc["name"]
                svc_port = svc["port"]
                state = _test_connectivity(k8s, namespace, svc_name, svc_port)
                actual, verdict, evidence = _verdict_for(state, svc_name, svc_port)

                report.results.append(
                    ValidationResult(
                        control_type=ControlType.NETWORK_POLICY,
                        control_name="intra-namespace-isolation",
                        test_description=(
                            f"Unlabeled probe pod should not reach {svc_name}:{svc_port}"
                        ),
                        expected="BLOCK",
                        actual=actual,
                        verdict=verdict,
                        evidence=evidence,
                        remediation_hint=(
                            f"Ensure NetworkPolicy for {svc_name} uses specific podSelector "
                            "labels in ingress rules, not an empty selector."
                        )
                        if state == "OPEN"
                        else "",
                    )
                )

    finally:
        sec_logger.info("Cleaning up probe pod...")
        _cleanup_probe_pod(k8s, namespace)

    passed = report.passed
    failed = report.failed
    total = report.total
    report.summary = (
        f"NetworkPolicy validation: {passed}/{total} passed, {failed} failed. "
        f"Policies in namespace: {len(policies)}."
    )

    return report
