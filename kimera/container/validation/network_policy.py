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

from ..core.k8s_client import K8sClient
from ..core.logger import SecurityLogger
from .models import (
    ControlType,
    ValidationReport,
    ValidationResult,
    ValidationVerdict,
)

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


def _deploy_probe_pod(k8s: K8sClient, namespace: str) -> bool:
    """Deploy an ephemeral busybox probe pod for network testing."""
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
            except ApiException:
                return False
        elif e.status in (403, 422):
            # Admission rejected — that's actually useful info
            logger.warning(
                "Probe pod rejected by admission controller: %s. "
                "This may indicate strict policies that also block the probe itself.",
                e.reason,
            )
            return False
        else:
            return False

    # Wait for pod to be running
    for _ in range(30):
        try:
            pod = k8s.v1.read_namespaced_pod(PROBE_POD_NAME, namespace)
            if pod.status.phase == "Running":
                return True
        except ApiException:
            pass
        time.sleep(2)

    return False


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
) -> bool:
    """Test TCP connectivity from probe pod. Returns True if connection succeeds."""
    cmd = f"nc -z -w {timeout} {host} {port} 2>&1 && echo OPEN || echo CLOSED"
    try:
        output = k8s.exec_in_pod(PROBE_POD_NAME, cmd, container="probe")
        return "OPEN" in output
    except Exception:
        return False


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
                    services.append({
                        "name": svc.metadata.name,
                        "port": port_spec.port,
                        "protocol": port_spec.protocol or "TCP",
                    })
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
        has_no_rules = (
            not policy.spec.ingress and not policy.spec.egress
        )

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


def validate_network_policies(
    k8s: K8sClient,
    sec_logger: SecurityLogger,
) -> ValidationReport:
    """Validate that NetworkPolicies actually block unauthorized traffic.

    Deploys an ephemeral probe pod, tests connectivity against infrastructure,
    cross-namespace services, and cloud metadata endpoints, then compares
    actual connectivity against what policies should block.

    Args:
        k8s: Kubernetes client.
        sec_logger: Security logger for console output.

    Returns:
        ValidationReport with results for each connectivity test.
    """
    namespace = k8s.namespace
    report = ValidationReport(namespace=namespace, control_type=ControlType.NETWORK_POLICY)

    # Check default-deny first (no probe needed)
    default_deny_result = _check_default_deny(k8s, namespace)
    if default_deny_result:
        report.results.append(default_deny_result)

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
    probe_deployed = _deploy_probe_pod(k8s, namespace)

    if not probe_deployed:
        sec_logger.warning(
            "Could not deploy probe pod. Admission controllers may be blocking it. "
            "Skipping active connectivity tests."
        )
        report.summary = (
            f"NetworkPolicy validation: {report.passed}/{report.total} passed "
            f"(probe pod deployment failed — active tests skipped)."
        )
        return report

    try:
        # Test cloud metadata endpoint (SSRF vector)
        for target in METADATA_TARGETS:
            sec_logger.info(f"Testing: {target['label']}...")
            reachable = _test_connectivity(
                k8s, namespace, target["host"], target["port"]
            )

            if target["should_block"]:
                report.results.append(ValidationResult(
                    control_type=ControlType.NETWORK_POLICY,
                    control_name="cloud-metadata-block",
                    test_description=f"{target['label']} should be blocked",
                    expected="BLOCK",
                    actual="ALLOWED" if reachable else "BLOCKED",
                    verdict=ValidationVerdict.FAIL if reachable else ValidationVerdict.PASS,
                    evidence=f"nc -z {target['host']} {target['port']}: {'OPEN' if reachable else 'CLOSED'}",
                    remediation_hint=target.get("remediation", ""),
                ))

        # Test infrastructure targets
        for target in INFRASTRUCTURE_TARGETS:
            sec_logger.info(f"Testing: {target['label']}...")
            reachable = _test_connectivity(
                k8s, namespace, target["host"], target["port"]
            )

            if target["should_block"]:
                report.results.append(ValidationResult(
                    control_type=ControlType.NETWORK_POLICY,
                    control_name="infrastructure-isolation",
                    test_description=f"{target['label']} should be blocked from app pods",
                    expected="BLOCK",
                    actual="ALLOWED" if reachable else "BLOCKED",
                    verdict=ValidationVerdict.FAIL if reachable else ValidationVerdict.PASS,
                    evidence=f"nc -z {target['host']} {target['port']}: {'OPEN' if reachable else 'CLOSED'}",
                    remediation_hint=target.get("remediation", ""),
                ))

        # Test cross-namespace connectivity
        for target in CROSS_NAMESPACE_TARGETS:
            sec_logger.info(f"Testing: {target['label']}...")
            reachable = _test_connectivity(
                k8s, namespace, target["host"], target["port"]
            )

            if target["should_block"]:
                report.results.append(ValidationResult(
                    control_type=ControlType.NETWORK_POLICY,
                    control_name="cross-namespace-isolation",
                    test_description=f"{target['label']} should be blocked",
                    expected="BLOCK",
                    actual="ALLOWED" if reachable else "BLOCKED",
                    verdict=ValidationVerdict.FAIL if reachable else ValidationVerdict.PASS,
                    evidence=f"nc -z {target['host']} {target['port']}: {'OPEN' if reachable else 'CLOSED'}",
                    remediation_hint=target.get("remediation", ""),
                ))

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
                reachable = _test_connectivity(k8s, namespace, svc_name, svc_port)

                report.results.append(ValidationResult(
                    control_type=ControlType.NETWORK_POLICY,
                    control_name="intra-namespace-isolation",
                    test_description=(
                        f"Unlabeled probe pod should not reach {svc_name}:{svc_port}"
                    ),
                    expected="BLOCK",
                    actual="ALLOWED" if reachable else "BLOCKED",
                    verdict=ValidationVerdict.FAIL if reachable else ValidationVerdict.PASS,
                    evidence=f"nc -z {svc_name} {svc_port}: {'OPEN' if reachable else 'CLOSED'}",
                    remediation_hint=(
                        f"Ensure NetworkPolicy for {svc_name} uses specific podSelector "
                        "labels in ingress rules, not an empty selector."
                    ) if reachable else "",
                ))

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
