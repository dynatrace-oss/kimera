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


from ...application.config.schemas import NetworkTopologyEntry
from ..core.k8s_client import K8sClient
from ..core.logger import SecurityLogger
from .models import (
    ControlType,
    ValidationReport,
    ValidationResult,
    ValidationVerdict,
)
from .netpol_checks import (
    _check_default_deny,
    _check_policy_reachability,
    _discover_namespace_services,
)
from .netpol_probe import _cleanup_probe_pod, _deploy_probe_pod, _test_connectivity
from .netpol_targets import (
    CROSS_NAMESPACE_TARGETS,
    INFRASTRUCTURE_TARGETS,
    METADATA_TARGETS,
    _verdict_for,
)

# Each table is probed identically; only the control name it reports under differs.
_TARGET_SUITES = (
    (METADATA_TARGETS, "cloud-metadata-block"),
    (INFRASTRUCTURE_TARGETS, "infrastructure-isolation"),
    (CROSS_NAMESPACE_TARGETS, "cross-namespace-isolation"),
)

# Probing every service would make validation scale with namespace size.
_MAX_INTRA_NAMESPACE_TARGETS = 5


def validate_network_policies(
    k8s: K8sClient,
    sec_logger: SecurityLogger,
    network_topology: dict[str, NetworkTopologyEntry] | None = None,
) -> ValidationReport:
    """Validate that NetworkPolicies actually block unauthorized traffic.

    Deploys an ephemeral probe pod, tests connectivity against infrastructure,
    cross-namespace services and metadata endpoints, then compares it to policy.

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
        for targets, control_name in _TARGET_SUITES:
            for target in targets:
                sec_logger.info(f"Testing: {target['label']}...")
                state = _test_connectivity(k8s, namespace, target["host"], target["port"])
                actual, verdict, evidence = _verdict_for(state, target["host"], target["port"])
                if target["should_block"]:
                    report.results.append(
                        ValidationResult(
                            control_type=ControlType.NETWORK_POLICY,
                            control_name=control_name,
                            test_description=f"{target['label']} should be blocked",
                            expected="BLOCK",
                            actual=actual,
                            verdict=verdict,
                            evidence=evidence,
                            remediation_hint=target.get("remediation", ""),
                        )
                    )

        # Services that should be unreachable from a pod with no matching labels.
        # The probe pod carries kimera labels, so most policies should not admit it.
        namespace_services = _discover_namespace_services(k8s, namespace)
        if namespace_services and policies:
            sec_logger.info("Testing intra-namespace isolation...")
            for svc in namespace_services[:_MAX_INTRA_NAMESPACE_TARGETS]:
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
