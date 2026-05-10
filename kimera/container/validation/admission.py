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

"""Validate that admission controllers actually reject policy-violating resources.

Uses ``--dry-run=server`` so test resources pass through all admission webhooks
but are never persisted. Safe for production.
"""

import logging
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

# Test resources that well-configured admission controllers should reject.
# Each entry has: id, description, pod spec overrides, expected outcome.
ADMISSION_TEST_CASES: list[dict[str, Any]] = [
    {
        "id": "privileged-container",
        "description": "Privileged container should be rejected",
        "pod_overrides": {
            "securityContext": {"privileged": True},
        },
        "expected_rejection": True,
        "remediation": (
            "Configure PSA 'restricted' or 'baseline' profile on this namespace, "
            "or add a Kyverno/Gatekeeper policy to block privileged containers."
        ),
    },
    {
        "id": "host-pid-namespace",
        "description": "hostPID sharing should be rejected",
        "pod_spec_overrides": {
            "hostPID": True,
        },
        "expected_rejection": True,
        "remediation": (
            "Configure PSA 'restricted' or 'baseline' profile, "
            "or add a policy to block hostPID."
        ),
    },
    {
        "id": "host-network",
        "description": "hostNetwork sharing should be rejected",
        "pod_spec_overrides": {
            "hostNetwork": True,
        },
        "expected_rejection": True,
        "remediation": (
            "Configure PSA 'restricted' or 'baseline' profile, "
            "or add a policy to block hostNetwork."
        ),
    },
    {
        "id": "run-as-root",
        "description": "Container running as root (UID 0) should be rejected",
        "pod_overrides": {
            "securityContext": {"runAsUser": 0},
        },
        "expected_rejection": True,
        "remediation": (
            "Configure PSA 'restricted' profile or add a policy requiring "
            "runAsNonRoot: true."
        ),
    },
    {
        "id": "no-resource-limits",
        "description": "Container without resource limits should be rejected",
        "strip_resources": True,
        "expected_rejection": True,
        "remediation": (
            "Add a LimitRange to the namespace or add a policy requiring "
            "resource limits on all containers."
        ),
    },
    {
        "id": "dangerous-capabilities",
        "description": "Container with SYS_ADMIN capability should be rejected",
        "pod_overrides": {
            "securityContext": {
                "capabilities": {"add": ["SYS_ADMIN"]},
            },
        },
        "expected_rejection": True,
        "remediation": (
            "Configure PSA 'restricted' profile or add a policy blocking "
            "dangerous capabilities (SYS_ADMIN, NET_RAW, SYS_PTRACE)."
        ),
    },
    {
        "id": "privilege-escalation",
        "description": "Container with allowPrivilegeEscalation should be rejected",
        "pod_overrides": {
            "securityContext": {
                "allowPrivilegeEscalation": True,
            },
        },
        "expected_rejection": True,
        "remediation": (
            "Configure PSA 'restricted' profile or add a policy requiring "
            "allowPrivilegeEscalation: false."
        ),
    },
]


def _detect_admission_controllers(k8s: K8sClient) -> list[dict[str, str]]:
    """Detect which admission controllers are active in the cluster.

    Checks for:
    - Pod Security Admission (PSA) via namespace labels
    - Kyverno via CRDs
    - OPA Gatekeeper via CRDs
    - ValidatingWebhookConfigurations
    """
    controllers: list[dict[str, str]] = []

    # Check PSA labels on the target namespace
    try:
        ns = k8s.v1.read_namespace(k8s.namespace)
        labels = ns.metadata.labels or {}
        psa_enforce = labels.get("pod-security.kubernetes.io/enforce", "")
        if psa_enforce:
            controllers.append({
                "type": "PSA",
                "name": f"pod-security.kubernetes.io/enforce={psa_enforce}",
                "level": psa_enforce,
            })
    except ApiException:
        pass

    # Check for Kyverno CRDs
    try:
        from kubernetes.client import ApiextensionsV1Api  # noqa: PLC0415

        api_ext = ApiextensionsV1Api()
        crds = api_ext.list_custom_resource_definition()
        for crd in crds.items:
            if "kyverno.io" in (crd.metadata.name or ""):
                controllers.append({
                    "type": "Kyverno",
                    "name": crd.metadata.name,
                })
                break
    except (ApiException, ImportError):
        pass

    # Check for Gatekeeper CRDs
    try:
        from kubernetes.client import ApiextensionsV1Api  # noqa: PLC0415

        api_ext = ApiextensionsV1Api()
        crds = api_ext.list_custom_resource_definition()
        for crd in crds.items:
            if "gatekeeper.sh" in (crd.metadata.name or ""):
                controllers.append({
                    "type": "OPA/Gatekeeper",
                    "name": crd.metadata.name,
                })
                break
    except (ApiException, ImportError):
        pass

    # Check ValidatingWebhookConfigurations
    try:
        from kubernetes.client import AdmissionregistrationV1Api  # noqa: PLC0415

        admission_api = AdmissionregistrationV1Api()
        webhooks = admission_api.list_validating_webhook_configuration()
        for wh in webhooks.items:
            name = wh.metadata.name or ""
            # Skip kube-system internal webhooks
            if "kube-system" in name or "cert-manager" in name:
                continue
            controllers.append({
                "type": "ValidatingWebhook",
                "name": name,
            })
    except (ApiException, ImportError):
        pass

    return controllers


def _build_test_pod(
    namespace: str,
    test_case: dict[str, Any],
) -> dict[str, Any]:
    """Build a minimal Pod spec for a dry-run admission test.

    The pod is designed to trigger specific admission rejections while being
    otherwise valid K8s YAML.
    """
    container: dict[str, Any] = {
        "name": "kimera-admission-probe",
        "image": "busybox:1.36",
        "command": ["sleep", "1"],
    }

    # Apply container-level overrides (securityContext on the container)
    pod_overrides = test_case.get("pod_overrides", {})
    if "securityContext" in pod_overrides:
        container["securityContext"] = pod_overrides["securityContext"]

    # Resource limits — strip for the no-limits test
    if not test_case.get("strip_resources", False):
        container["resources"] = {
            "limits": {"cpu": "10m", "memory": "16Mi"},
            "requests": {"cpu": "10m", "memory": "16Mi"},
        }

    pod: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": f"kimera-admission-test-{test_case['id']}",
            "namespace": namespace,
            "labels": {"app.kubernetes.io/managed-by": "kimera"},
        },
        "spec": {
            "containers": [container],
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 0,
        },
    }

    # Apply pod-spec-level overrides (hostPID, hostNetwork, etc.)
    pod_spec_overrides = test_case.get("pod_spec_overrides", {})
    for key, value in pod_spec_overrides.items():
        pod["spec"][key] = value

    return pod


def validate_admission(
    k8s: K8sClient,
    sec_logger: SecurityLogger,
) -> ValidationReport:
    """Validate that admission controllers reject policy-violating resources.

    For each test case, submits a pod spec via ``dry_run=["All"]`` (server-side
    dry-run). The resource passes through all admission webhooks but is never
    persisted. If the API server accepts the resource, the admission controller
    failed to enforce its policy.

    Args:
        k8s: Kubernetes client.
        sec_logger: Security logger for console output.

    Returns:
        ValidationReport with results for each admission test.
    """
    namespace = k8s.namespace
    report = ValidationReport(namespace=namespace, control_type=ControlType.ADMISSION)

    # Detect what's installed
    controllers = _detect_admission_controllers(k8s)
    if controllers:
        sec_logger.info(
            f"Detected admission controllers: "
            f"{', '.join(c['type'] + '(' + c['name'] + ')' for c in controllers)}"
        )
    else:
        sec_logger.warning(
            "No admission controllers detected (no PSA labels, Kyverno, or Gatekeeper). "
            "All test resources will likely be admitted."
        )

    for test_case in ADMISSION_TEST_CASES:
        test_id = test_case["id"]
        description = test_case["description"]
        expected_rejection = test_case.get("expected_rejection", True)

        sec_logger.info(f"Testing: {description}...")

        pod_body = _build_test_pod(namespace, test_case)

        try:
            # Server-side dry-run: passes through admission webhooks, never persisted
            k8s.v1.create_namespaced_pod(
                namespace=namespace,
                body=pod_body,
                dry_run="All",
            )
            # If we get here, the pod was admitted (no rejection)
            if expected_rejection:
                report.results.append(ValidationResult(
                    control_type=ControlType.ADMISSION,
                    control_name=test_id,
                    test_description=description,
                    expected="REJECT",
                    actual="ADMITTED",
                    verdict=ValidationVerdict.FAIL,
                    evidence="Pod was admitted by API server (dry-run=server)",
                    remediation_hint=test_case.get("remediation", ""),
                ))
            else:
                report.results.append(ValidationResult(
                    control_type=ControlType.ADMISSION,
                    control_name=test_id,
                    test_description=description,
                    expected="ADMIT",
                    actual="ADMITTED",
                    verdict=ValidationVerdict.PASS,
                ))

        except ApiException as e:
            # Rejection by admission controller (403 or 422 typically)
            if e.status in (403, 422):
                reason = str(e.reason or "")
                body_str = str(e.body or "")[:500]

                if expected_rejection:
                    report.results.append(ValidationResult(
                        control_type=ControlType.ADMISSION,
                        control_name=test_id,
                        test_description=description,
                        expected="REJECT",
                        actual="REJECTED",
                        verdict=ValidationVerdict.PASS,
                        evidence=f"HTTP {e.status}: {reason}. {body_str}",
                    ))
                else:
                    report.results.append(ValidationResult(
                        control_type=ControlType.ADMISSION,
                        control_name=test_id,
                        test_description=description,
                        expected="ADMIT",
                        actual="REJECTED",
                        verdict=ValidationVerdict.FAIL,
                        evidence=f"HTTP {e.status}: {reason}. {body_str}",
                    ))
            else:
                report.results.append(ValidationResult(
                    control_type=ControlType.ADMISSION,
                    control_name=test_id,
                    test_description=description,
                    expected="REJECT" if expected_rejection else "ADMIT",
                    actual=f"ERROR (HTTP {e.status})",
                    verdict=ValidationVerdict.ERROR,
                    evidence=str(e)[:500],
                ))

        except Exception as e:
            report.results.append(ValidationResult(
                control_type=ControlType.ADMISSION,
                control_name=test_id,
                test_description=description,
                expected="REJECT" if expected_rejection else "ADMIT",
                actual=f"ERROR: {type(e).__name__}",
                verdict=ValidationVerdict.ERROR,
                evidence=str(e)[:500],
            ))

    passed = report.passed
    failed = report.failed
    total = report.total
    report.summary = (
        f"Admission validation: {passed}/{total} passed, {failed} failed. "
        f"Controllers: {', '.join(c['type'] for c in controllers) or 'none detected'}."
    )

    return report
