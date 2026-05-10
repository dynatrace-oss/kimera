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

"""Config-driven workload security assessment.

Loads check definitions from config/checks/workload.yaml and evaluates
each deployment against them. No hardcoded check logic — the YAML config
determines what to check, the severity, and the ATT&CK/CIS mappings.
"""

import logging
from pathlib import Path
from typing import Any

import yaml
from kubernetes.client import V1Deployment
from kubernetes.client.rest import ApiException

from ..container.core.k8s_client import K8sClient
from .findings import AssessmentReport, Finding, Severity, TechniqueRef

logger = logging.getLogger(__name__)

_CONFIG_DIR = Path(__file__).resolve().parents[2] / "config" / "checks"


def _load_checks(config_path: Path | None = None) -> list[dict[str, Any]]:
    """Load assessment check definitions from YAML."""
    path = config_path or (_CONFIG_DIR / "workload.yaml")
    if not path.exists():
        logger.warning("Check config not found: %s", path)
        return []
    with open(path) as fh:
        data = yaml.safe_load(fh) or {}
    return data.get("checks", [])


def _get_nested(obj: Any, dotted_path: str) -> Any:
    """Resolve a dotted attribute path on a K8s API object.

    Handles both dict-like access and attribute access (K8s client objects).
    Returns None if any segment is missing.
    """
    current = obj
    for segment in dotted_path.split("."):
        if current is None:
            return None
        if isinstance(current, dict):
            current = current.get(segment)
        else:
            current = getattr(current, segment, None)
    return current


def _evaluate_condition(value: Any, condition: str, check: dict[str, Any]) -> bool:
    """Evaluate a condition against a value. Returns True if the check FIRES (finding exists)."""
    if condition == "equals_true":
        return value is True
    if condition == "equals_zero":
        return value == 0
    if condition == "not_true":
        return value is not True
    if condition == "not_false":
        return value is not False
    if condition == "missing":
        return value is None
    if condition == "missing_or_empty":
        return not value
    if condition == "contains_any":
        if not value:
            return False
        match_values = set(check.get("match_values", []))
        if isinstance(value, list):
            return bool(match_values & set(value))
        return False
    if condition == "count_zero":
        return value == 0 or value is None
    logger.warning("Unknown condition: %s", condition)
    return False


def _build_technique_ref(check: dict[str, Any]) -> TechniqueRef:
    """Build a TechniqueRef from a check definition."""
    return TechniqueRef(
        mitre_id=check.get("mitre_id", ""),
        mitre_name=check.get("mitre_name", ""),
        cis_controls=check.get("cis_controls", []),
    )


def _evaluate_container_check(
    check: dict[str, Any],
    deployment_name: str,
    container: Any,
    pod_spec: Any,
) -> Finding | None:
    """Evaluate a container-level check against a container spec."""
    field_path = check["field"]
    value = _get_nested(container, field_path)

    # Some checks fall back to pod-level (e.g. runAsNonRoot)
    if check.get("check_pod_level") and not _evaluate_condition(value, check["condition"], check):
        pod_value = _get_nested(pod_spec, f"security_context.{field_path.split('.')[-1]}")
        if pod_value is True:
            return None  # Pod-level setting covers it

    if _evaluate_condition(value, check["condition"], check):
        container_name = getattr(container, "name", "unknown")
        evidence = ""
        if check["condition"] == "contains_any" and isinstance(value, list):
            match_values = set(check.get("match_values", []))
            matched = [v for v in value if v in match_values]
            evidence = f"{field_path}: {matched}"

        return Finding(
            target=f"{deployment_name}/{container_name}",
            check_id=check["id"],
            severity=Severity(check["severity"]),
            title=check["title"],
            detail=check.get("detail", ""),
            evidence=evidence,
            remediation=check.get("remediation", ""),
            technique=_build_technique_ref(check),
        )
    return None


def _evaluate_pod_check(
    check: dict[str, Any],
    deployment_name: str,
    pod_spec: Any,
) -> Finding | None:
    """Evaluate a pod-level check against a pod spec."""
    field_path = check["field"]
    value = _get_nested(pod_spec, field_path)

    if _evaluate_condition(value, check["condition"], check):
        extra = ""
        if check["id"] == "sa_token_automounted":
            sa_name = getattr(pod_spec, "service_account_name", None) or "default"
            extra = f" ({sa_name})"

        return Finding(
            target=f"{deployment_name}{extra}",
            check_id=check["id"],
            severity=Severity(check["severity"]),
            title=check["title"],
            detail=check.get("detail", ""),
            remediation=check.get("remediation", ""),
            technique=_build_technique_ref(check),
        )
    return None


def _evaluate_resource_check(
    check: dict[str, Any],
    deployment_name: str,
    container: Any,
) -> Finding | None:
    """Evaluate a resource limits/requests check."""
    resources = getattr(container, "resources", None)
    value = _get_nested(resources, check["field"].replace("resources.", "")) if resources else None

    if _evaluate_condition(value, check["condition"], check):
        container_name = getattr(container, "name", "unknown")
        return Finding(
            target=f"{deployment_name}/{container_name}",
            check_id=check["id"],
            severity=Severity(check["severity"]),
            title=check["title"],
            detail=check.get("detail", ""),
            remediation=check.get("remediation", ""),
            technique=_build_technique_ref(check),
        )
    return None


def assess_deployment(
    deployment: V1Deployment,
    checks: list[dict[str, Any]] | None = None,
) -> list[Finding]:
    """Assess a single deployment against loaded check definitions.

    Returns structured findings. No console output. No side effects.
    """
    if checks is None:
        checks = _load_checks()

    findings: list[Finding] = []
    name = deployment.metadata.name
    pod_spec = deployment.spec.template.spec

    for check in checks:
        check_type = check.get("type", "")

        if check_type == "container_field":
            for container in pod_spec.containers:
                finding = _evaluate_container_check(check, name, container, pod_spec)
                if finding:
                    findings.append(finding)

        elif check_type == "resource_check":
            for container in pod_spec.containers:
                finding = _evaluate_resource_check(check, name, container)
                if finding:
                    findings.append(finding)

        elif check_type == "pod_field":
            finding = _evaluate_pod_check(check, name, pod_spec)
            if finding:
                findings.append(finding)

        # namespace_check is handled in assess_namespace, not per-deployment

    return findings


def assess_namespace(
    k8s: K8sClient,
    config_path: Path | None = None,
) -> AssessmentReport:
    """Assess all workloads in the client's namespace.

    Returns a structured report. No console output.
    """
    namespace = k8s.namespace
    report = AssessmentReport(namespace=namespace)
    checks = _load_checks(config_path)

    try:
        deployments = k8s.apps_v1.list_namespaced_deployment(namespace)
    except ApiException as exc:
        logger.error("Failed to list deployments in %s: %s", namespace, exc)
        return report

    for deployment in deployments.items:
        report.workloads_scanned += 1
        findings = assess_deployment(deployment, checks)
        report.findings.extend(findings)

    # Namespace-level checks
    ns_checks = [c for c in checks if c.get("type") == "namespace_check"]
    for check in ns_checks:
        resource = check.get("resource", "")
        if resource == "network_policies":
            try:
                policies = k8s.list_network_policies(namespace)
                count = len(policies)
            except ApiException:
                count = 0

            if _evaluate_condition(count, check["condition"], check):
                report.findings.append(Finding(
                    target=namespace,
                    check_id=check["id"],
                    severity=Severity(check["severity"]),
                    title=check["title"],
                    detail=check.get("detail", ""),
                    remediation=check.get("remediation", ""),
                    technique=_build_technique_ref(check),
                ))

    return report
