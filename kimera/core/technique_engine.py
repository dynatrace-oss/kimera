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

from kubernetes.client.rest import ApiException

from ..container.core.k8s_client import K8sClient
from ..container.make_vulnerable.probe_runner import ProbeRunner
from .findings import TechniqueResult
from .technique_registry import TechniqueDefinition, TechniqueRegistry

logger = logging.getLogger(__name__)
_probe_runner = ProbeRunner()

# Re-export for backward compatibility
__all__ = ["TechniqueDefinition", "TechniqueRegistry", "execute_technique"]


def execute_technique(
    k8s: K8sClient,
    registry: TechniqueRegistry,
    technique_id: str,
    target_pod: str | None = None,
    params: dict[str, Any] | None = None,
) -> TechniqueResult:
    """Execute a technique from the registry against a target."""
    technique = registry.get(technique_id)
    if not technique:
        return TechniqueResult(
            technique_id=technique_id,
            technique_name="Unknown",
            target=target_pod or "unknown",
            success=False,
            evidence=[f"Technique {technique_id} not found in registry"],
        )

    result = TechniqueResult(
        technique_id=technique_id,
        technique_name=technique.name,
        mitre_id=technique.mitre_id,
        tactic=technique.tactic,
        target=target_pod or k8s.namespace,
        success=False,
    )

    if technique.mode == "exec":
        _execute_exec_technique(k8s, technique, result, target_pod, params or {})
    elif technique.mode == "api":
        _execute_api_technique(k8s, technique, result)
    else:
        result.evidence = [f"Unknown execution mode: {technique.mode}"]

    return result


def _execute_exec_technique(
    k8s: K8sClient,
    technique: TechniqueDefinition,
    result: TechniqueResult,
    target_pod: str | None,
    params: dict[str, Any],
) -> None:
    if not target_pod:
        result.evidence = ["No target pod specified for exec-mode technique"]
        return

    probes = technique.probes
    if not probes:
        result.evidence = ["No probes defined for technique"]
        return

    resolved_probes = [
        _resolve_probe_params(probe, params, k8s.namespace)
        for probe in probes
    ]

    try:
        script = _probe_runner.build_script(resolved_probes)
    except ValueError as exc:
        result.evidence = [f"Failed to build probe script: {exc}"]
        return

    try:
        output = k8s.exec_in_pod(target_pod, script)
    except Exception as exc:
        result.evidence = [f"Exec failed: {exc}"]
        return

    for marker_def in technique.evidence_markers:
        marker = marker_def.get("marker", "")
        if marker and marker in output:
            result.evidence.append(marker_def.get("evidence", marker))
            impact_text = marker_def.get("impact", "")
            if impact_text:
                result.impact.append(impact_text)

    for indicator in technique.success_indicators:
        if indicator in output:
            result.success = True
            break


def _execute_api_technique(
    k8s: K8sClient,
    technique: TechniqueDefinition,
    result: TechniqueResult,
) -> None:
    try:
        resources = _enumerate_for_technique(k8s, technique, k8s.namespace)
        if resources:
            result.success = True
            result.evidence = [f"Enumerated {len(resources)} resources"]
            for r in resources[:10]:
                result.evidence.append(f"{r['type']}: {r['name']}")
    except ApiException as exc:
        result.evidence = [f"API call failed: {exc.reason}"]


def _enumerate_for_technique(
    k8s: K8sClient,
    technique: TechniqueDefinition,
    namespace: str,
) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []

    for api_call in technique.api_calls:
        resource_type = api_call.get("resource", "")
        try:
            items = _list_resource(k8s, namespace, resource_type)
            resources.extend(items)
        except ApiException as exc:
            logger.warning("Failed to enumerate %s: %s", resource_type, exc.reason)

    return resources


def _list_resource(k8s: K8sClient, namespace: str, resource_type: str) -> list[dict[str, Any]]:
    """List K8s resources by type. Returns dicts with name and type keys."""
    if resource_type == "deployments":
        return [{"name": i.metadata.name, "type": "deployment"}
                for i in k8s.apps_v1.list_namespaced_deployment(namespace).items]
    if resource_type == "services":
        return [{"name": i.metadata.name, "type": "service"}
                for i in k8s.v1.list_namespaced_service(namespace).items]
    if resource_type == "serviceaccounts":
        return [{"name": i.metadata.name, "type": "serviceaccount"}
                for i in k8s.v1.list_namespaced_service_account(namespace).items]
    if resource_type == "secrets":
        return [{"name": i.metadata.name, "type": f"secret/{i.type}"}
                for i in k8s.v1.list_namespaced_secret(namespace).items]
    if resource_type == "configmaps":
        return [{"name": i.metadata.name, "type": "configmap",
                 "keys": list((i.data or {}).keys())}
                for i in k8s.v1.list_namespaced_config_map(namespace).items]
    if resource_type == "namespaces":
        return [{"name": i.metadata.name, "type": "namespace"}
                for i in k8s.v1.list_namespace().items]
    if resource_type == "networkpolicies":
        return [{"name": i.metadata.name, "type": "networkpolicy"}
                for i in k8s.list_network_policies(namespace)]
    if resource_type == "rolebindings":
        return [{"name": i.metadata.name, "type": "rolebinding", "role": i.role_ref.name}
                for i in k8s.rbac_v1.list_namespaced_role_binding(namespace).items]
    if resource_type == "clusterrolebindings":
        return [{"name": i.metadata.name, "type": "clusterrolebinding", "role": i.role_ref.name}
                for i in k8s.rbac_v1.list_cluster_role_binding().items]
    if resource_type == "endpoints":
        return [{"name": i.metadata.name, "type": "endpoints"}
                for i in k8s.v1.list_namespaced_endpoints(namespace).items]
    if resource_type == "validate_controls":
        return []  # V1-V3: handled by MCP validate_defense tool
    logger.warning("Unknown API resource type: %s", resource_type)
    return []


def _resolve_probe_params(
    probe: dict[str, Any],
    params: dict[str, Any],
    namespace: str,
) -> dict[str, Any]:
    """Substitute {{ param_name }} placeholders in probe fields."""
    resolved = {}
    params_with_ns = {**params, "namespace": namespace}

    for key, value in probe.items():
        if isinstance(value, str):
            for param_name, param_value in params_with_ns.items():
                value = value.replace("{{ " + param_name + " }}", str(param_value))
            resolved[key] = value
        else:
            resolved[key] = value

    return resolved
