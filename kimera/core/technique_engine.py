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

from ..container.core.k8s_client import K8sClient
from ..container.make_vulnerable.probe_runner import ProbeRunner
from .api_executor import execute_api_technique
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
        execute_api_technique(k8s, technique, result)
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
