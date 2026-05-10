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
from pathlib import Path
from typing import Any

import yaml
from kubernetes.client.rest import ApiException

from ..container.core.k8s_client import K8sClient
from ..container.make_vulnerable.probe_runner import ProbeRunner
from .findings import TechniqueResult

logger = logging.getLogger(__name__)

_CONFIG_DIR = Path(__file__).resolve().parents[2] / "config" / "techniques"
_probe_runner = ProbeRunner()


class TechniqueDefinition:
    """A loaded technique definition from YAML config."""

    def __init__(self, technique_id: str, data: dict[str, Any]) -> None:
        """Load technique from parsed YAML data."""
        self.technique_id = technique_id
        self.name: str = data.get("name", technique_id)
        self.enabled: bool = data.get("enabled", True)
        self.severity: str = data.get("severity", "medium")
        self.description: str = data.get("description", "")

        mitre = data.get("mitre", {})
        self.mitre_id: str = mitre.get("technique_id", "")
        self.mitre_name: str = mitre.get("technique_name", "")
        self.tactic: str = mitre.get("tactic", "")

        execution = data.get("execution", {})
        self.mode: str = execution.get("mode", "exec")
        self.requires_target_pod: bool = execution.get("requires_target_pod", True)
        self.probes: list[dict[str, Any]] = execution.get("probes", [])
        self.parameters: list[dict[str, Any]] = execution.get("parameters", [])
        self.api_calls: list[dict[str, Any]] = execution.get("api_calls", [])

        self.evidence_markers: list[dict[str, str]] = data.get(
            "execution", {},
        ).get("evidence_markers", [])
        self.success_indicators: list[str] = data.get("success_indicators", [])
        self.impact: list[str] = data.get("impact", [])
        self.remediation: str = data.get("remediation", "")
        self.data_store_ports: dict[int, str] = data.get("data_store_ports", {})


class TechniqueRegistry:
    """Loads and manages technique definitions from YAML configs.

    Supports runtime extension: call reload() after adding new YAML files
    to config/techniques/.
    """

    def __init__(self, config_dir: Path | None = None) -> None:
        """Load all technique definitions from the config directory."""
        self._config_dir = config_dir or _CONFIG_DIR
        self._techniques: dict[str, TechniqueDefinition] = {}
        self._registry_data: dict[str, dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        """Reload all technique definitions from disk.

        Call after adding new technique YAML files at runtime.
        """
        self._techniques.clear()
        self._registry_data.clear()

        registry_path = self._config_dir / "registry.yaml"
        if not registry_path.exists():
            logger.warning("Technique registry not found: %s", registry_path)
            return

        with open(registry_path) as fh:
            registry = yaml.safe_load(fh) or {}

        for tech_id, meta in registry.get("techniques", {}).items():
            tech_file = self._config_dir / meta["file"]
            if not tech_file.exists():
                logger.debug("Technique file not found (skipping): %s", tech_file)
                continue

            with open(tech_file) as fh:
                tech_data = yaml.safe_load(fh) or {}

            self._techniques[tech_id] = TechniqueDefinition(tech_id, tech_data)
            self._registry_data[tech_id] = {
                "name": meta["name"],
                "phase": meta.get("phase", "unknown"),
                "noise": meta.get("noise", "medium"),
            }

    def get(self, technique_id: str) -> TechniqueDefinition | None:
        """Look up a technique by ID."""
        return self._techniques.get(technique_id)

    def list_techniques(self) -> list[dict[str, str]]:
        """List all registered techniques with metadata."""
        result = []
        for tech_id, meta in self._registry_data.items():
            tech = self._techniques.get(tech_id)
            if tech and tech.enabled:
                result.append({
                    "id": tech_id,
                    "name": meta["name"],
                    "phase": meta["phase"],
                    "noise": meta["noise"],
                    "mitre_id": tech.mitre_id,
                    "tactic": tech.tactic,
                    "mode": tech.mode,
                })
        return result

    def list_by_phase(self, phase: str) -> list[str]:
        """List technique IDs for a given phase."""
        return [
            tech_id for tech_id, meta in self._registry_data.items()
            if meta["phase"] == phase and self._techniques.get(tech_id, TechniqueDefinition(tech_id, {})).enabled
        ]

    @property
    def technique_count(self) -> int:
        """Count of loaded, enabled techniques."""
        return sum(1 for t in self._techniques.values() if t.enabled)

    def __contains__(self, technique_id: str) -> bool:
        """Check if a technique ID is registered."""
        return technique_id in self._techniques


def execute_technique(
    k8s: K8sClient,
    registry: TechniqueRegistry,
    technique_id: str,
    target_pod: str | None = None,
    params: dict[str, Any] | None = None,
) -> TechniqueResult:
    """Execute a technique from the registry against a target.

    Loads the technique YAML, builds probe scripts, executes via the
    appropriate mode (exec, api, probe), and returns structured results.

    Args:
        k8s: Kubernetes client configured for the target namespace.
        registry: Loaded technique registry.
        technique_id: ID of the technique to execute (e.g. "C1", "L1").
        target_pod: Pod name for exec-mode techniques.
        params: Runtime parameters (e.g. probe_host, probe_port for L1).

    Returns:
        TechniqueResult with evidence and ATT&CK mapping.
    """
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
    """Execute a technique that runs shell commands inside a pod."""
    if not target_pod:
        result.evidence = ["No target pod specified for exec-mode technique"]
        return

    # Build script from probes, substituting parameters
    probes = technique.probes
    if not probes:
        result.evidence = ["No probes defined for technique"]
        return

    # Template substitution for parameterized probes
    resolved_probes = []
    for probe in probes:
        resolved = _resolve_probe_params(probe, params, k8s.namespace)
        resolved_probes.append(resolved)

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

    # Parse output against evidence markers
    for marker_def in technique.evidence_markers:
        marker = marker_def.get("marker", "")
        if marker and marker in output:
            result.evidence.append(marker_def.get("evidence", marker))
            impact_text = marker_def.get("impact", "")
            if impact_text:
                result.impact.append(impact_text)

    # Check success indicators
    for indicator in technique.success_indicators:
        if indicator in output:
            result.success = True
            break


def _execute_api_technique(
    k8s: K8sClient,
    technique: TechniqueDefinition,
    result: TechniqueResult,
) -> None:
    """Execute a technique that uses K8s API calls directly."""
    namespace = k8s.namespace

    # API-mode techniques gather information via API calls
    try:
        if technique.technique_id.startswith("R"):
            # Reconnaissance techniques — enumerate resources
            inventory = _enumerate_for_technique(k8s, technique, namespace)
            if inventory:
                result.success = True
                result.evidence = [f"Enumerated {len(inventory)} resources"]
    except ApiException as exc:
        result.evidence = [f"API call failed: {exc.reason}"]


def _enumerate_for_technique(
    k8s: K8sClient,
    technique: TechniqueDefinition,
    namespace: str,
) -> list[dict[str, Any]]:
    """Run API enumeration for reconnaissance techniques."""
    resources: list[dict[str, Any]] = []

    for api_call in technique.api_calls:
        resource_type = api_call.get("resource", "")
        try:
            if resource_type == "deployments":
                deps = k8s.apps_v1.list_namespaced_deployment(namespace)
                for dep in deps.items:
                    resources.append({"name": dep.metadata.name, "type": "deployment"})
            elif resource_type == "services":
                svcs = k8s.v1.list_namespaced_service(namespace)
                for svc in svcs.items:
                    resources.append({"name": svc.metadata.name, "type": "service"})
            elif resource_type == "serviceaccounts":
                sas = k8s.v1.list_namespaced_service_account(namespace)
                for sa in sas.items:
                    resources.append({"name": sa.metadata.name, "type": "serviceaccount"})
        except ApiException as exc:
            logger.warning("Failed to enumerate %s: %s", resource_type, exc.reason)

    return resources


def _resolve_probe_params(
    probe: dict[str, Any],
    params: dict[str, Any],
    namespace: str,
) -> dict[str, Any]:
    """Substitute template parameters in a probe definition.

    Handles {{ param_name }} placeholders in probe fields.
    """
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


def enumerate_targets(k8s: K8sClient) -> dict[str, Any]:
    """Discover all security-relevant resources in the namespace.

    Low-noise reconnaissance via standard API list calls. Returns structured
    inventory. No console output. Maps to T1613.
    """
    namespace = k8s.namespace
    inventory: dict[str, Any] = {
        "namespace": namespace,
        "deployments": [],
        "services": [],
        "service_accounts": [],
        "network_policies": [],
        "secrets_metadata": [],
        "role_bindings": [],
    }

    try:
        deps = k8s.apps_v1.list_namespaced_deployment(namespace)
        for dep in deps.items:
            pod_spec = dep.spec.template.spec
            containers = []
            for c in pod_spec.containers:
                ctx = c.security_context
                containers.append({
                    "name": c.name,
                    "image": c.image,
                    "privileged": bool(ctx and ctx.privileged),
                    "capabilities_add": list(ctx.capabilities.add or [])
                    if ctx and ctx.capabilities and ctx.capabilities.add else [],
                    "has_limits": bool(c.resources and c.resources.limits),
                })
            inventory["deployments"].append({
                "name": dep.metadata.name,
                "replicas": dep.spec.replicas,
                "service_account": pod_spec.service_account_name or "default",
                "host_pid": bool(pod_spec.host_pid),
                "host_network": bool(pod_spec.host_network),
                "automount_token": pod_spec.automount_service_account_token is not False,
                "containers": containers,
            })
    except ApiException as exc:
        logger.warning("Failed to list deployments: %s", exc.reason)

    try:
        svcs = k8s.v1.list_namespaced_service(namespace)
        for svc in svcs.items:
            ports = [
                {"port": p.port, "protocol": p.protocol or "TCP"}
                for p in (svc.spec.ports or [])
            ]
            inventory["services"].append({
                "name": svc.metadata.name,
                "type": svc.spec.type,
                "ports": ports,
                "selector": dict(svc.spec.selector) if svc.spec.selector else {},
            })
    except ApiException as exc:
        logger.warning("Failed to list services: %s", exc.reason)

    try:
        sas = k8s.v1.list_namespaced_service_account(namespace)
        inventory["service_accounts"] = [sa.metadata.name for sa in sas.items]
    except ApiException as exc:
        logger.warning("Failed to list service accounts: %s", exc.reason)

    try:
        policies = k8s.list_network_policies(namespace)
        inventory["network_policies"] = [p.metadata.name for p in policies]
    except ApiException as exc:
        logger.warning("Failed to list network policies: %s", exc.reason)

    try:
        secrets = k8s.v1.list_namespaced_secret(namespace)
        inventory["secrets_metadata"] = [
            {"name": s.metadata.name, "type": s.type}
            for s in secrets.items
        ]
    except ApiException as exc:
        logger.warning("Failed to list secrets: %s", exc.reason)

    try:
        bindings = k8s.rbac_v1.list_namespaced_role_binding(namespace)
        for rb in bindings.items:
            subjects = [
                {"kind": s.kind, "name": s.name}
                for s in (rb.subjects or [])
            ]
            inventory["role_bindings"].append({
                "name": rb.metadata.name,
                "role": rb.role_ref.name,
                "role_kind": rb.role_ref.kind,
                "subjects": subjects,
            })
    except ApiException as exc:
        logger.warning("Failed to list role bindings: %s", exc.reason)

    return inventory
