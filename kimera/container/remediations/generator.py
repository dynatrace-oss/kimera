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

import json
from pathlib import Path
from typing import Any

import yaml

from ...application.config.schemas import NetworkTopologyEntry
from ..core.k8s_client import K8sClient
from ..core.logger import SecurityLogger

_PROMPTS_DIR = Path(__file__).parent.parent.parent / "prompts"

SUPPORTED_TYPES = frozenset(
    {
        "missing-network-policies",
        "privileged-containers",
        "dangerous-capabilities",
        "host-namespace-sharing",
        "missing-resource-limits",
        "all",
    }
)


def _load_template(name: str) -> Any:
    """Load and return a Jinja2 template by filename.

    Args:
        name: Template filename inside ``kimera/prompts/``.

    Returns:
        A ``jinja2.Template`` instance.

    Raises:
        ImportError: If the ``llm`` extra is not installed.
    """
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape  # noqa: PLC0415
    except ImportError as exc:
        raise ImportError(
            "Jinja2 is required for LLM prompt rendering. "
            "Install with: uv pip install 'kimera[llm]'"
        ) from exc

    env = Environment(
        loader=FileSystemLoader(str(_PROMPTS_DIR)),
        autoescape=select_autoescape([]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["tojson"] = json.dumps
    return env.get_template(name)


class LLMRemediationGenerator:
    """Generate security remediations for Kubernetes workloads using Anthropic Claude.

    Supports all exploit types: network policies, privileged containers,
    dangerous capabilities, host namespace sharing, and resource limits.
    Context is sourced from the Kubernetes API and, optionally, from
    Dynatrace KSPM/Smartscape data via the DT MCP gateway.

    Attributes:
        k8s: Kubernetes client for cluster introspection.
        logger: Security logger.
        model: Anthropic model identifier.
    """

    def __init__(
        self,
        k8s: K8sClient,
        logger: SecurityLogger,
        network_topology: dict[str, NetworkTopologyEntry] | None = None,
        model: str = "claude-sonnet-4-6",
    ) -> None:
        """Initialise the generator.

        Args:
            k8s: Kubernetes client.
            logger: Security logger.
            network_topology: Per-service ingress topology from profile config.
                Used to populate the ``from:`` selectors in generated policies.
            model: Anthropic model identifier.
        """
        self.k8s = k8s
        self.logger = logger
        self._topology = network_topology or {}
        self.model = model

    # -- Public API ----------------------------------------------------------------

    def generate(
        self,
        exploit_type: str = "missing-network-policies",
        kspm_context: str | None = None,
        smartscape_context: str | None = None,
    ) -> str:
        """Generate remediation YAML for the given exploit type.

        Args:
            exploit_type: One of ``SUPPORTED_TYPES``.
            kspm_context: Optional KSPM compliance findings (text).
            smartscape_context: Optional Smartscape edge data (text).

        Returns:
            Multi-document YAML string ready to write to a file.

        Raises:
            ImportError: If the ``llm`` extra is not installed.
            ValueError: If the LLM returns malformed output or exploit type is invalid.
        """
        if exploit_type not in SUPPORTED_TYPES:
            raise ValueError(
                f"Unsupported exploit type: {exploit_type}. "
                f"Choose from: {', '.join(sorted(SUPPORTED_TYPES))}"
            )

        try:
            import anthropic  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "Anthropic SDK is required for remediation generation. "
                "Install with: uv pip install 'kimera[llm]'"
            ) from exc

        namespace = self.k8s.namespace
        context = self._get_cluster_context(exploit_type)
        topology = {
            svc: [dict(c) for c in entry.allowed_ingress_from]
            for svc, entry in self._topology.items()
        }

        system_prompt = _load_template("generate_system.j2").render(exploit_type=exploit_type)
        user_prompt = _load_template("generate_user.j2").render(
            exploit_type=exploit_type,
            namespace=namespace,
            context=context,
            topology=topology,
            kspm_context=kspm_context,
            smartscape_context=smartscape_context,
        )

        self.logger.info(f"Calling {self.model} to generate {exploit_type} remediations...")

        client = anthropic.Anthropic()
        message = client.messages.create(
            model=self.model,
            max_tokens=8192,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        raw = getattr(message.content[0], "text", "") if message.content else ""
        yaml_output = self._clean_yaml_output(raw)
        self._validate_yaml(yaml_output)
        return yaml_output

    def generate_exploit(
        self,
        exploit_type: str = "privileged-containers",
        service: str | None = None,
        kspm_context: str | None = None,
        smartscape_context: str | None = None,
    ) -> str:
        """Generate exploit patches for the given exploit type.

        Analyzes cluster state and generates tailored JSON patches to introduce
        vulnerabilities into deployments for security testing.

        Args:
            exploit_type: One of ``SUPPORTED_TYPES`` (excluding ``all`` for now).
            service: Optional target service. If omitted, the LLM recommends targets.
            kspm_context: Optional KSPM compliance findings (text).
            smartscape_context: Optional Smartscape edge data (text).

        Returns:
            Multi-document YAML string with exploit patch definitions.

        Raises:
            ImportError: If the ``llm`` extra is not installed.
            ValueError: If the LLM returns malformed output or exploit type is invalid.
        """
        if exploit_type not in SUPPORTED_TYPES:
            raise ValueError(
                f"Unsupported exploit type: {exploit_type}. "
                f"Choose from: {', '.join(sorted(SUPPORTED_TYPES))}"
            )

        try:
            import anthropic  # noqa: PLC0415
        except ImportError as exc:
            raise ImportError(
                "Anthropic SDK is required for exploit generation. "
                "Install with: uv pip install 'kimera[llm]'"
            ) from exc

        namespace = self.k8s.namespace
        context = self._get_cluster_context(exploit_type)

        system_prompt = _load_template("exploit_system.j2").render(
            exploit_type=exploit_type,
            service=service,
        )
        user_prompt = _load_template("exploit_user.j2").render(
            exploit_type=exploit_type,
            namespace=namespace,
            service=service,
            context=context,
            kspm_context=kspm_context,
            smartscape_context=smartscape_context,
        )

        self.logger.info(f"Calling {self.model} to generate {exploit_type} exploit patches...")

        client = anthropic.Anthropic()
        message = client.messages.create(
            model=self.model,
            max_tokens=8192,
            system=system_prompt,
            messages=[{"role": "user", "content": user_prompt}],
        )

        raw = getattr(message.content[0], "text", "") if message.content else ""
        yaml_output = self._clean_yaml_output(raw)
        self._validate_exploit_yaml(yaml_output)
        return yaml_output

    def _validate_exploit_yaml(self, yaml_text: str) -> None:
        """Validate the generated exploit YAML structure."""
        try:
            docs = list(yaml.safe_load_all(yaml_text))
        except yaml.YAMLError as e:
            raise ValueError(f"LLM returned invalid YAML: {e}") from e

        for i, doc in enumerate(docs):
            if doc is None:
                continue
            if not isinstance(doc, dict):
                raise ValueError(f"Document {i} is not a mapping")
            if "target" not in doc:
                raise ValueError(f"Document {i} missing 'target' field")
            target = doc["target"]
            if not isinstance(target, dict) or "deployment" not in target:
                raise ValueError(f"Document {i} missing 'target.deployment'")
            if "patches" not in doc:
                raise ValueError(f"Document {i} missing 'patches' field")
            patches = doc["patches"]
            if not isinstance(patches, list) or not patches:
                raise ValueError(f"Document {i} has empty or invalid 'patches'")

    # -- Context gathering ---------------------------------------------------------

    def _get_cluster_context(self, exploit_type: str) -> dict[str, Any]:
        """Gather K8s context relevant to the exploit type."""
        namespace = self.k8s.namespace
        context: dict[str, Any] = {}

        # Deployment info is always useful
        context["deployments"] = self._get_deployment_info(namespace)

        if exploit_type in ("missing-network-policies", "all"):
            context["statefulsets"] = self._get_statefulset_info(namespace)
            context["services"] = self._get_service_info(namespace)

        if exploit_type in (
            "privileged-containers",
            "dangerous-capabilities",
            "host-namespace-sharing",
            "missing-resource-limits",
            "all",
        ):
            context["security_contexts"] = self._get_security_contexts(namespace)

        return context

    def _get_deployment_info(self, namespace: str) -> dict[str, dict[str, Any]]:
        """Return deployment name to labels and ports mapping."""
        result: dict[str, dict[str, Any]] = {}
        try:
            deps = self.k8s.apps_v1.list_namespaced_deployment(namespace)
            for dep in deps.items:
                name = dep.metadata.name
                labels = dep.spec.selector.match_labels or {}
                ports = self._extract_ports(dep)
                result[name] = {"labels": dict(labels), "ports": ports}
        except Exception as e:
            self.logger.error(f"Failed to list deployments: {e}")
        return result

    def _get_statefulset_info(self, namespace: str) -> dict[str, dict[str, Any]]:
        """Return statefulset name to labels and ports mapping."""
        result: dict[str, dict[str, Any]] = {}
        try:
            stss = self.k8s.apps_v1.list_namespaced_stateful_set(namespace)
            for sts in stss.items:
                name = sts.metadata.name
                labels = sts.spec.selector.match_labels or {}
                ports = self._extract_ports(sts)
                result[name] = {"labels": dict(labels), "ports": ports}
        except Exception as e:
            self.logger.error(f"Failed to list statefulsets: {e}")
        return result

    def _get_service_info(self, namespace: str) -> dict[str, dict[str, Any]]:
        """Return service name to ports and selector mapping."""
        result: dict[str, dict[str, Any]] = {}
        try:
            svcs = self.k8s.v1.list_namespaced_service(namespace)
            for svc in svcs.items:
                name = svc.metadata.name
                ports: list[dict[str, Any]] = []
                if svc.spec.ports:
                    for p in svc.spec.ports:
                        ports.append(
                            {
                                "port": p.port,
                                "target_port": str(p.target_port) if p.target_port else None,
                                "protocol": p.protocol or "TCP",
                            }
                        )
                selector = dict(svc.spec.selector) if svc.spec.selector else {}
                result[name] = {"ports": ports, "selector": selector}
        except Exception as e:
            self.logger.error(f"Failed to list services: {e}")
        return result

    def _get_security_contexts(self, namespace: str) -> dict[str, dict[str, Any]]:
        """Return deployment security context details for hardening analysis."""
        result: dict[str, dict[str, Any]] = {}
        try:
            deps = self.k8s.apps_v1.list_namespaced_deployment(namespace)
            for dep in deps.items:
                name = dep.metadata.name
                pod_spec = dep.spec.template.spec

                pod_level = {
                    "host_pid": getattr(pod_spec, "host_pid", False) or False,
                    "host_network": getattr(pod_spec, "host_network", False) or False,
                    "host_ipc": getattr(pod_spec, "host_ipc", False) or False,
                }

                containers: list[dict[str, Any]] = []
                for c in pod_spec.containers:
                    info: dict[str, Any] = {"name": c.name}
                    ctx = c.security_context

                    if ctx:
                        info["privileged"] = getattr(ctx, "privileged", None)
                        info["allow_privilege_escalation"] = getattr(
                            ctx, "allow_privilege_escalation", None
                        )
                        info["run_as_non_root"] = getattr(ctx, "run_as_non_root", None)
                        info["run_as_user"] = getattr(ctx, "run_as_user", None)
                        info["read_only_root_filesystem"] = getattr(
                            ctx, "read_only_root_filesystem", None
                        )
                        caps = getattr(ctx, "capabilities", None)
                        if caps:
                            info["capabilities_add"] = list(caps.add or [])
                            info["capabilities_drop"] = list(caps.drop or [])

                    resources = c.resources
                    if resources:
                        info["resources"] = {
                            "limits": dict(resources.limits) if resources.limits else None,
                            "requests": dict(resources.requests) if resources.requests else None,
                        }

                    containers.append(info)

                result[name] = {"pod": pod_level, "containers": containers}
        except Exception as e:
            self.logger.error(f"Failed to get security contexts: {e}")
        return result

    # -- Output handling -----------------------------------------------------------

    @staticmethod
    def _clean_yaml_output(raw: str) -> str:
        """Strip markdown fences if the LLM wrapped its output."""
        text = raw.strip()
        if text.startswith("```"):
            text = text.split("```", 2)[1]
            # Strip language identifier (yaml, json, yml, etc.)
            first_line_end = text.find("\n")
            if first_line_end != -1:
                lang = text[:first_line_end].strip()
                if lang.isalpha():
                    text = text[first_line_end:]
            text = text.rsplit("```", 1)[0].strip()
        return text

    def _validate_yaml(self, yaml_text: str) -> None:
        """Parse and validate the generated YAML structure."""
        try:
            docs = list(yaml.safe_load_all(yaml_text))
        except yaml.YAMLError as e:
            raise ValueError(f"LLM returned invalid YAML: {e}") from e

        for i, doc in enumerate(docs):
            if doc is None:
                continue
            if not isinstance(doc, dict):
                raise ValueError(f"Document {i} is not a mapping")
            if "apiVersion" not in doc:
                raise ValueError(f"Document {i} missing apiVersion")
            if "kind" not in doc:
                raise ValueError(f"Document {i} missing kind")
            if not doc.get("metadata", {}).get("name"):
                raise ValueError(f"Document {i} missing metadata.name")

    # -- Helpers -------------------------------------------------------------------

    @staticmethod
    def _extract_ports(workload: Any) -> list[int]:
        """Extract declared container ports from a workload spec."""
        ports: list[int] = []
        try:
            for container in workload.spec.template.spec.containers:
                if container.ports:
                    for port in container.ports:
                        if port.container_port:
                            ports.append(int(port.container_port))
        except (AttributeError, TypeError):
            pass
        return ports
