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
from typing import Any

import yaml

from ...application.config.schemas import NetworkTopologyEntry
from ...core.llm import DEFAULT_MODEL, complete, strip_code_fence
from ...resources import prompts_dir
from ..core.k8s_client import K8sClient
from ..core.logger import SecurityLogger
from ..validation.external_egress import close_external_gaps, unmatched_declarations
from ..validation.reachability import Workload, close_gaps
from .cluster_context import gather_cluster_context
from .exploit_findings import FindingsDocument
from .finding_scope import NAMESPACE_SCOPE, TARGETED_SCOPE, report
from .output_validation import validate_exploit_yaml, validate_resource_yaml
from .targeted import apply_scope, build_plan

_PROMPTS_DIR = prompts_dir()

SUPPORTED_TYPES = frozenset(
    {
        "missing-network-policies",
        "privileged-containers",
        "dangerous-capabilities",
        "host-namespace-sharing",
        "missing-resource-limits",
        "rbac-abuse",
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

    Covers every exploit type. Context comes from the Kubernetes API and,
    optionally, Dynatrace KSPM/Smartscape data via the DT MCP gateway.

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
        model: str = DEFAULT_MODEL,
    ) -> None:
        """Initialise the generator.

        Args:
            k8s: Kubernetes client.
            logger: Security logger.
            network_topology: Per-workload ingress topology and declared external
                egress from profile config. Populates the ``from:`` selectors in
                generated policies and guarantees the declared ``ipBlock`` rules.
            model: Anthropic model identifier.
        """
        self.k8s = k8s
        self.logger = logger
        self._topology = network_topology or {}
        self.model = model

    def generate(
        self,
        exploit_type: str = "missing-network-policies",
        kspm_context: str | None = None,
        smartscape_context: str | None = None,
        findings: FindingsDocument | None = None,
        scope: str = NAMESPACE_SCOPE,
    ) -> str:
        """Generate remediation YAML for the given exploit type.

        Args:
            exploit_type: One of ``SUPPORTED_TYPES``.
            kspm_context: Optional KSPM compliance findings (text).
            smartscape_context: Optional Smartscape edge data (text).
            findings: Observed paths from one exploited workload. Required in
                targeted scope, and used to report what a namespace set closes.
            scope: ``targeted`` constrains only the findings' source workload.

        Returns:
            Multi-document YAML string ready to write to a file.

        Raises:
            ImportError: If the ``llm`` extra is not installed.
            ProviderNotConfiguredError: If no LLM backend is available.
            ProviderError: If the selected backend fails.
            ValueError: If the LLM returns malformed output or exploit type is invalid.
        """
        if exploit_type not in SUPPORTED_TYPES:
            raise ValueError(
                f"Unsupported exploit type: {exploit_type}. "
                f"Choose from: {', '.join(sorted(SUPPORTED_TYPES))}"
            )

        namespace = self.k8s.namespace
        context = gather_cluster_context(self.k8s, self.logger, exploit_type)
        topology = self._render_topology()

        plan = None
        if findings is not None:
            plan = build_plan(findings, context, self._topology, namespace)
            report(plan.classification)

        system_prompt = _load_template("generate_system.j2").render(
            exploit_type=exploit_type, scope=scope
        )
        user_prompt = _load_template("generate_user.j2").render(
            exploit_type=exploit_type,
            namespace=namespace,
            context=context,
            topology=topology,
            kspm_context=kspm_context,
            smartscape_context=smartscape_context,
            scope=scope,
            plan=plan,
        )

        self.logger.info(f"Calling {self.model} to generate {exploit_type} remediations...")

        raw = complete(system=system_prompt, user=user_prompt, model=self.model, max_tokens=8192)
        yaml_output = strip_code_fence(raw)
        validate_resource_yaml(yaml_output)
        if scope == TARGETED_SCOPE and plan is not None:
            return apply_scope(yaml_output, plan, namespace, self.logger)
        if exploit_type in ("missing-network-policies", "all"):
            yaml_output = self._close_gaps(yaml_output, context)
        return yaml_output

    def _render_topology(self) -> dict[str, dict[str, Any]]:
        """Flatten the profile topology for the prompt template.

        ``ingress`` stays ``None`` when undeclared so the template can tell that apart
        from an explicit empty list, which means block all ingress.
        """
        return {
            svc: {
                "ingress": (
                    None
                    if entry.allowed_ingress_from is None
                    else [dict(c) for c in entry.allowed_ingress_from]
                ),
                "egress": [
                    {
                        "cidr": str(dest.cidr),
                        "excluded": [str(net) for net in dest.except_],
                        "ports": list(dest.ports),
                        "protocol": dest.protocol,
                    }
                    for dest in entry.allowed_egress_to
                ],
            }
            for svc, entry in self._topology.items()
        }

    def _close_gaps(self, yaml_text: str, context: dict[str, Any]) -> str:
        """Add egress rules for flows the policy set declares but denies.

        Pod-to-pod needs both sides to agree, which an LLM writing them
        independently can miss; external destinations need a matching ``ipBlock``.
        """
        workloads = [
            Workload(name=name, labels=dict(info.get("labels") or {}))
            for kind in ("deployments", "statefulsets", "cronjobs")
            for name, info in (context.get(kind) or {}).items()
        ]
        if not workloads:
            return yaml_text

        for key in unmatched_declarations(workloads, self._topology):
            self.logger.warning(
                f"Topology key '{key}' declares external egress but matches no workload "
                f"in {self.k8s.namespace} — no rule added for it"
            )

        docs = [d for d in yaml.safe_load_all(yaml_text) if d]
        policies = [d for d in docs if d.get("kind") == "NetworkPolicy"]
        closed = close_gaps(policies, workloads)
        closed_external = close_external_gaps(docs, workloads, self._topology, self.k8s.namespace)
        if not closed and not closed_external:
            return yaml_text

        for gap in closed:
            self.logger.warning(f"Closed egress gap: {gap.describe()}")
        for external_gap in closed_external:
            self.logger.warning(f"Closed external egress gap: {external_gap.describe()}")
        if closed:
            self.logger.info(f"Added {len(closed)} egress rule(s) to match declared ingress")
        if closed_external:
            self.logger.info(
                f"Added egress rule(s) for {len(closed_external)} declared external destination(s)"
            )
        return yaml.safe_dump_all(docs, default_flow_style=False, sort_keys=False)

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
            ProviderNotConfiguredError: If no LLM backend is available.
            ProviderError: If the selected backend fails.
            ValueError: If the LLM returns malformed output or exploit type is invalid.
        """
        if exploit_type not in SUPPORTED_TYPES:
            raise ValueError(
                f"Unsupported exploit type: {exploit_type}. "
                f"Choose from: {', '.join(sorted(SUPPORTED_TYPES))}"
            )

        namespace = self.k8s.namespace
        context = gather_cluster_context(self.k8s, self.logger, exploit_type)

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

        raw = complete(system=system_prompt, user=user_prompt, model=self.model, max_tokens=8192)
        yaml_output = strip_code_fence(raw)
        validate_exploit_yaml(yaml_output)
        return yaml_output
