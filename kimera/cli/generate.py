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

import click

from ..container.core.journal import record_operation
from ..container.core.logger import console
from ..container.resource_applier import ResourceApplier
from . import REGISTRY


@click.command("generate")
@click.option(
    "--mode",
    default="remediate",
    show_default=True,
    type=click.Choice(["remediate", "exploit"]),
    help="Generation mode.",
)
@click.option(
    "--type",
    "exploit_type",
    default="missing-network-policies",
    show_default=True,
    type=click.Choice(["all"] + REGISTRY.types),
    help="Type of remediation or exploit to generate.",
)
@click.option("--service", default=None, help="Target service for exploit mode.")
@click.option("--output", "-o", default=None, help="Output file path.")
@click.option("--model", default="claude-sonnet-4-6", show_default=True, help="Anthropic model.")
@click.option(
    "--apply", "apply_generated", is_flag=True, default=False, help="Apply after generation."
)
@click.option(
    "--enrich",
    default=None,
    type=click.Choice(["dynatrace"]),
    help="Enrich LLM context with observability data.",
)
@click.option(
    "--enrich-strategy",
    default="targeted",
    show_default=True,
    type=click.Choice(["targeted", "llm-query", "davis"]),
    help="Enrichment data fetching strategy.",
)
@click.option("--yes", "-y", is_flag=True, default=False, help="Skip confirmation prompt.")
@click.pass_context
def generate(
    ctx: click.Context,
    mode: str,
    exploit_type: str,
    service: str | None,
    output: str | None,
    model: str,
    apply_generated: bool,
    enrich: str | None,
    enrich_strategy: str,
    yes: bool,
) -> None:
    """Generate security remediations or exploit patches using an LLM."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    k8s = ctx.obj["k8s"]

    from ..container.remediations.generator import LLMRemediationGenerator

    if output is None:
        output = "kimera-exploit.yaml" if mode == "exploit" else "kimera-remediations.yaml"

    # Fetch enrichment context from observability platform
    compliance_context: str | None = None
    topology_context: str | None = None

    if enrich:
        provider = _create_enrichment_provider(enrich, strategy=enrich_strategy, model=model)
        if provider:
            enrichment = provider.fetch(
                logger=logger,
                namespace=config.namespace,
                cluster_name=config.kubernetes.context or "",
                exploit_type=exploit_type,
            )
            if enrichment:
                compliance_context = enrichment.compliance_context
                topology_context = enrichment.topology_context

    generator = LLMRemediationGenerator(
        k8s=k8s,
        logger=logger,
        network_topology=config.network_topology,
        model=model,
    )

    try:
        if mode == "exploit":
            yaml_output = generator.generate_exploit(
                exploit_type=exploit_type,
                service=service,
                kspm_context=compliance_context,
                smartscape_context=topology_context,
            )
        else:
            yaml_output = generator.generate(
                exploit_type=exploit_type,
                kspm_context=compliance_context,
                smartscape_context=topology_context,
            )
    except ImportError as e:
        logger.error(str(e))
        return
    except ValueError as e:
        logger.error(f"Generation failed: {e}")
        return

    from pathlib import Path

    Path(output).write_text(yaml_output)
    label = "exploit patches" if mode == "exploit" else "remediations"
    logger.success(f"Generated {label} written to {output}")
    console.print(f"\n[dim]Preview:[/dim]\n{yaml_output[:2000]}")
    if len(yaml_output) > 2000:
        console.print(f"[dim]... ({len(yaml_output)} chars total, see {output})[/dim]")

    if not apply_generated:
        console.print(f"\n[dim]Re-run with --apply to apply, or use: kimera apply {output}[/dim]")
        return

    if not yes and not config.dry_run:
        if not click.confirm(f"\nApply {label} from {output}?", default=False):
            logger.info("Cancelled")
            return

    applier = ResourceApplier(k8s, logger)

    if mode == "exploit":
        applied, _ = applier.apply_exploit_patches(output, config.namespace, dry_run=config.dry_run)
        op_action = "make_vulnerable"
    else:
        applied, _ = applier.apply_from_file(output, config.namespace, dry_run=config.dry_run)
        op_action = "apply"

    if applied > 0 and not config.dry_run:
        record_operation(op_action, exploit_type, output, config.namespace)


def _create_enrichment_provider(
    name: str,
    *,
    strategy: str = "targeted",
    model: str = "",
) -> object | None:
    """Create an enrichment provider by name.

    Returns None if the provider's dependencies are not installed.
    """
    if name == "dynatrace":
        from ..container.integrations.dynatrace.enrichment import DynatraceEnrichmentProvider

        kwargs: dict[str, str] = {}
        if model:
            kwargs["model"] = model
        return DynatraceEnrichmentProvider(strategy_name=strategy, **kwargs)
    return None
