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

from typing import Any

import click

from ..application.config.schemas import ToolkitConfig
from ..container.core.journal import record_operation
from ..container.core.logger import SecurityLogger, console
from ..container.infrastructure.resource_applier import ResourceApplier
from . import REGISTRY


@click.command("generate")
@click.option(
    "--mode", default="remediate", show_default=True,
    type=click.Choice(["remediate", "exploit"]),
    help="Generation mode.",
)
@click.option(
    "--type", "exploit_type", default="missing-network-policies", show_default=True,
    type=click.Choice(["all"] + REGISTRY.types),
    help="Type of remediation or exploit to generate.",
)
@click.option("--service", default=None, help="Target service for exploit mode.")
@click.option("--output", "-o", default=None, help="Output file path.")
@click.option("--model", default="claude-sonnet-4-6", show_default=True, help="Anthropic model.")
@click.option("--apply", "apply_generated", is_flag=True, default=False, help="Apply after generation.")
@click.option("--use-dt-mcp", is_flag=True, default=False, help="Enrich with Dynatrace MCP data.")
@click.option(
    "--dt-strategy", default="targeted", show_default=True,
    type=click.Choice(["targeted", "llm-query", "davis"]),
    help="DT data fetching strategy.",
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
    use_dt_mcp: bool,
    dt_strategy: str,
    yes: bool,
) -> None:
    """Generate security remediations or exploit patches using an LLM."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    k8s = ctx.obj["k8s"]

    from ..container.remediations.generator import LLMRemediationGenerator

    if output is None:
        output = "kimera-exploit.yaml" if mode == "exploit" else "kimera-remediations.yaml"

    if dt_strategy != "targeted" and not use_dt_mcp:
        logger.error("--dt-strategy requires --use-dt-mcp")
        return

    smartscape_context: str | None = None
    kspm_context: str | None = None

    if use_dt_mcp:
        dt_context = _fetch_dt_context(config, logger, dt_strategy, exploit_type, model)
        if dt_context:
            smartscape_context = dt_context.raw_smartscape or None
            kspm_context = dt_context.raw_kspm or None

    generator = LLMRemediationGenerator(
        k8s=k8s, logger=logger, network_topology=config.network_topology, model=model,
    )

    try:
        if mode == "exploit":
            yaml_output = generator.generate_exploit(
                exploit_type=exploit_type, service=service,
                kspm_context=kspm_context, smartscape_context=smartscape_context,
            )
        else:
            yaml_output = generator.generate(
                exploit_type=exploit_type,
                kspm_context=kspm_context, smartscape_context=smartscape_context,
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


def _fetch_dt_context(
    config: ToolkitConfig,
    logger: SecurityLogger,
    strategy_name: str,
    exploit_type: str,
    model: str,
) -> Any:
    import asyncio
    import os

    from ..container.infrastructure.dt_data_models import DtContext
    from ..container.infrastructure.dt_query_strategies import create_strategy

    dt_env = os.environ.get("DT_ENVIRONMENT", "")
    dt_token = os.environ.get("DT_PLATFORM_TOKEN", "")

    if not dt_env or not dt_token:
        logger.warning(
            "DT MCP requires DT_ENVIRONMENT and DT_PLATFORM_TOKEN. "
            "Skipping DT MCP enrichment."
        )
        return None

    try:
        from ..container.infrastructure.dt_mcp_client import DynatraceMCPClient
    except ImportError as e:
        logger.warning(f"DT MCP client not available: {e}. Skipping enrichment.")
        return None

    strategy_kwargs: dict[str, str] = {}
    if strategy_name == "llm-query":
        strategy_kwargs["model"] = model

    try:
        strategy = create_strategy(strategy_name, **strategy_kwargs)
    except (ValueError, ImportError) as e:
        logger.error(f"Failed to create DT strategy '{strategy_name}': {e}")
        return None

    async def _fetch() -> DtContext | None:
        mcp_client = DynatraceMCPClient(dt_env, dt_token)
        try:
            await mcp_client.connect()
            logger.info(f"Connected to DT MCP gateway (strategy: {strategy.name})")
            namespace = config.namespace
            cluster_name = config.kubernetes.context or ""
            ctx = await strategy.fetch(mcp_client, exploit_type, namespace, cluster_name)
            logger.info(ctx.summary)
            return ctx
        except Exception as e:
            logger.warning(f"DT MCP enrichment failed: {e}")
            return None
        finally:
            await mcp_client.close()

    return asyncio.run(_fetch())
