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

import click
from rich.table import Table

from ..container.core.logger import console
from ..container.make_vulnerable.probe_runner import ProbeRunner
from ..core.technique_engine import (
    TechniqueRegistry,
    _resolve_probe_params,
    execute_technique,
)


def _parse_params(pairs: tuple[str, ...]) -> dict[str, str]:
    """Split ``key=value`` arguments, rejecting anything that is not a pair.

    Raises:
        click.BadParameter: If an argument contains no ``=``.
    """
    params: dict[str, str] = {}
    for pair in pairs:
        key, sep, value = pair.partition("=")
        if not sep or not key:
            raise click.BadParameter(f"expected key=value, got {pair!r}", param_hint="--param")
        params[key] = value
    return params


@click.group("technique")
def technique() -> None:
    """List and run ATT&CK-mapped techniques from the technique registry."""


@technique.command("list")
@click.option("--phase", default=None, help="Only show techniques in this phase.")
def list_techniques(phase: str | None) -> None:
    """Show the techniques available in the registry."""
    registry = TechniqueRegistry()
    rows = [t for t in registry.list_techniques() if phase is None or t["phase"] == phase]
    if not rows:
        console.print("[INFO] No techniques matched.")
        return
    table = Table(title="Techniques")
    for column in ("ID", "Name", "Phase", "Tactic", "MITRE", "Mode"):
        table.add_column(column)
    for row in rows:
        table.add_row(
            row["id"], row["name"], row["phase"], row["tactic"], row["mitre_id"], row["mode"]
        )
    console.print(table)


@technique.command("run")
@click.argument("technique_id")
@click.option("--pod", "target_pod", default=None, help="Target pod for exec-mode techniques.")
@click.option(
    "--param",
    "param_pairs",
    multiple=True,
    metavar="KEY=VALUE",
    help="Value for a {{ KEY }} placeholder in the technique's probes. Repeatable.",
)
@click.option(
    "--dry-run",
    is_flag=True,
    default=False,
    help="Print the resolved probe script without executing it.",
)
@click.option("--json", "output_json", is_flag=True, default=False, help="Emit result as JSON.")
@click.pass_context
def run_technique(
    ctx: click.Context,
    technique_id: str,
    target_pod: str | None,
    param_pairs: tuple[str, ...],
    dry_run: bool,
    output_json: bool,
) -> None:
    """Run TECHNIQUE_ID against a target and report its evidence."""
    k8s = ctx.obj["k8s"]
    params = _parse_params(param_pairs)

    registry = TechniqueRegistry()
    definition = registry.get(technique_id)
    if not definition:
        raise click.ClickException(f"Technique {technique_id!r} is not in the registry.")

    if dry_run:
        resolved = [_resolve_probe_params(p, params, k8s.namespace) for p in definition.probes]
        console.print(ProbeRunner().build_script(resolved), highlight=False)
        return

    result = execute_technique(
        k8s=k8s,
        registry=registry,
        technique_id=technique_id,
        target_pod=target_pod,
        params=params,
    )

    if output_json:
        console.print(json.dumps(result.model_dump(), indent=2), highlight=False)
        return

    console.print(f"[{'SUCCESS' if result.success else 'INFO'}] {result.technique_name}")
    for line in result.evidence:
        console.print(f"  • {line}")
    for line in result.impact:
        console.print(f"  ! {line}")
    if result.raw_output:
        console.print("[INFO] Probe output:")
        console.print(result.raw_output, highlight=False)
