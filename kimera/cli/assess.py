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
from rich.table import Table

from ..container.core.logger import console
from ..core.assessor import assess_namespace
from ..core.findings import AssessmentReport, Severity

_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "dim",
    Severity.INFO: "dim",
}


def _render_report(report: AssessmentReport) -> None:
    """Render an AssessmentReport as Rich tables."""
    if not report.findings:
        console.print(f"\n[green]✅ No findings in namespace '{report.namespace}'[/green]")
        console.print(f"   Scanned {report.workloads_scanned} workloads\n")
        return

    table = Table(
        title=f"Assessment: {report.namespace} ({report.workloads_scanned} workloads)",
        show_lines=True,
    )
    table.add_column("Severity", width=10)
    table.add_column("Target", style="cyan", width=30)
    table.add_column("Finding", width=35)
    table.add_column("MITRE", style="dim", width=12)
    table.add_column("Remediation", width=40)

    for finding in sorted(report.findings, key=lambda f: list(Severity).index(f.severity)):
        style = _SEVERITY_STYLE.get(finding.severity, "")
        table.add_row(
            f"[{style}]{finding.severity.upper()}[/{style}]",
            finding.target,
            finding.title + (f"\n{finding.detail}" if finding.detail else ""),
            finding.technique.mitre_id,
            finding.remediation[:80] + "..." if len(finding.remediation) > 80 else finding.remediation,
        )

    console.print(table)

    console.print(f"\n  {report.critical_count} critical, {report.high_count} high, "
                  f"{len(report.findings)} total findings\n")


@click.command()
@click.argument("service", required=False)
@click.option("--json", "output_json", is_flag=True, default=False, help="Output as JSON.")
@click.pass_context
def assess(ctx: click.Context, service: str | None, output_json: bool) -> None:
    """Assess security posture of workloads in the namespace.

    Scans all deployments against CIS Kubernetes Benchmark controls.
    Each finding includes severity, MITRE ATT&CK mapping, and remediation.
    """
    k8s = ctx.obj["k8s"]

    report = assess_namespace(k8s)

    if output_json:
        import json
        data = report.model_dump()
        data["summary"] = report.to_summary()
        console.print_json(json.dumps(data, indent=2))
    else:
        _render_report(report)
