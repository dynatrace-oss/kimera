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

"""Orchestrator for security control validation.

Entry point for ``kimera validate-control``. Dispatches to the appropriate
validator(s) based on the requested control type.
"""

import json

from rich.table import Table

from ..core.k8s_client import K8sClient
from ..core.logger import SecurityLogger, console
from .admission import validate_admission
from .models import (
    ControlType,
    ValidationReport,
    ValidationVerdict,
)
from .network_policy import validate_network_policies
from .rbac import validate_rbac


def validate_controls(
    k8s: K8sClient,
    logger: SecurityLogger,
    control_type: str = "all",
    output_json: bool = False,
) -> list[ValidationReport]:
    """Run security control validation for the given type(s).

    Args:
        k8s: Kubernetes client configured for the target namespace.
        logger: Security logger for console output.
        control_type: One of ``network-policy``, ``admission``, ``rbac``, ``all``.
        output_json: If True, print JSON output instead of Rich tables.

    Returns:
        List of ValidationReport objects.
    """
    reports: list[ValidationReport] = []

    validators = {
        ControlType.NETWORK_POLICY: validate_network_policies,
        ControlType.ADMISSION: validate_admission,
        ControlType.RBAC: validate_rbac,
    }

    if control_type == "all":
        types_to_run = list(validators.keys())
    else:
        try:
            types_to_run = [ControlType(control_type)]
        except ValueError:
            logger.error(
                f"Unknown control type: {control_type}. "
                f"Choose from: {', '.join(t.value for t in ControlType)}, all"
            )
            return []

    for ct in types_to_run:
        console.print(f"\n[bold]═══ Validating: {ct.value} ═══[/bold]\n")
        validator = validators[ct]
        report = validator(k8s, logger)
        reports.append(report)

        if output_json:
            console.print_json(json.dumps(report.to_dict(), indent=2))
        else:
            _render_report(report, logger)

    # Summary across all reports
    if len(reports) > 1:
        _render_summary(reports, logger)

    return reports


def _render_report(report: ValidationReport, logger: SecurityLogger) -> None:
    """Render a single validation report as a Rich table."""
    if not report.results:
        logger.info(f"No checks executed for {report.control_type}.")
        return

    table = Table(
        title=f"Control Validation: {report.control_type}",
        show_lines=True,
    )
    table.add_column("Control", style="cyan", width=25)
    table.add_column("Test", style="white", width=45)
    table.add_column("Expected", style="dim", width=8)
    table.add_column("Actual", style="white", width=12)
    table.add_column("Result", width=6)

    for r in report.results:
        if r.verdict == ValidationVerdict.PASS:
            verdict_str = "[green]✓ PASS[/green]"
        elif r.verdict == ValidationVerdict.FAIL:
            verdict_str = "[red]✗ FAIL[/red]"
        elif r.verdict == ValidationVerdict.ERROR:
            verdict_str = "[yellow]! ERR[/yellow]"
        else:
            verdict_str = "[dim]- SKIP[/dim]"

        table.add_row(
            r.control_name,
            r.test_description,
            r.expected,
            r.actual,
            verdict_str,
        )

    console.print(table)
    console.print(f"\n{report.summary}\n")

    # Print remediation hints for failures
    failures = [r for r in report.results if r.verdict == ValidationVerdict.FAIL]
    if failures:
        console.print("[bold]Remediation needed:[/bold]")
        for f in failures:
            if f.remediation_hint:
                console.print(f"  [red]✗[/red] {f.control_name}: {f.remediation_hint}")
        console.print()


def _render_summary(reports: list[ValidationReport], logger: SecurityLogger) -> None:
    """Render aggregate summary across all validation reports."""
    console.print("\n[bold]═══ Overall Summary ═══[/bold]\n")

    total_passed = sum(r.passed for r in reports)
    total_failed = sum(r.failed for r in reports)
    total_errors = sum(r.errors for r in reports)
    total_checks = sum(r.total for r in reports)

    table = Table(show_header=True)
    table.add_column("Control Type", style="cyan")
    table.add_column("Passed", style="green")
    table.add_column("Failed", style="red")
    table.add_column("Errors", style="yellow")
    table.add_column("Status")

    for r in reports:
        status = "[green]✓ ALL PASS[/green]" if r.all_passed else "[red]✗ ISSUES[/red]"
        table.add_row(
            str(r.control_type),
            str(r.passed),
            str(r.failed),
            str(r.errors),
            status,
        )

    table.add_row(
        "[bold]TOTAL[/bold]",
        f"[bold]{total_passed}[/bold]",
        f"[bold]{total_failed}[/bold]",
        f"[bold]{total_errors}[/bold]",
        "[bold green]✓ SECURE[/bold green]"
        if total_failed == 0 and total_errors == 0
        else "[bold red]✗ GAPS FOUND[/bold red]",
    )

    console.print(table)

    if total_failed > 0:
        logger.warning(
            f"{total_failed} security control(s) failed validation. "
            "Your defenses have gaps that attackers can exploit."
        )
    elif total_checks > 0:
        logger.secure(
            f"All {total_checks} security controls validated successfully. "
            "Your defenses are holding."
        )
