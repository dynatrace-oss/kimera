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

from ..container.validation.engine import validate_controls


@click.command("validate-control")
@click.option(
    "--type",
    "control_type",
    default="all",
    show_default=True,
    type=click.Choice(["network-policy", "admission", "rbac", "all"]),
    help="Type of security control to validate.",
)
@click.option(
    "--json",
    "output_json",
    is_flag=True,
    default=False,
    help="Output results as JSON.",
)
@click.pass_context
def validate_control(ctx: click.Context, control_type: str, output_json: bool) -> None:
    r"""Validate that security controls actually block attacks.

    Tests whether NetworkPolicies, admission controllers (PSA, Kyverno,
    Gatekeeper), and RBAC restrictions hold by:

    \b
      network-policy: Deploy ephemeral probe pod, test connectivity
      admission:      Submit test resources via --dry-run=server
      rbac:           Check SA permissions via role/binding analysis

    Safe for production: uses dry-run and ephemeral resources only.
    """
    logger = ctx.obj["logger"]
    k8s = ctx.obj["k8s"]

    validate_controls(k8s, logger, control_type=control_type, output_json=output_json)
