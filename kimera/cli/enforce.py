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

from ..container.core.logger import console
from ..container.enforcement import PolicyEnforcementManager


@click.group()
@click.pass_context
def enforce(ctx: click.Context) -> None:
    """Manage NetworkPolicy enforcement (Cilium)."""


@enforce.command("enable")
@click.pass_context
def enforce_enable(ctx: click.Context) -> None:
    """Check for Cilium NetworkPolicy enforcement; print install guidance if not found."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    k8s = ctx.obj["k8s"]

    manager = PolicyEnforcementManager(k8s, logger)
    manager.enable(dry_run=config.dry_run)


@enforce.command("disable")
@click.pass_context
def enforce_disable(ctx: click.Context) -> None:
    """Show guidance for removing Cilium and disabling NetworkPolicy enforcement."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    k8s = ctx.obj["k8s"]

    manager = PolicyEnforcementManager(k8s, logger)

    if not manager.is_enabled():
        logger.info("Cilium is not running — no enforcement to disable")
        return

    manager.disable(dry_run=config.dry_run)


@enforce.command("status")
@click.pass_context
def enforce_status(ctx: click.Context) -> None:
    """Show NetworkPolicy enforcement status."""
    logger = ctx.obj["logger"]
    k8s = ctx.obj["k8s"]

    manager = PolicyEnforcementManager(k8s, logger)
    status_info = manager.get_status()

    if not status_info.get("installed"):
        console.print("NetworkPolicy enforcement: [red]not installed[/red]")
        console.print("\nRun 'kimera enforce enable' to check Cilium enforcement status.")
        return

    console.print("NetworkPolicy enforcement: [green]active[/green]")
    console.print(f"  Image:     {status_info['image']}")
    console.print(f"  Desired:   {status_info['desired']}")
    console.print(f"  Ready:     {status_info['ready']}")
    console.print(f"  Available: {status_info['available']}")
