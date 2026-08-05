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

from ..container.assessment.scanner import SecurityScanner
from ..container.core.journal import clear_all, pending_operations, record_operation
from ..container.core.k8s_client import K8sClient
from ..container.core.logger import SecurityLogger, console
from ..container.resource_applier import ResourceApplier
from . import EXPLOITS, REGISTRY, _resolve_services


@click.command()
@click.argument("exploit_type", required=False)
@click.pass_context
def revert(ctx: click.Context, exploit_type: str | None) -> None:
    """Revert changes made by kimera, restoring original deployment state."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    k8s = ctx.obj["k8s"]

    if exploit_type:
        if exploit_type not in EXPLOITS:
            logger.error(f"Unknown exploit type: {exploit_type}")
            return

        service = config.exploit_mappings.get(exploit_type)
        if not service:
            logger.error(f"No service mapping found for {exploit_type}")
            return

        exploit_class = EXPLOITS[exploit_type]
        exploit_instance = exploit_class(k8s, service, logger)
        exploit_instance.revert(dry_run=config.dry_run)
        return

    ops = pending_operations(namespace=config.namespace)
    if not ops:
        logger.info("No recorded operations to revert")
        return

    logger.info(f"Reverting {len(ops)} recorded operation(s)...")

    seen: set[tuple[str, str]] = set()
    for op in ops:
        key = (op["exploit_type"], op["service"])
        if key in seen:
            continue
        seen.add(key)

        action = op.get("action", "make_vulnerable")
        et = op["exploit_type"]
        svc = op["service"]

        if action == "apply":
            _revert_applied_resources(k8s, logger, config.namespace, config.dry_run)
        elif et in REGISTRY:
            entry = REGISTRY[et]
            exploit_instance = entry.cls(k8s, svc, logger)
            exploit_instance.revert(dry_run=config.dry_run)
        else:
            logger.warning(f"Unknown exploit type in journal: {et}")

    if not config.dry_run:
        clear_all()
        logger.success("All operations reverted")


@click.command()
@click.argument("service", required=False)
@click.option("--revision", "-r", type=int, help="Rollback to specific revision")
@click.pass_context
def rollback(ctx: click.Context, service: str | None, revision: int | None) -> None:
    """Rollback deployment to a previous revision."""
    config = ctx.obj["config"]
    k8s = ctx.obj["k8s"]

    if service:
        k8s.rollback_deployment(service, revision)
    else:
        services = _resolve_services(config, k8s)
        for svc in services:
            k8s.rollback_deployment(svc, revision)


@click.command()
@click.pass_context
def rollback_original(ctx: click.Context) -> None:
    """Rollback all services to original version (revision 1)."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    k8s = ctx.obj["k8s"]

    logger.info("Rolling back all services to original versions...")
    services = _resolve_services(config, k8s)
    for service in services:
        k8s.rollback_deployment(service, revision=1)


@click.command()
@click.pass_context
def status(ctx: click.Context) -> None:
    """Show current deployment and security status."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    k8s = ctx.obj["k8s"]

    logger.info("Checking current status...")

    console.print("\n[bold]Namespace Status[/bold]")
    try:
        ns = k8s.v1.read_namespace(config.namespace)
        console.print(f"✅ Namespace '{ns}' exists")
    except Exception:
        console.print("❌ Namespace not found")
        return

    console.print("\n[bold]Deployment Status[/bold]")
    deployments = k8s.apps_v1.list_namespaced_deployment(config.namespace)

    for dep in deployments.items:
        ready = f"{dep.status.ready_replicas or 0}/{dep.spec.replicas}"
        if dep.status.ready_replicas == dep.spec.replicas:
            console.print(f"✅ {dep.metadata.name}: {ready}")
        else:
            console.print(f"⚠️  {dep.metadata.name}: {ready}")

    console.print("\n[bold]Security Status[/bold]")
    scanner = SecurityScanner(k8s, logger)
    services = _resolve_services(config, k8s)
    scanner.quick_security_check(services)


@click.command("apply")
@click.argument("file", type=click.Path(exists=True, dir_okay=False))
@click.pass_context
def apply_resources(ctx: click.Context, file: str) -> None:
    """Apply Kubernetes resources from a YAML file."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    k8s = ctx.obj["k8s"]

    applier = ResourceApplier(k8s, logger)
    applied, _ = applier.apply_from_file(file, config.namespace, dry_run=config.dry_run)

    if applied > 0 and not config.dry_run:
        record_operation("apply", "applied-resources", str(file), config.namespace)


def _revert_applied_resources(
    k8s: K8sClient,
    logger: SecurityLogger,
    namespace: str,
    dry_run: bool,
) -> None:
    from ..container.resource_applier import TOOLKIT_LABEL, TOOLKIT_LABEL_VALUE

    policies = k8s.list_network_policies(namespace)
    removed = 0
    for policy in policies:
        labels = policy.metadata.labels or {}
        if labels.get(TOOLKIT_LABEL) == TOOLKIT_LABEL_VALUE:
            if dry_run:
                logger.info(f"DRY RUN: Would delete NetworkPolicy {policy.metadata.name}")
            else:
                k8s.delete_network_policy(policy.metadata.name, namespace)
            removed += 1

    if removed == 0:
        logger.info("No toolkit-managed resources found to remove")
    elif not dry_run:
        logger.success(f"Removed {removed} toolkit-managed resources")
