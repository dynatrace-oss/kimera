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
from . import EXPLOITS, _resolve_services


@click.command()
@click.argument("exploit_type", required=False)
@click.option("--service", "-s", help="Override target service")
@click.pass_context
def secure(ctx: click.Context, exploit_type: str | None, service: str | None) -> None:
    """Print remediation guidance for security issues."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    k8s = ctx.obj["k8s"]

    if exploit_type:
        if exploit_type not in EXPLOITS:
            logger.error(f"Unknown exploit type: {exploit_type}")
            return

        target_service = service or config.exploit_mappings.get(exploit_type)
        exploit_class = EXPLOITS[exploit_type]
        exploit_instance = exploit_class(k8s, target_service, logger)
        exploit_instance.make_secure(dry_run=config.dry_run)
    else:
        for et, svc in config.exploit_mappings.items():
            if et in EXPLOITS:
                exploit_class = EXPLOITS[et]
                exploit_instance = exploit_class(k8s, svc, logger)
                exploit_instance.make_secure(dry_run=config.dry_run)


@click.command()
@click.argument("service")
@click.pass_context
def secure_service(ctx: click.Context, service: str) -> None:
    """Print remediation guidance for a specific service."""
    config = ctx.obj["config"]
    ns = config.namespace
    console.print(f"\n[bold]Remediation for {service}[/bold]\n")
    console.print(f"  kimera -n {ns} generate --type all --apply\n")
    console.print("[dim]Or target a specific exploit type:[/dim]")
    console.print(f"  kimera -n {ns} generate --type privileged-containers --apply")
    console.print(f"  kimera -n {ns} generate --type dangerous-capabilities --apply")
    console.print(f"  kimera -n {ns} generate --type host-namespace-sharing --apply")
    console.print(f"  kimera -n {ns} generate --type missing-resource-limits --apply")
    console.print(f"  kimera -n {ns} generate --type missing-network-policies --apply\n")


@click.command()
@click.pass_context
def verify(ctx: click.Context) -> None:
    """Verify security improvements."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    k8s = ctx.obj["k8s"]

    logger.info("Verifying security improvements...")

    all_secure = True
    results = []
    services = _resolve_services(config, k8s)

    for service in services:
        pod_name = k8s.find_pod_for_service(service)
        if not pod_name:
            results.append((service, "No pod found", False))
            all_secure = False
            continue

        try:
            pod = k8s.v1.read_namespaced_pod(pod_name, k8s.namespace)
            issues = []

            container = pod.spec.containers[0]
            if container.security_context and container.security_context.privileged:
                issues.append("Privileged")
            if (
                container.security_context
                and container.security_context.capabilities
                and container.security_context.capabilities.add
            ):
                issues.append("Dangerous capabilities")
            if pod.spec.host_pid or pod.spec.host_network or pod.spec.host_ipc:
                issues.append("Host namespace access")
            if not container.resources or not container.resources.limits:
                issues.append("No resource limits")

            if issues:
                results.append((service, ", ".join(issues), False))
                all_secure = False
            else:
                results.append((service, "Secure", True))

        except Exception as e:
            results.append((service, f"Error: {e}", False))
            all_secure = False

    table = Table(title="Security Verification Results")
    table.add_column("Service", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Secure", style="white")

    for service, status_text, is_secure in results:
        table.add_row(service, status_text, "✅" if is_secure else "❌")

    console.print(table)

    policies = k8s.list_network_policies(k8s.namespace)
    if policies:
        console.print(f"\n✅ {len(policies)} NetworkPolicies in namespace {k8s.namespace}")
    else:
        console.print(f"\n❌ No NetworkPolicies in namespace {k8s.namespace}")
        all_secure = False

    if all_secure:
        logger.secure("All security verifications passed! 🎉")
    else:
        logger.warning("Some security issues remain. Please review the output above.")
