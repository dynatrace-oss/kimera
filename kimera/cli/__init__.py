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

import sys
from typing import Any

import click

from ..application.config.loader import ConfigLoader
from ..application.config.registry import ExploitRegistry
from ..application.config.schemas import ToolkitConfig
from ..container.core.k8s_client import K8sClient
from ..container.core.logger import SecurityLogger, setup_logger

REGISTRY = ExploitRegistry()
EXPLOITS = REGISTRY.classes


def _load_config(
    namespace: str,
    profile: str | None,
    debug: bool,
    dry_run: bool,
    verbose: bool,
) -> ToolkitConfig:
    overrides: dict[str, Any] = {}
    if debug:
        overrides["debug"] = True
    if dry_run:
        overrides["dry_run"] = True
    if verbose:
        overrides["verbose"] = True

    effective_profile = profile
    if not effective_profile and namespace == "unguard":
        effective_profile = "unguard"

    if namespace != "default":
        overrides["kubernetes"] = {"namespace": namespace}

    loader = ConfigLoader()
    return loader.load(profile=effective_profile, overrides=overrides)


def _resolve_services(config: ToolkitConfig, k8s: K8sClient) -> list[str]:
    if config.services:
        return config.services
    try:
        deployments = k8s.apps_v1.list_namespaced_deployment(config.namespace)
        return [d.metadata.name for d in deployments.items]
    except Exception:
        return []


@click.group()
@click.option("--namespace", "-n", default="default", help="Target namespace")
@click.option("--profile", "-p", default=None, help="Config profile (e.g., unguard)")
@click.option("--debug", is_flag=True, help="Enable debug output")
@click.option("--dry-run", is_flag=True, help="Preview changes without applying")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(
    ctx: click.Context,
    namespace: str,
    profile: str | None,
    debug: bool,
    dry_run: bool,
    verbose: bool,
) -> None:
    """Kubernetes Container Security Lab - Assessment and Exploitation Toolkit."""
    ctx.ensure_object(dict)

    config = _load_config(namespace, profile, debug, dry_run, verbose)
    logger = SecurityLogger(setup_logger("k8s_security", debug=config.debug))

    try:
        k8s_client = K8sClient(namespace=config.namespace, logger=logger, verbose=config.verbose)
    except Exception as e:
        logger.error(f"Failed to initialize Kubernetes client: {e}")
        sys.exit(1)

    ctx.obj["config"] = config
    ctx.obj["logger"] = logger
    ctx.obj["k8s"] = k8s_client

    if ctx.invoked_subcommand in ["assess", "exploit", "secure", "verify"]:
        from ..banner import show_banner
        show_banner(config.namespace)


# Register subcommands
from .assess import assess  # noqa: E402, I001
from .enforce import enforce  # noqa: E402, I001
from .exploit import exploit, exploit_all, vuln, vuln_service  # noqa: E402, I001
from .manage import apply_resources, revert, rollback, rollback_original, status  # noqa: E402, I001
from .generate import generate  # noqa: E402, I001
from .secure import secure, secure_service, verify  # noqa: E402, I001
from .validate import validate_control  # noqa: E402, I001

cli.add_command(assess)
cli.add_command(exploit)
cli.add_command(exploit_all)
cli.add_command(vuln)
cli.add_command(vuln_service)
cli.add_command(secure)
cli.add_command(secure_service)
cli.add_command(verify)
cli.add_command(rollback)
cli.add_command(rollback_original)
cli.add_command(revert)
cli.add_command(status)
cli.add_command(apply_resources)
cli.add_command(validate_control)
cli.add_command(enforce)
cli.add_command(generate)
