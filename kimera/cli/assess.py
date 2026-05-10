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
from . import _resolve_services


@click.command()
@click.argument("service", required=False)
@click.pass_context
def assess(ctx: click.Context, service: str | None) -> None:
    """Assess security posture of services."""
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]
    k8s = ctx.obj["k8s"]

    scanner = SecurityScanner(k8s, logger)

    if service:
        scanner.assess_service(service)
    else:
        services = _resolve_services(config, k8s)
        scanner.assess_all_services(services)
