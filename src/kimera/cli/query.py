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
from typing import Any

import click
from rich.table import Table

from ..container.core.exceptions import QueryDeniedError
from ..container.core.logger import console
from ..core.enrichment import QueryProvider

# Providers are named here and constructed lazily, so an uninstalled optional
# dependency is an error for that provider rather than for the whole CLI.
PROVIDER_NAMES = ("dynatrace",)
DEFAULT_PROVIDER = "dynatrace"


def _create_query_provider(name: str) -> QueryProvider | None:
    """Build a query provider by name, or None if the name is not registered."""
    if name == "dynatrace":
        from ..container.integrations.dynatrace.enrichment import DynatraceQueryProvider

        return DynatraceQueryProvider()
    return None


def _render(records: list[dict[str, Any]]) -> None:
    columns: list[str] = []
    for record in records:
        for key in record:
            if key not in columns:
                columns.append(key)
    table = Table()
    for column in columns:
        table.add_column(column, overflow="fold")
    for record in records:
        table.add_row(*(str(record.get(column, "")) for column in columns))
    console.print(table)


@click.command("query")
@click.argument("query_string")
@click.option(
    "--provider",
    "provider_name",
    default=DEFAULT_PROVIDER,
    show_default=True,
    help=f"Observability provider to query. One of: {', '.join(PROVIDER_NAMES)}.",
)
@click.option("--json", "output_json", is_flag=True, default=False, help="Emit records as JSON.")
def query(query_string: str, provider_name: str, output_json: bool) -> None:
    """Run QUERY_STRING against an observability provider and report the records.

    The query language is the provider's own — Kimera passes the string through
    unchanged rather than translating between platforms.
    """
    provider = _create_query_provider(provider_name)
    if provider is None:
        raise click.ClickException(
            f"Unknown provider {provider_name!r}. Available: {', '.join(PROVIDER_NAMES)}."
        )

    try:
        records = provider.execute_query(query_string)
    except (ImportError, ValueError, QueryDeniedError) as exc:
        raise click.ClickException(str(exc)) from exc
    except Exception as exc:
        raise click.ClickException(f"Query failed: {exc}") from exc

    if output_json:
        console.print(json.dumps(records, indent=2, default=str), highlight=False)
        return

    if not records:
        console.print("[INFO] Query returned no records.")
        return

    _render(records)
    console.print(f"[INFO] {len(records)} record(s).")
