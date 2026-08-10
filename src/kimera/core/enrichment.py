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

from dataclasses import dataclass, field
from typing import Any, Protocol

from ..container.core.logger import SecurityLogger


@dataclass
class EnrichmentContext:
    """Extra context from an observability platform for LLM remediation.

    Fields use generic names so any platform can provide them:
      compliance_context — KSPM findings, Falco alerts, OPA violations, etc.
      topology_context  — service graph, network flows, dependency map, etc.
    """

    compliance_context: str | None = None
    topology_context: str | None = None
    source: str = ""
    queries_executed: list[str] = field(default_factory=list)


class QueryProvider(Protocol):
    """Protocol for running a query against an observability platform.

    Separate from EnrichmentProvider: that one answers a fixed question shaped for
    an LLM prompt, this one runs the caller's own query and returns the records.
    The query language stays the platform's own — translating between platform
    query languages would be a layer with one implementation on each side.
    """

    @property
    def name(self) -> str: ...  # noqa: D102

    @property
    def query_language(self) -> str: ...  # noqa: D102

    def execute_query(self, query: str) -> list[dict[str, Any]]:  # noqa: D102
        """Run ``query`` and return its records.

        Raises:
            ImportError: An optional dependency the provider needs is absent.
            ValueError: Required credentials are absent.
            QueryDeniedError: The provider refused the request (HTTP 403).
        """
        ...


class EnrichmentProvider(Protocol):
    """Protocol for observability platform enrichment.

    Implement this to add a new enrichment source (Dynatrace, Datadog,
    Falco, etc.). The generate command discovers providers and calls
    fetch() to get extra context for the LLM prompt.
    """

    @property
    def name(self) -> str: ...  # noqa: D102

    def fetch(  # noqa: D102
        self,
        logger: SecurityLogger,
        namespace: str,
        cluster_name: str,
        exploit_type: str,
        **kwargs: str,
    ) -> EnrichmentContext | None: ...
