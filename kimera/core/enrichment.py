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
from typing import Protocol

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
