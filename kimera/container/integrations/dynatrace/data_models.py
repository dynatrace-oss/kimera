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


@dataclass(frozen=True)
class KspmFinding:
    """A single KSPM compliance finding."""

    object_name: str
    rule_title: str
    count: int = 1


@dataclass(frozen=True)
class SmartscapeEdge:
    """An observed Smartscape communication edge."""

    source_name: str
    target_name: str
    source_workload: str = ""  # K8s workload name (from getNodeField(id, "k8s.workload.name"))
    target_workload: str = ""


@dataclass(frozen=True)
class DtContext:
    """Aggregated Dynatrace context returned by a data strategy.

    Contains both structured data (for programmatic use) and pre-formatted
    text (for backward compatibility with existing prompt templates).
    """

    strategy_name: str
    kspm_findings: list[KspmFinding] = field(default_factory=list)
    smartscape_edges: list[SmartscapeEdge] = field(default_factory=list)
    queries_executed: list[str] = field(default_factory=list)
    records_fetched: int = 0
    raw_kspm: str = ""
    raw_smartscape: str = ""
    summary: str = ""
