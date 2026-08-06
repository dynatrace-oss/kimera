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
from enum import StrEnum
from typing import Any


class PathResult(StrEnum):
    """Observed outcome of probing one network path.

    ``UNKNOWN`` is never collapsed into ``BLOCKED``: a path nothing could measure
    is not a path something denied.
    """

    REACHABLE = "REACHABLE"
    BLOCKED = "BLOCKED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class AttackPath:
    """One network path a demonstration probed, and what it observed.

    ``source`` is the workload name, not the pod name: a NetworkPolicy selects
    pods by the workload's labels, and pod names change on every restart.
    """

    source: str
    host: str
    port: int
    protocol: str
    result: PathResult

    def describe(self) -> str:
        """Return a one-line summary naming both ends and the outcome."""
        return f"{self.source} -> {self.host}:{self.port}/{self.protocol} {self.result}"


@dataclass
class ExploitResult:
    """Result of an exploit execution.

    Attributes:
        success: Whether exploit succeeded
        message: Result message
        evidence: List of evidence items
        impact: List of impact items
        attack_paths: Network paths probed, with their observed results
        metadata: Additional metadata
    """

    success: bool
    message: str
    evidence: list[str] = field(default_factory=list)
    impact: list[str] = field(default_factory=list)
    attack_paths: list[AttackPath] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceMarker:
    """Maps a string found in test output to evidence and impact entries.

    Used by ``SecurityTest`` to declaratively extract findings from
    shell command output without ad-hoc string matching.
    """

    marker: str
    evidence: str
    impact: str = ""


@dataclass
class SecurityTest:
    """A single security test to run inside a pod.

    Encapsulates the shell script, evidence extraction rules, and
    impact descriptions for one test within an exploit demonstration.
    """

    name: str
    script: str
    evidence_markers: list[EvidenceMarker] = field(default_factory=list)
    summary_impact: list[str] = field(default_factory=list)


@dataclass
class CommandResult:
    """Structured result of a subprocess command execution.

    Wraps ``subprocess.run()`` output with a consistent interface
    for checking success and accessing stdout/stderr.
    """

    command: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def success(self) -> bool:
        """Return True if the command exited with code 0."""
        return self.returncode == 0
