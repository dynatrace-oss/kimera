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
from typing import Any


@dataclass
class ExploitMetadata:
    """Metadata for an exploit plugin.

    Attributes:
        name: Unique exploit identifier
        display_name: Human-readable name
        risk_level: Risk severity (CRITICAL, HIGH, MEDIUM, LOW)
        description: Detailed description
        mitre_tactics: MITRE ATT&CK tactics
        mitre_techniques: MITRE ATT&CK technique IDs
        cis_controls: CIS Benchmark control IDs
        cve_ids: Related CVE identifiers
        version: Plugin version
        author: Plugin author
    """

    name: str
    display_name: str
    risk_level: str
    description: str
    mitre_tactics: list[str] = field(default_factory=list)
    mitre_techniques: list[str] = field(default_factory=list)
    cis_controls: list[str] = field(default_factory=list)
    cve_ids: list[str] = field(default_factory=list)
    version: str = "1.0.0"
    author: str = "Dynatrace OSS"


@dataclass
class ExploitResult:
    """Result of an exploit execution.

    Attributes:
        success: Whether exploit succeeded
        message: Result message
        evidence: List of evidence items
        impact: List of impact items
        metadata: Additional metadata
    """

    success: bool
    message: str
    evidence: list[str] = field(default_factory=list)
    impact: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def add_evidence(self, item: str) -> None:
        """Add evidence item."""
        self.evidence.append(item)

    def add_impact(self, item: str) -> None:
        """Add impact item."""
        self.impact.append(item)


@dataclass
class VulnerabilityCheck:
    """Result of vulnerability check.

    Attributes:
        vulnerable: Whether system is vulnerable
        details: Check details
        severity: Vulnerability severity
        remediation_available: Whether remediation is available
    """

    vulnerable: bool
    details: str
    severity: str
    remediation_available: bool = True


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
