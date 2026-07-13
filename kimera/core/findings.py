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


from enum import StrEnum

from pydantic import BaseModel, Field


class Severity(StrEnum):
    """Finding severity aligned with CIS benchmark risk levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TechniqueRef(BaseModel):
    """Reference to a MITRE ATT&CK technique and CIS controls."""

    mitre_id: str = Field(default="", description="ATT&CK technique ID (e.g. T1611)")
    mitre_name: str = Field(default="", description="Technique name")
    cis_controls: list[str] = Field(default_factory=list, description="CIS benchmark controls")


class Finding(BaseModel):
    """A single security finding from assessment.

    Returned by the assessor. Consumed by CLI and MCP server.
    """

    target: str = Field(description="What was checked (deployment/container, SA, namespace)")
    check_id: str = Field(description="Check identifier from config/checks/workload.yaml")
    severity: Severity
    title: str
    detail: str = Field(default="")
    evidence: str = Field(default="")
    remediation: str = Field(default="")
    technique: TechniqueRef = Field(default_factory=TechniqueRef)


class AssessmentReport(BaseModel):
    """Structured assessment results for a namespace."""

    namespace: str
    workloads_scanned: int = 0
    findings: list[Finding] = Field(default_factory=list)

    @property
    def critical_count(self) -> int:
        """Count of critical severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    def to_summary(self) -> str:
        """One-line summary for LLM consumption."""
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        parts = [f"{v} {k}" for k, v in sorted(counts.items())]
        return (
            f"{self.workloads_scanned} workloads scanned, "
            f"{len(self.findings)} findings ({', '.join(parts) or 'none'})"
        )


class TechniqueResult(BaseModel):
    """Result from executing a single attack technique.

    Returned by the technique engine. Contains evidence and ATT&CK mapping.
    """

    technique_id: str = Field(description="Kimera technique ID (C1, E1, L1, etc.)")
    technique_name: str = Field(description="Human-readable name")
    mitre_id: str = Field(default="")
    tactic: str = Field(default="")
    target: str = Field(description="What was targeted")
    success: bool
    evidence: list[str] = Field(default_factory=list)
    impact: list[str] = Field(default_factory=list)
    defense_caught: bool | None = Field(
        default=None,
        description="Whether a defense blocked this (None if not checked)",
    )
    defense_detail: str = Field(default="")
    dry_run: bool = Field(default=False)

    def to_summary(self) -> str:
        """One-line summary for LLM consumption."""
        status = "SUCCESS" if self.success else "BLOCKED"
        defense = f" (caught by: {self.defense_detail})" if self.defense_caught else ""
        return (
            f"[{self.technique_id}] {self.technique_name}: {status} against {self.target}{defense}"
        )


class PentestReport(BaseModel):
    """Aggregated results from a pentest run."""

    namespace: str
    techniques_attempted: int = 0
    techniques_succeeded: int = 0
    techniques_blocked: int = 0
    results: list[TechniqueResult] = Field(default_factory=list)
    assessment: AssessmentReport | None = None
    kill_chain: list[str] = Field(
        default_factory=list,
        description="Ordered technique IDs forming a successful attack path",
    )

    def to_summary(self) -> str:
        """One-line summary for LLM consumption."""
        return (
            f"{self.techniques_attempted} techniques attempted, "
            f"{self.techniques_succeeded} succeeded, "
            f"{self.techniques_blocked} blocked by defenses"
        )
