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


class ControlType(StrEnum):
    """Types of security controls that can be validated."""

    NETWORK_POLICY = "network-policy"
    ADMISSION = "admission"
    RBAC = "rbac"


class ValidationVerdict(StrEnum):
    """Outcome of a single validation check."""

    PASS = "pass"  # noqa: S105
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"


@dataclass(frozen=True)
class ValidationResult:
    """Result of a single control validation check.

    Attributes:
        control_type: Category of control tested.
        control_name: Name of the specific policy/role/controller tested.
        test_description: Human-readable description of what was tested.
        expected: What we expected the control to do (e.g. "BLOCK", "REJECT").
        actual: What actually happened (e.g. "BLOCKED", "ALLOWED").
        verdict: Pass/fail/error/skipped.
        evidence: Raw output or API response that proves the result.
        remediation_hint: Suggested action if the control failed.
    """

    control_type: ControlType
    control_name: str
    test_description: str
    expected: str
    actual: str
    verdict: ValidationVerdict
    evidence: str = ""
    remediation_hint: str = ""


@dataclass
class ValidationReport:
    """Aggregated results from a validate-control run.

    Attributes:
        namespace: Namespace that was validated.
        control_type: Category of controls tested.
        results: Individual check results.
        summary: Human-readable summary.
    """

    namespace: str
    control_type: ControlType | str
    results: list[ValidationResult] = field(default_factory=list)
    summary: str = ""

    @property
    def passed(self) -> int:
        """Count of checks that passed."""
        return sum(1 for r in self.results if r.verdict == ValidationVerdict.PASS)

    @property
    def failed(self) -> int:
        """Count of checks that failed."""
        return sum(1 for r in self.results if r.verdict == ValidationVerdict.FAIL)

    @property
    def errors(self) -> int:
        """Count of checks that errored."""
        return sum(1 for r in self.results if r.verdict == ValidationVerdict.ERROR)

    @property
    def total(self) -> int:
        """Total number of checks executed."""
        return len(self.results)

    @property
    def all_passed(self) -> bool:
        """True if every check passed (no failures or errors)."""
        return self.failed == 0 and self.errors == 0 and self.total > 0

    def to_dict(self) -> dict:
        """Serialize to dict for JSON output."""
        return {
            "namespace": self.namespace,
            "control_type": str(self.control_type),
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "errors": self.errors,
            "all_passed": self.all_passed,
            "results": [
                {
                    "control_type": str(r.control_type),
                    "control_name": r.control_name,
                    "test_description": r.test_description,
                    "expected": r.expected,
                    "actual": r.actual,
                    "verdict": str(r.verdict),
                    "evidence": r.evidence,
                    "remediation_hint": r.remediation_hint,
                }
                for r in self.results
            ],
            "summary": self.summary,
        }
