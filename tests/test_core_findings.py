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


from kimera.core.findings import (
    AssessmentReport,
    Finding,
    Severity,
    TechniqueResult,
)


class TestAssessmentReportSummary:
    """to_summary() is consumed by MCP tools — wrong format breaks agents."""

    def test_counts_each_severity_independently(self) -> None:
        report = AssessmentReport(
            namespace="demo",
            workloads_scanned=3,
            findings=[
                Finding(target="a", check_id="c1", severity=Severity.CRITICAL, title="t1"),
                Finding(target="b", check_id="c2", severity=Severity.CRITICAL, title="t2"),
                Finding(target="c", check_id="c3", severity=Severity.HIGH, title="t3"),
                Finding(target="d", check_id="c4", severity=Severity.LOW, title="t4"),
            ],
        )
        assert report.critical_count == 2
        assert report.high_count == 1
        summary = report.to_summary()
        assert "3 workloads scanned" in summary
        assert "4 findings" in summary

    def test_empty_findings_does_not_crash(self) -> None:
        report = AssessmentReport(namespace="demo", workloads_scanned=2)
        summary = report.to_summary()
        assert "none" in summary
        assert report.critical_count == 0


class TestTechniqueResultSummary:
    """to_summary() drives MCP tool output — must distinguish success vs blocked."""

    def test_success_includes_technique_id(self) -> None:
        result = TechniqueResult(
            technique_id="C1",
            technique_name="SA token theft",
            target="frontend-pod",
            success=True,
            evidence=["Token found"],
        )
        summary = result.to_summary()
        assert "SUCCESS" in summary
        assert "C1" in summary

    def test_blocked_includes_defense_detail(self) -> None:
        result = TechniqueResult(
            technique_id="E1",
            technique_name="Privileged escape",
            target="api-pod",
            success=False,
            defense_caught=True,
            defense_detail="Kyverno policy disallow-privileged",
        )
        summary = result.to_summary()
        assert "BLOCKED" in summary
        assert "Kyverno" in summary
