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
    PentestReport,
    Severity,
    TechniqueRef,
    TechniqueResult,
)


class TestSeverityEnum:
    def test_values(self) -> None:
        assert Severity.CRITICAL == "critical"
        assert Severity.HIGH == "high"
        assert Severity.INFO == "info"


class TestFinding:
    def test_with_technique_ref(self) -> None:
        finding = Finding(
            target="frontend/nginx",
            check_id="privileged_mode",
            severity=Severity.CRITICAL,
            title="Privileged container",
            technique=TechniqueRef(
                mitre_id="T1611",
                mitre_name="Escape to Host",
                cis_controls=["5.2.1"],
            ),
        )
        assert finding.severity == Severity.CRITICAL
        assert finding.technique.mitre_id == "T1611"

    def test_default_technique_ref(self) -> None:
        finding = Finding(
            target="test", check_id="test_check", severity=Severity.LOW, title="Test",
        )
        assert finding.technique.mitre_id == ""

    def test_json_serialization(self) -> None:
        finding = Finding(
            target="x", check_id="y", severity=Severity.HIGH, title="z",
        )
        data = finding.model_dump()
        assert data["severity"] == "high"
        assert data["check_id"] == "y"


class TestAssessmentReport:
    def test_severity_counts(self) -> None:
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

    def test_summary_includes_counts(self) -> None:
        report = AssessmentReport(
            namespace="demo", workloads_scanned=5,
            findings=[Finding(target="a", check_id="c1", severity=Severity.HIGH, title="t1")],
        )
        summary = report.to_summary()
        assert "5 workloads scanned" in summary
        assert "1 findings" in summary

    def test_empty_report(self) -> None:
        report = AssessmentReport(namespace="demo", workloads_scanned=2)
        assert report.to_summary().endswith("(none)")


class TestTechniqueResult:
    def test_successful_technique_summary(self) -> None:
        result = TechniqueResult(
            technique_id="C1",
            technique_name="SA token theft",
            mitre_id="T1552.007",
            tactic="credential-access",
            target="frontend-pod",
            success=True,
            evidence=["Token found (1024 bytes)"],
        )
        assert "SUCCESS" in result.to_summary()
        assert "C1" in result.to_summary()

    def test_blocked_technique_summary(self) -> None:
        result = TechniqueResult(
            technique_id="E1",
            technique_name="Privileged escape",
            target="api-pod",
            success=False,
            defense_caught=True,
            defense_detail="Kyverno policy disallow-privileged",
        )
        assert "BLOCKED" in result.to_summary()
        assert "Kyverno" in result.to_summary()


class TestPentestReport:
    def test_summary(self) -> None:
        report = PentestReport(
            namespace="demo",
            techniques_attempted=5,
            techniques_succeeded=3,
            techniques_blocked=1,
            kill_chain=["C1", "L1"],
        )
        assert "5 techniques attempted" in report.to_summary()
        assert report.kill_chain == ["C1", "L1"]

    def test_json_roundtrip(self) -> None:
        report = PentestReport(namespace="demo", techniques_attempted=1)
        json_str = report.model_dump_json()
        assert "demo" in json_str
        restored = PentestReport.model_validate_json(json_str)
        assert restored.namespace == "demo"
