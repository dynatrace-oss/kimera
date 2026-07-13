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

"""Unit tests for the validate-control models."""

from kimera.container.validation.models import (
    ControlType,
    ValidationReport,
    ValidationResult,
    ValidationVerdict,
)


class TestValidationVerdict:
    def test_enum_values(self):
        assert ValidationVerdict.PASS.value == "pass"
        assert ValidationVerdict.FAIL.value == "fail"
        assert ValidationVerdict.ERROR.value == "error"
        assert ValidationVerdict.SKIPPED.value == "skipped"


class TestControlType:
    def test_enum_values(self):
        assert ControlType.NETWORK_POLICY.value == "network-policy"
        assert ControlType.ADMISSION.value == "admission"
        assert ControlType.RBAC.value == "rbac"


class TestValidationResult:
    def test_basic_creation(self):
        r = ValidationResult(
            control_type=ControlType.ADMISSION,
            control_name="privileged-container",
            test_description="Privileged container should be rejected",
            expected="REJECT",
            actual="REJECTED",
            verdict=ValidationVerdict.PASS,
            evidence="HTTP 403: Forbidden",
        )
        assert r.verdict == ValidationVerdict.PASS
        assert r.control_name == "privileged-container"
        assert r.evidence == "HTTP 403: Forbidden"

    def test_frozen_dataclass(self):
        r = ValidationResult(
            control_type=ControlType.RBAC,
            control_name="test",
            test_description="test",
            expected="DENY",
            actual="DENIED",
            verdict=ValidationVerdict.PASS,
        )
        # Frozen dataclass should raise on mutation
        try:
            r.verdict = ValidationVerdict.FAIL  # type: ignore[misc]
            raise AssertionError("Should have raised")
        except AttributeError:
            pass


class TestValidationReport:
    def _make_report(self) -> ValidationReport:
        return ValidationReport(
            namespace="demo",
            control_type=ControlType.ADMISSION,
            results=[
                ValidationResult(
                    control_type=ControlType.ADMISSION,
                    control_name="privileged",
                    test_description="Block privileged",
                    expected="REJECT",
                    actual="REJECTED",
                    verdict=ValidationVerdict.PASS,
                ),
                ValidationResult(
                    control_type=ControlType.ADMISSION,
                    control_name="host-pid",
                    test_description="Block hostPID",
                    expected="REJECT",
                    actual="ADMITTED",
                    verdict=ValidationVerdict.FAIL,
                    remediation_hint="Add hostPID policy",
                ),
                ValidationResult(
                    control_type=ControlType.ADMISSION,
                    control_name="error-case",
                    test_description="Error test",
                    expected="REJECT",
                    actual="ERROR",
                    verdict=ValidationVerdict.ERROR,
                ),
            ],
            summary="Test summary",
        )

    def test_counters(self):
        report = self._make_report()
        assert report.passed == 1
        assert report.failed == 1
        assert report.errors == 1
        assert report.total == 3
        assert report.all_passed is False

    def test_all_passed(self):
        report = ValidationReport(
            namespace="demo",
            control_type=ControlType.RBAC,
            results=[
                ValidationResult(
                    control_type=ControlType.RBAC,
                    control_name="test",
                    test_description="test",
                    expected="DENY",
                    actual="DENIED",
                    verdict=ValidationVerdict.PASS,
                ),
            ],
        )
        assert report.all_passed is True

    def test_empty_report(self):
        report = ValidationReport(namespace="demo", control_type=ControlType.RBAC)
        assert report.total == 0
        assert report.all_passed is False  # Empty report is not "all passed"

    def test_to_dict(self):
        report = self._make_report()
        d = report.to_dict()
        assert d["namespace"] == "demo"
        assert d["total"] == 3
        assert d["passed"] == 1
        assert d["failed"] == 1
        assert d["errors"] == 1
        assert d["all_passed"] is False
        assert len(d["results"]) == 3
        assert d["results"][0]["verdict"] == "pass"
        assert d["results"][1]["remediation_hint"] == "Add hostPID policy"
