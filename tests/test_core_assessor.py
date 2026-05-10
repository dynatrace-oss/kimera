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

"""Tests for config-driven assessment engine."""

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from kimera.core.assessor import (
    _evaluate_condition,
    _load_checks,
    assess_deployment,
)
from kimera.core.findings import Severity


@pytest.fixture
def sample_checks(tmp_path: Path) -> Path:
    """Create a minimal check config for testing."""
    checks = {
        "checks": [
            {
                "id": "privileged_mode",
                "type": "container_field",
                "field": "security_context.privileged",
                "condition": "equals_true",
                "severity": "critical",
                "title": "Privileged container",
                "mitre_id": "T1611",
                "mitre_name": "Escape to Host",
                "cis_controls": ["5.2.1"],
            },
            {
                "id": "missing_resource_limits",
                "type": "resource_check",
                "field": "resources.limits",
                "condition": "missing",
                "severity": "high",
                "title": "No resource limits",
                "mitre_id": "T1499",
                "mitre_name": "Endpoint DoS",
                "cis_controls": ["5.4.1"],
            },
            {
                "id": "host_pid",
                "type": "pod_field",
                "field": "host_pid",
                "condition": "equals_true",
                "severity": "critical",
                "title": "Host PID namespace shared",
                "mitre_id": "T1611",
                "mitre_name": "Escape to Host",
                "cis_controls": ["5.2.2"],
            },
        ],
    }
    config_path = tmp_path / "workload.yaml"
    config_path.write_text(yaml.dump(checks))
    return config_path


def _make_deployment(
    name: str = "test-deploy",
    privileged: bool = False,
    has_limits: bool = True,
    host_pid: bool = False,
    caps_add: list | None = None,
) -> MagicMock:
    """Build a mock V1Deployment with configurable security settings."""
    dep = MagicMock()
    dep.metadata.name = name

    container = MagicMock()
    container.name = "app"

    ctx = MagicMock()
    ctx.privileged = privileged
    ctx.allow_privilege_escalation = None
    ctx.run_as_non_root = None
    ctx.run_as_user = None
    ctx.read_only_root_filesystem = None
    ctx.seccomp_profile = None

    if caps_add:
        ctx.capabilities.add = caps_add
        ctx.capabilities.drop = None
    else:
        ctx.capabilities = None

    container.security_context = ctx

    if has_limits:
        container.resources.limits = {"cpu": "100m", "memory": "128Mi"}
    else:
        container.resources = None

    pod_spec = MagicMock()
    pod_spec.containers = [container]
    pod_spec.host_pid = host_pid
    pod_spec.host_network = False
    pod_spec.host_ipc = False
    pod_spec.automount_service_account_token = True
    pod_spec.service_account_name = "default"
    pod_spec.security_context = None

    dep.spec.template.spec = pod_spec
    return dep


class TestEvaluateCondition:
    def test_equals_true(self) -> None:
        assert _evaluate_condition(True, "equals_true", {}) is True
        assert _evaluate_condition(False, "equals_true", {}) is False
        assert _evaluate_condition(None, "equals_true", {}) is False

    def test_not_false(self) -> None:
        assert _evaluate_condition(None, "not_false", {}) is True
        assert _evaluate_condition(True, "not_false", {}) is True
        assert _evaluate_condition(False, "not_false", {}) is False

    def test_missing(self) -> None:
        assert _evaluate_condition(None, "missing", {}) is True
        assert _evaluate_condition("value", "missing", {}) is False

    def test_contains_any(self) -> None:
        check = {"match_values": ["SYS_ADMIN", "NET_ADMIN"]}
        assert _evaluate_condition(["SYS_ADMIN", "CHOWN"], "contains_any", check) is True
        assert _evaluate_condition(["CHOWN"], "contains_any", check) is False
        assert _evaluate_condition(None, "contains_any", check) is False

    def test_count_zero(self) -> None:
        assert _evaluate_condition(0, "count_zero", {}) is True
        assert _evaluate_condition(None, "count_zero", {}) is True
        assert _evaluate_condition(5, "count_zero", {}) is False


class TestLoadChecks:
    def test_loads_from_file(self, sample_checks: Path) -> None:
        checks = _load_checks(sample_checks)
        assert len(checks) == 3
        assert checks[0]["id"] == "privileged_mode"

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        checks = _load_checks(tmp_path / "nonexistent.yaml")
        assert checks == []

    def test_loads_real_config(self) -> None:
        """Verify the actual config/checks/workload.yaml loads correctly."""
        checks = _load_checks()
        assert len(checks) > 10, "Expected at least 10 checks in workload.yaml"
        ids = {c["id"] for c in checks}
        assert "privileged_mode" in ids
        assert "host_pid" in ids
        assert "missing_resource_limits" in ids


class TestAssessDeployment:
    def test_privileged_container_detected(self, sample_checks: Path) -> None:
        checks = _load_checks(sample_checks)
        dep = _make_deployment(privileged=True)
        findings = assess_deployment(dep, checks)

        privileged_findings = [f for f in findings if f.check_id == "privileged_mode"]
        assert len(privileged_findings) == 1
        assert privileged_findings[0].severity == Severity.CRITICAL
        assert privileged_findings[0].technique.mitre_id == "T1611"

    def test_secure_deployment_no_findings_for_privileged(self, sample_checks: Path) -> None:
        checks = _load_checks(sample_checks)
        dep = _make_deployment(privileged=False, has_limits=True, host_pid=False)
        findings = assess_deployment(dep, checks)

        privileged_findings = [f for f in findings if f.check_id == "privileged_mode"]
        assert len(privileged_findings) == 0

    def test_missing_limits_detected(self, sample_checks: Path) -> None:
        checks = _load_checks(sample_checks)
        dep = _make_deployment(has_limits=False)
        findings = assess_deployment(dep, checks)

        limit_findings = [f for f in findings if f.check_id == "missing_resource_limits"]
        assert len(limit_findings) == 1
        assert limit_findings[0].severity == Severity.HIGH

    def test_host_pid_detected(self, sample_checks: Path) -> None:
        checks = _load_checks(sample_checks)
        dep = _make_deployment(host_pid=True)
        findings = assess_deployment(dep, checks)

        pid_findings = [f for f in findings if f.check_id == "host_pid"]
        assert len(pid_findings) == 1
        assert pid_findings[0].technique.cis_controls == ["5.2.2"]

    def test_multiple_issues_detected(self, sample_checks: Path) -> None:
        checks = _load_checks(sample_checks)
        dep = _make_deployment(privileged=True, has_limits=False, host_pid=True)
        findings = assess_deployment(dep, checks)

        check_ids = {f.check_id for f in findings}
        assert "privileged_mode" in check_ids
        assert "missing_resource_limits" in check_ids
        assert "host_pid" in check_ids

    def test_finding_target_includes_container_name(self, sample_checks: Path) -> None:
        checks = _load_checks(sample_checks)
        dep = _make_deployment(name="frontend", privileged=True)
        findings = assess_deployment(dep, checks)

        privileged = [f for f in findings if f.check_id == "privileged_mode"][0]
        assert "frontend" in privileged.target
        assert "app" in privileged.target  # container name
