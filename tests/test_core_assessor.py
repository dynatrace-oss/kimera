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
    """Minimal check config covering all three check types."""
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


# -- Condition evaluator: core logic, wrong result = wrong finding severity --


@pytest.mark.parametrize(
    "value,condition,match_values,expected",
    [
        # equals_true
        (True, "equals_true", None, True),
        (False, "equals_true", None, False),
        (None, "equals_true", None, False),  # null must not fire
        # not_false (used for allowPrivilegeEscalation)
        (None, "not_false", None, True),  # unset should fire
        (True, "not_false", None, True),
        (False, "not_false", None, False),
        # missing
        (None, "missing", None, True),
        ("value", "missing", None, False),
        # contains_any (capability matching)
        (["SYS_ADMIN", "CHOWN"], "contains_any", ["SYS_ADMIN", "NET_ADMIN"], True),
        (["CHOWN"], "contains_any", ["SYS_ADMIN", "NET_ADMIN"], False),
        (None, "contains_any", ["SYS_ADMIN"], False),  # null list
        ([], "contains_any", ["SYS_ADMIN"], False),  # empty list
        # count_zero (namespace-level checks)
        (0, "count_zero", None, True),
        (None, "count_zero", None, True),
        (5, "count_zero", None, False),
    ],
)
def test_evaluate_condition(
    value: object,
    condition: str,
    match_values: list[str] | None,
    expected: bool,
) -> None:
    check: dict = {}
    if match_values:
        check["match_values"] = match_values
    assert _evaluate_condition(value, condition, check) is expected


# -- Config loading: error paths and real config integration --


def test_missing_config_file_returns_empty(tmp_path: Path) -> None:
    """Missing config must not crash — returns empty list."""
    assert _load_checks(tmp_path / "nonexistent.yaml") == []


def test_real_workload_config_loads() -> None:
    """Integration: config/checks/workload.yaml loads with expected checks.

    Catches accidentally deleted checks or broken YAML syntax.
    """
    checks = _load_checks()
    ids = {c["id"] for c in checks}
    assert len(checks) >= 10, f"Expected >=10 checks, got {len(checks)}"
    assert "privileged_mode" in ids
    assert "host_pid" in ids
    assert "missing_resource_limits" in ids


# -- Deployment assessment: one test per check TYPE (each hits different code path) --


class TestAssessDeployment:
    def test_container_field_check_fires_and_maps_mitre(self, sample_checks: Path) -> None:
        """container_field: privileged=True produces CRITICAL finding with T1611."""
        checks = _load_checks(sample_checks)
        findings = assess_deployment(_make_deployment(privileged=True), checks)

        priv = [f for f in findings if f.check_id == "privileged_mode"]
        assert len(priv) == 1
        assert priv[0].severity == Severity.CRITICAL
        assert priv[0].technique.mitre_id == "T1611"
        # Target format: "deployment_name/container_name"
        assert "test-deploy" in priv[0].target
        assert "app" in priv[0].target

    def test_container_field_check_does_not_fire_when_secure(self, sample_checks: Path) -> None:
        """Negative case: privileged=False must not produce privileged finding."""
        checks = _load_checks(sample_checks)
        findings = assess_deployment(_make_deployment(privileged=False), checks)
        assert not [f for f in findings if f.check_id == "privileged_mode"]

    def test_resource_check_fires_when_limits_missing(self, sample_checks: Path) -> None:
        """resource_check: different code path from container_field."""
        checks = _load_checks(sample_checks)
        findings = assess_deployment(_make_deployment(has_limits=False), checks)

        limits = [f for f in findings if f.check_id == "missing_resource_limits"]
        assert len(limits) == 1
        assert limits[0].severity == Severity.HIGH

    def test_pod_field_check_fires_for_host_pid(self, sample_checks: Path) -> None:
        """pod_field: evaluated on pod spec, not per-container."""
        checks = _load_checks(sample_checks)
        findings = assess_deployment(_make_deployment(host_pid=True), checks)

        pid = [f for f in findings if f.check_id == "host_pid"]
        assert len(pid) == 1
        assert pid[0].technique.cis_controls == ["5.2.2"]

    def test_multiple_issues_coexist(self, sample_checks: Path) -> None:
        """All check types fire independently — catches early-return bugs."""
        checks = _load_checks(sample_checks)
        findings = assess_deployment(
            _make_deployment(privileged=True, has_limits=False, host_pid=True),
            checks,
        )
        check_ids = {f.check_id for f in findings}
        assert check_ids == {"privileged_mode", "missing_resource_limits", "host_pid"}
