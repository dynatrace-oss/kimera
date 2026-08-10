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


from unittest.mock import MagicMock, patch

from kimera.mcp.server import (
    attempt_technique,
    get_remediation,
    list_techniques,
    reload_techniques,
)


class TestListTechniques:
    def test_returns_all_techniques_with_summary(self) -> None:
        """MCP contract: result has 'techniques' list and 'summary' string."""
        result = list_techniques()
        assert "techniques" in result
        assert "summary" in result
        assert isinstance(result["techniques"], list)
        assert len(result["techniques"]) >= 5

    def test_phase_filter_narrows_results(self) -> None:
        all_result = list_techniques()
        cred_result = list_techniques(phase="credential-access")
        assert len(cred_result["techniques"]) < len(all_result["techniques"])
        assert all(t["phase"] == "credential-access" for t in cred_result["techniques"])

    def test_empty_phase_returns_zero_not_crash(self) -> None:
        result = list_techniques(phase="nonexistent-phase")
        assert result["total"] == 0
        assert "summary" in result


class TestGetRemediation:
    def test_known_check_returns_remediation(self) -> None:
        result = get_remediation(check_id="privileged_mode")
        assert result["check_id"] == "privileged_mode"
        assert result["severity"] == "critical"
        assert "privileged" in result["remediation"].lower()
        assert result["mitre_id"] == "T1611"
        assert "summary" in result

    def test_unknown_check_returns_structured_error(self) -> None:
        result = get_remediation(check_id="nonexistent_check")
        assert "error" in result
        assert "summary" in result


class TestReloadTechniques:
    def test_returns_count_and_summary(self) -> None:
        result = reload_techniques()
        assert "current_count" in result
        assert "summary" in result
        assert result["current_count"] >= 5
        assert isinstance(result["techniques"], list)


class TestAttemptTechniqueDryRun:
    """The MCP server previously executed for real and labelled the result a dry run."""

    @patch("kimera.mcp.server._get_k8s")
    def test_dry_run_default_does_not_touch_the_cluster(self, get_k8s: MagicMock) -> None:
        k8s = MagicMock()
        k8s.namespace = "demo"
        get_k8s.return_value = k8s

        result = attempt_technique("L1", "demo", target_pod="p", params={"probe_host": "svc"})

        k8s.exec_in_pod.assert_not_called()
        assert result["dry_run"] is True

    @patch("kimera.mcp.server._get_k8s")
    def test_dry_run_false_executes(self, get_k8s: MagicMock) -> None:
        k8s = MagicMock()
        k8s.namespace = "demo"
        k8s.exec_in_pod.return_value = "OPEN"
        get_k8s.return_value = k8s

        result = attempt_technique(
            "L1", "demo", target_pod="p", params={"probe_host": "svc"}, dry_run=False
        )

        k8s.exec_in_pod.assert_called_once()
        assert result["dry_run"] is False
