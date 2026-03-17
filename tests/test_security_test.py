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

"""Tests for SecurityTest, EvidenceMarker, and BaseExploit._run_tests()."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from kimera.container.core.k8s_client import K8sClient
from kimera.container.core.logger import SecurityLogger
from kimera.container.make_vulnerable.privileged_containers import (
    PrivilegedContainersExploit,
)
from kimera.container.make_vulnerable.test_loader import load_exploit_tests
from kimera.domain.models import EvidenceMarker, SecurityTest


def _create_mock_k8s_client() -> tuple[K8sClient, MagicMock]:
    """Create a mock K8sClient."""
    with (
        patch("kimera.container.core.k8s_client.config") as mock_config,
        patch("kimera.container.core.k8s_client.client") as mock_k8s_client,
    ):
        config_exception = type("ConfigException", (Exception,), {})
        mock_config.ConfigException = config_exception
        mock_config.load_incluster_config.side_effect = config_exception("Not in cluster")
        mock_config.load_kube_config.return_value = None

        mock_k8s_client.CoreV1Api.return_value = MagicMock()
        mock_k8s_client.AppsV1Api.return_value = MagicMock()
        mock_k8s_client.NetworkingV1Api.return_value = MagicMock()

        mock_logger = MagicMock(spec=SecurityLogger)
        k8s = K8sClient(namespace="test-ns", logger=mock_logger)

    return k8s, mock_logger


def _patch_journal(tmp_path: Path):  # type: ignore[no-untyped-def]
    """Redirect journal state file to tmp_path."""
    return patch(
        "kimera.container.core.journal._state_path",
        return_value=tmp_path / ".kimera-state.json",
    )


class TestEvidenceMarker:
    """Tests for the EvidenceMarker dataclass."""

    def test_marker_with_impact(self):
        """Test marker with all fields."""
        m = EvidenceMarker("VULNERABLE", "Found vulnerability", "Can escape container")
        assert m.marker == "VULNERABLE"
        assert m.evidence == "Found vulnerability"
        assert m.impact == "Can escape container"

    def test_marker_without_impact(self):
        """Test marker with default empty impact."""
        m = EvidenceMarker("WARNING", "Found warning")
        assert m.impact == ""


class TestSecurityTest:
    """Tests for the SecurityTest dataclass."""

    def test_creates_test_with_markers(self):
        """Test creating a SecurityTest with evidence markers."""
        test = SecurityTest(
            name="Check privilege",
            script="echo test",
            evidence_markers=[
                EvidenceMarker("VULNERABLE", "Is vulnerable"),
            ],
        )
        assert test.name == "Check privilege"
        assert test.script == "echo test"
        assert len(test.evidence_markers) == 1

    def test_default_empty_markers(self):
        """Test that markers default to empty list."""
        test = SecurityTest(name="Basic", script="echo ok")
        assert test.evidence_markers == []
        assert test.summary_impact == []


class TestRunTests:
    """Tests for BaseExploit._run_tests()."""

    def test_collects_evidence_from_markers(self, tmp_path: Path) -> None:
        """Test that matching markers produce evidence entries."""
        k8s, logger = _create_mock_k8s_client()
        k8s.exec_in_pod = MagicMock(return_value="❌ VULNERABLE: Can write to /sys")  # type: ignore[method-assign]

        exploit = PrivilegedContainersExploit(k8s, "test-svc", logger)

        tests = [
            SecurityTest(
                name="Priv check",
                script="echo test",
                evidence_markers=[
                    EvidenceMarker("VULNERABLE: Can write to /sys", "Writable /sys", "Host access"),
                    EvidenceMarker("NO MATCH", "Should not appear"),
                ],
            ),
        ]

        with _patch_journal(tmp_path):
            result = exploit._run_tests("test-pod", tests)

        assert result.success is True
        assert "Writable /sys" in result.evidence
        assert "Host access" in result.impact
        assert "Should not appear" not in result.evidence

    def test_no_evidence_when_no_markers_match(self, tmp_path: Path) -> None:
        """Test that result is unsuccessful when no markers match."""
        k8s, logger = _create_mock_k8s_client()
        k8s.exec_in_pod = MagicMock(return_value="✅ Protected: All good")  # type: ignore[method-assign]

        exploit = PrivilegedContainersExploit(k8s, "test-svc", logger)

        tests = [
            SecurityTest(
                name="Check",
                script="echo test",
                evidence_markers=[
                    EvidenceMarker("VULNERABLE", "Bad thing"),
                ],
            ),
        ]

        with _patch_journal(tmp_path):
            result = exploit._run_tests("test-pod", tests)

        assert result.success is False
        assert len(result.evidence) == 0

    def test_handles_exec_failure(self, tmp_path: Path) -> None:
        """Test that exec_in_pod failures are caught and logged."""
        k8s, logger = _create_mock_k8s_client()
        k8s.exec_in_pod = MagicMock(side_effect=Exception("Connection refused"))  # type: ignore[method-assign]

        exploit = PrivilegedContainersExploit(k8s, "test-svc", logger)

        tests = [
            SecurityTest(
                name="Failing test",
                script="echo test",
                evidence_markers=[EvidenceMarker("X", "Y")],
            ),
        ]

        with _patch_journal(tmp_path):
            result = exploit._run_tests("test-pod", tests)

        assert result.success is False
        logger.error.assert_called()

    def test_runs_multiple_tests(self, tmp_path: Path) -> None:
        """Test that multiple tests are run and evidence is aggregated."""
        k8s, logger = _create_mock_k8s_client()
        k8s.exec_in_pod = MagicMock(  # type: ignore[method-assign]
            side_effect=[
                "❌ VULNERABLE: Can write to /sys",
                "❌ CRITICAL: Can access host via /proc/1/root!",
            ]
        )

        exploit = PrivilegedContainersExploit(k8s, "test-svc", logger)

        tests = [
            SecurityTest(
                name="Test A",
                script="script1",
                evidence_markers=[
                    EvidenceMarker("VULNERABLE: Can write", "Evidence A"),
                ],
            ),
            SecurityTest(
                name="Test B",
                script="script2",
                evidence_markers=[
                    EvidenceMarker("Can access host", "Evidence B", "Impact B"),
                ],
            ),
        ]

        with _patch_journal(tmp_path):
            result = exploit._run_tests("test-pod", tests)

        assert len(result.evidence) == 2
        assert "Evidence A" in result.evidence
        assert "Evidence B" in result.evidence
        assert "Impact B" in result.impact

    def test_marker_without_impact_does_not_add_impact(self, tmp_path: Path) -> None:
        """Test that markers with empty impact don't add to impact list."""
        k8s, logger = _create_mock_k8s_client()
        k8s.exec_in_pod = MagicMock(return_value="Found WARNING here")  # type: ignore[method-assign]

        exploit = PrivilegedContainersExploit(k8s, "test-svc", logger)

        tests = [
            SecurityTest(
                name="No impact test",
                script="echo test",
                evidence_markers=[
                    EvidenceMarker("WARNING", "Warning found"),
                ],
            ),
        ]

        with _patch_journal(tmp_path):
            result = exploit._run_tests("test-pod", tests)

        assert "Warning found" in result.evidence
        assert len(result.impact) == 0


class TestYamlLoading:
    """Tests for loading tests from YAML exploit config files."""

    def test_loads_privileged_containers_tests(self):
        """Test that privileged-containers.yaml loads valid tests."""
        tests, summary = load_exploit_tests("privileged-containers")
        assert len(tests) == 3
        assert len(summary) > 0
        for test in tests:
            assert test.name
            assert test.script
            assert len(test.evidence_markers) > 0

    def test_loads_all_exploit_types(self):
        """Test that all 5 exploit YAML files load successfully."""
        for exploit_type in [
            "privileged-containers",
            "dangerous-capabilities",
            "host-namespace-sharing",
            "missing-resource-limits",
            "missing-network-policies",
        ]:
            tests, summary = load_exploit_tests(exploit_type)
            assert len(tests) > 0, f"No tests loaded for {exploit_type}"
            assert len(summary) > 0, f"No summary_impact for {exploit_type}"

    def test_nonexistent_exploit_returns_empty(self):
        """Test that a missing YAML file returns empty lists."""
        tests, summary = load_exploit_tests("nonexistent-exploit")
        assert tests == []
        assert summary == []

    def test_probe_types_generate_valid_scripts(self):
        """Test that structured probes produce non-empty scripts."""
        tests, _ = load_exploit_tests("privileged-containers")
        for test in tests:
            assert test.script.strip(), f"Empty script for test: {test.name}"
