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

"""Tests for the revert mechanism and rollback verification."""

from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from kimera.container.core.journal import pending_operations, record_operation
from kimera.container.core.k8s_client import K8sClient
from kimera.container.core.logger import SecurityLogger
from kimera.container.make_vulnerable.missing_network_policies import (
    TOOLKIT_LABEL,
    TOOLKIT_LABEL_VALUE,
    MissingNetworkPoliciesExploit,
)
from kimera.container.make_vulnerable.privileged_containers import PrivilegedContainersExploit


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


class TestDeploymentRevert:
    """Test revert on deployment-based exploits."""

    def test_revert_calls_rollback(self, tmp_path: Path) -> None:
        """Test that revert calls rollback_deployment."""
        k8s, logger = _create_mock_k8s_client()
        k8s.rollback_deployment = MagicMock(return_value=True)  # type: ignore[method-assign]

        exploit = PrivilegedContainersExploit(k8s, "test-svc", logger)
        # Stub check_vulnerability to return False (no longer vulnerable)
        exploit.check_vulnerability = MagicMock(return_value=False)  # type: ignore[method-assign]

        with _patch_journal(tmp_path):
            result = exploit.revert()

        assert result is True
        k8s.rollback_deployment.assert_called_once_with("test-svc")

    def test_revert_verifies_vulnerability_removed(self, tmp_path: Path) -> None:
        """Test that revert checks vulnerability after rollback."""
        k8s, logger = _create_mock_k8s_client()
        k8s.rollback_deployment = MagicMock(return_value=True)  # type: ignore[method-assign]

        exploit = PrivilegedContainersExploit(k8s, "test-svc", logger)
        exploit.check_vulnerability = MagicMock(return_value=False)  # type: ignore[method-assign]

        with _patch_journal(tmp_path):
            exploit.revert()

        exploit.check_vulnerability.assert_called_once()

    def test_revert_warns_if_still_vulnerable(self, tmp_path: Path) -> None:
        """Test that revert warns if vulnerability persists after rollback."""
        k8s, logger = _create_mock_k8s_client()
        k8s.rollback_deployment = MagicMock(return_value=True)  # type: ignore[method-assign]

        exploit = PrivilegedContainersExploit(k8s, "test-svc", logger)
        exploit.check_vulnerability = MagicMock(return_value=True)  # type: ignore[method-assign]

        with _patch_journal(tmp_path):
            result = exploit.revert()

        assert result is True
        logger.warning.assert_called()

    def test_revert_dry_run(self, tmp_path: Path) -> None:
        """Test that dry-run does not call rollback."""
        k8s, logger = _create_mock_k8s_client()
        k8s.rollback_deployment = MagicMock()  # type: ignore[method-assign]

        exploit = PrivilegedContainersExploit(k8s, "test-svc", logger)

        with _patch_journal(tmp_path):
            result = exploit.revert(dry_run=True)

        assert result is True
        k8s.rollback_deployment.assert_not_called()

    def test_revert_clears_journal(self, tmp_path: Path) -> None:
        """Test that successful revert clears the journal entry."""
        k8s, logger = _create_mock_k8s_client()
        k8s.rollback_deployment = MagicMock(return_value=True)  # type: ignore[method-assign]

        exploit = PrivilegedContainersExploit(k8s, "test-svc", logger)
        exploit.check_vulnerability = MagicMock(return_value=False)  # type: ignore[method-assign]

        with _patch_journal(tmp_path):
            record_operation("make_vulnerable", "privileged-containers", "test-svc", "test-ns")
            exploit.revert()
            ops = pending_operations()

        assert len(ops) == 0


class TestNetworkPolicyRevert:
    """Test revert on network policy exploit."""

    def test_revert_removes_toolkit_policies(self, tmp_path: Path) -> None:
        """Test that revert removes toolkit-managed network policies."""
        k8s, logger = _create_mock_k8s_client()

        toolkit_policy = Mock()
        toolkit_policy.metadata.name = "default-deny-all"
        toolkit_policy.metadata.labels = {TOOLKIT_LABEL: TOOLKIT_LABEL_VALUE}

        mock_result = Mock()
        mock_result.items = [toolkit_policy]
        k8s.networking_v1.list_namespaced_network_policy.return_value = mock_result

        exploit = MissingNetworkPoliciesExploit(k8s, "test-svc", logger)

        with _patch_journal(tmp_path):
            result = exploit.revert()

        assert result is True
        k8s.networking_v1.delete_namespaced_network_policy.assert_called_once()

    def test_revert_clears_journal(self, tmp_path: Path) -> None:
        """Test that revert clears journal for network policy exploit."""
        k8s, logger = _create_mock_k8s_client()

        mock_result = Mock()
        mock_result.items = []
        k8s.networking_v1.list_namespaced_network_policy.return_value = mock_result

        exploit = MissingNetworkPoliciesExploit(k8s, "test-svc", logger)

        with _patch_journal(tmp_path):
            record_operation("make_secure", "missing-network-policies", "test-svc", "test-ns")
            exploit.revert()
            ops = pending_operations()

        assert len(ops) == 0


class TestJournalIntegration:
    """Test that make_vulnerable and make_secure record operations."""

    def test_make_vulnerable_records_operation(self, tmp_path: Path) -> None:
        """Test that make_vulnerable writes to the journal."""
        k8s, logger = _create_mock_k8s_client()
        k8s.patch_deployment = MagicMock(return_value=True)  # type: ignore[method-assign]

        exploit = PrivilegedContainersExploit(k8s, "test-svc", logger)

        with _patch_journal(tmp_path):
            exploit.make_vulnerable()
            ops = pending_operations()

        assert len(ops) == 1
        assert ops[0]["action"] == "make_vulnerable"
        assert ops[0]["exploit_type"] == "privileged-containers"

    def test_make_secure_records_operation(self, tmp_path: Path) -> None:
        """Test that make_secure writes to the journal."""
        k8s, logger = _create_mock_k8s_client()
        k8s.patch_deployment = MagicMock(return_value=True)  # type: ignore[method-assign]
        k8s.get_deployment = MagicMock(return_value=None)  # type: ignore[method-assign]

        exploit = PrivilegedContainersExploit(k8s, "test-svc", logger)

        with _patch_journal(tmp_path):
            exploit.make_secure()
            ops = pending_operations()

        assert len(ops) == 1
        assert ops[0]["action"] == "make_secure"

    def test_dry_run_does_not_record(self, tmp_path: Path) -> None:
        """Test that dry-run operations are not recorded."""
        k8s, logger = _create_mock_k8s_client()
        k8s.patch_deployment = MagicMock(return_value=True)  # type: ignore[method-assign]

        exploit = PrivilegedContainersExploit(k8s, "test-svc", logger)

        with _patch_journal(tmp_path):
            exploit.make_vulnerable(dry_run=True)
            ops = pending_operations()

        assert len(ops) == 0
