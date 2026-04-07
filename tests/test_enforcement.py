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

from unittest.mock import MagicMock, Mock, patch

import pytest
from kubernetes.client.rest import ApiException

from kimera.container.core.exceptions import K8sError
from kimera.container.core.k8s_client import K8sClient
from kimera.container.core.logger import SecurityLogger
from kimera.container.infrastructure.enforcement import (
    CILIUM_DAEMONSET,
    CILIUM_NAMESPACE,
    PolicyEnforcementManager,
)


def _create_mock_k8s_client() -> tuple[K8sClient, MagicMock, MagicMock, MagicMock, MagicMock]:
    """Create a mock K8sClient with all API clients."""
    with (
        patch("kimera.container.core.k8s_client.config") as mock_config,
        patch("kimera.container.core.k8s_client.client") as mock_k8s_client,
    ):
        config_exception = type("ConfigException", (Exception,), {})
        mock_config.ConfigException = config_exception
        mock_config.load_incluster_config.side_effect = config_exception("Not in cluster")
        mock_config.load_kube_config.return_value = None

        mock_core_v1 = MagicMock()
        mock_apps_v1 = MagicMock()
        mock_networking_v1 = MagicMock()
        mock_rbac_v1 = MagicMock()

        mock_k8s_client.CoreV1Api.return_value = mock_core_v1
        mock_k8s_client.AppsV1Api.return_value = mock_apps_v1
        mock_k8s_client.NetworkingV1Api.return_value = mock_networking_v1
        mock_k8s_client.RbacAuthorizationV1Api.return_value = mock_rbac_v1

        mock_logger = MagicMock(spec=SecurityLogger)
        k8s = K8sClient(namespace="test-ns", logger=mock_logger)

    return k8s, mock_apps_v1, mock_core_v1, mock_rbac_v1, mock_logger


# --- K8sClient DaemonSet method tests ---


class TestK8sClientDaemonSetMethods:
    """Test K8sClient DaemonSet CRUD methods."""

    def setup_method(self):
        self.k8s, self.mock_apps, self.mock_core, self.mock_rbac, self.mock_logger = (
            _create_mock_k8s_client()
        )

    def test_get_daemonset_success(self):
        mock_ds = Mock()
        self.mock_apps.read_namespaced_daemon_set.return_value = mock_ds

        result = self.k8s.get_daemonset("test-ds", "kube-system")
        assert result is mock_ds

    def test_get_daemonset_not_found(self):
        self.mock_apps.read_namespaced_daemon_set.side_effect = ApiException(
            status=404, reason="Not Found"
        )
        assert self.k8s.get_daemonset("missing") is None

    def test_get_daemonset_api_error(self):
        self.mock_apps.read_namespaced_daemon_set.side_effect = ApiException(
            status=500, reason="Server Error"
        )
        with pytest.raises(K8sError, match="Failed to get DaemonSet"):
            self.k8s.get_daemonset("broken")

    def test_create_daemonset_success(self):
        body = {"metadata": {"name": "test-ds"}}
        assert self.k8s.create_daemonset(body, "kube-system") is True
        self.mock_apps.create_namespaced_daemon_set.assert_called_once()

    def test_create_daemonset_dry_run(self):
        body = {"metadata": {"name": "test-ds"}}
        assert self.k8s.create_daemonset(body, "kube-system", dry_run=True) is True
        self.mock_apps.create_namespaced_daemon_set.assert_not_called()

    def test_create_daemonset_conflict(self):
        self.mock_apps.create_namespaced_daemon_set.side_effect = ApiException(
            status=409, reason="Conflict"
        )
        body = {"metadata": {"name": "existing"}}
        assert self.k8s.create_daemonset(body) is True

    def test_create_daemonset_api_error(self):
        self.mock_apps.create_namespaced_daemon_set.side_effect = ApiException(
            status=500, reason="Server Error"
        )
        body = {"metadata": {"name": "bad"}}
        assert self.k8s.create_daemonset(body) is False

    def test_delete_daemonset_success(self):
        assert self.k8s.delete_daemonset("test-ds", "kube-system") is True
        self.mock_apps.delete_namespaced_daemon_set.assert_called_once()

    def test_delete_daemonset_not_found(self):
        self.mock_apps.delete_namespaced_daemon_set.side_effect = ApiException(
            status=404, reason="Not Found"
        )
        assert self.k8s.delete_daemonset("missing") is True

    def test_delete_daemonset_api_error(self):
        self.mock_apps.delete_namespaced_daemon_set.side_effect = ApiException(
            status=500, reason="Server Error"
        )
        assert self.k8s.delete_daemonset("broken") is False

    def test_daemonset_exists_true(self):
        assert self.k8s.daemonset_exists("test-ds", "kube-system") is True

    def test_daemonset_exists_false(self):
        self.mock_apps.read_namespaced_daemon_set.side_effect = ApiException(
            status=404, reason="Not Found"
        )
        assert self.k8s.daemonset_exists("missing") is False

    def test_daemonset_exists_api_error(self):
        self.mock_apps.read_namespaced_daemon_set.side_effect = ApiException(
            status=500, reason="Server Error"
        )
        with pytest.raises(K8sError, match="Failed to check DaemonSet"):
            self.k8s.daemonset_exists("broken")


class TestK8sClientRBACMethods:
    """Test K8sClient RBAC and ServiceAccount methods."""

    def setup_method(self):
        self.k8s, self.mock_apps, self.mock_core, self.mock_rbac, self.mock_logger = (
            _create_mock_k8s_client()
        )

    def test_create_service_account_success(self):
        body = {"metadata": {"name": "test-sa"}}
        assert self.k8s.create_service_account(body, "kube-system") is True

    def test_create_service_account_conflict(self):
        self.mock_core.create_namespaced_service_account.side_effect = ApiException(
            status=409, reason="Conflict"
        )
        body = {"metadata": {"name": "existing"}}
        assert self.k8s.create_service_account(body) is True

    def test_delete_service_account_not_found(self):
        self.mock_core.delete_namespaced_service_account.side_effect = ApiException(
            status=404, reason="Not Found"
        )
        assert self.k8s.delete_service_account("missing") is True

    def test_create_cluster_role_success(self):
        body = {"metadata": {"name": "test-cr"}}
        assert self.k8s.create_cluster_role(body) is True
        self.mock_rbac.create_cluster_role.assert_called_once()

    def test_create_cluster_role_conflict(self):
        self.mock_rbac.create_cluster_role.side_effect = ApiException(status=409, reason="Conflict")
        body = {"metadata": {"name": "existing"}}
        assert self.k8s.create_cluster_role(body) is True

    def test_delete_cluster_role_success(self):
        assert self.k8s.delete_cluster_role("test-cr") is True

    def test_delete_cluster_role_not_found(self):
        self.mock_rbac.delete_cluster_role.side_effect = ApiException(
            status=404, reason="Not Found"
        )
        assert self.k8s.delete_cluster_role("missing") is True

    def test_create_cluster_role_binding_success(self):
        body = {"metadata": {"name": "test-crb"}}
        assert self.k8s.create_cluster_role_binding(body) is True

    def test_delete_cluster_role_binding_not_found(self):
        self.mock_rbac.delete_cluster_role_binding.side_effect = ApiException(
            status=404, reason="Not Found"
        )
        assert self.k8s.delete_cluster_role_binding("missing") is True

    def test_k8s_client_has_rbac_v1(self):
        assert hasattr(self.k8s, "rbac_v1")
        assert self.k8s.rbac_v1 is self.mock_rbac


# --- PolicyEnforcementManager tests ---


class TestEnforcementEnable:
    """Test PolicyEnforcementManager enable — Cilium detection and guidance."""

    def setup_method(self):
        self.k8s, self.mock_apps, self.mock_core, self.mock_rbac, self.mock_logger = (
            _create_mock_k8s_client()
        )
        self.manager = PolicyEnforcementManager(self.k8s, self.mock_logger)

    def test_enable_returns_true_when_cilium_running(self):
        mock_ds = Mock()
        mock_ds.status.desired_number_scheduled = 2
        mock_ds.status.number_ready = 2
        self.mock_apps.read_namespaced_daemon_set.return_value = mock_ds

        assert self.manager.enable() is True

    def test_enable_returns_false_and_prints_guidance_when_cilium_missing(self):
        self.mock_apps.read_namespaced_daemon_set.side_effect = ApiException(
            status=404, reason="Not Found"
        )
        assert self.manager.enable() is False

    def test_enable_dry_run_returns_true(self):
        assert self.manager.enable(dry_run=True) is True
        self.mock_apps.read_namespaced_daemon_set.assert_not_called()

    def test_enable_checks_cilium_daemonset_in_kube_system(self):
        mock_ds = Mock()
        mock_ds.status.desired_number_scheduled = 1
        mock_ds.status.number_ready = 1
        self.mock_apps.read_namespaced_daemon_set.return_value = mock_ds

        self.manager.enable()
        self.mock_apps.read_namespaced_daemon_set.assert_called_with(
            CILIUM_DAEMONSET, CILIUM_NAMESPACE
        )


class TestEnforcementDisable:
    """Test PolicyEnforcementManager disable — guidance only."""

    def setup_method(self):
        self.k8s, self.mock_apps, self.mock_core, self.mock_rbac, self.mock_logger = (
            _create_mock_k8s_client()
        )
        self.manager = PolicyEnforcementManager(self.k8s, self.mock_logger)

    def test_disable_makes_no_cluster_changes(self):
        self.manager.disable()
        self.mock_apps.delete_namespaced_daemon_set.assert_not_called()
        self.mock_rbac.delete_cluster_role.assert_not_called()
        self.mock_core.delete_namespaced_service_account.assert_not_called()

    def test_disable_dry_run(self):
        self.manager.disable(dry_run=True)
        self.mock_logger.info.assert_called()


class TestEnforcementStatus:
    """Test PolicyEnforcementManager status checks."""

    def setup_method(self):
        self.k8s, self.mock_apps, self.mock_core, self.mock_rbac, self.mock_logger = (
            _create_mock_k8s_client()
        )
        self.manager = PolicyEnforcementManager(self.k8s, self.mock_logger)

    def test_is_enabled_true(self):
        mock_ds = Mock()
        mock_ds.status.desired_number_scheduled = 3
        mock_ds.status.number_ready = 3
        self.mock_apps.read_namespaced_daemon_set.return_value = mock_ds

        assert self.manager.is_enabled() is True

    def test_is_enabled_false_no_daemonset(self):
        self.mock_apps.read_namespaced_daemon_set.side_effect = ApiException(
            status=404, reason="Not Found"
        )
        assert self.manager.is_enabled() is False

    def test_is_enabled_false_not_ready(self):
        mock_ds = Mock()
        mock_ds.status.desired_number_scheduled = 3
        mock_ds.status.number_ready = 1
        self.mock_apps.read_namespaced_daemon_set.return_value = mock_ds

        assert self.manager.is_enabled() is False

    def test_get_status_installed(self):
        mock_ds = Mock()
        mock_ds.status.desired_number_scheduled = 3
        mock_ds.status.number_ready = 3
        mock_ds.status.number_available = 3
        mock_ds.spec.template.spec.containers = [Mock(image="quay.io/cilium/cilium:v1.16.5")]
        self.mock_apps.read_namespaced_daemon_set.return_value = mock_ds

        status = self.manager.get_status()
        assert status["installed"] is True
        assert status["desired"] == 3
        assert status["ready"] == 3
        assert "cilium" in status["image"]

    def test_get_status_not_installed(self):
        self.mock_apps.read_namespaced_daemon_set.side_effect = ApiException(
            status=404, reason="Not Found"
        )

        status = self.manager.get_status()
        assert status["installed"] is False
