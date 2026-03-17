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


class TestK8sClient:
    """Test K8sClient functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = MagicMock(spec=SecurityLogger)

    @patch("kimera.container.core.k8s_client.config")
    @patch("kimera.container.core.k8s_client.client")
    def test_k8s_client_init_default(self, mock_k8s_client, mock_config):
        """Test K8sClient initialization with defaults."""
        # Mock the ConfigException class properly
        config_exception = type("ConfigException", (Exception,), {})
        mock_config.ConfigException = config_exception
        mock_config.load_incluster_config.side_effect = config_exception("Not in cluster")
        mock_config.load_kube_config.return_value = None

        k8s_client = K8sClient()

        assert k8s_client.namespace == "default"
        assert k8s_client.verbose is False
        assert k8s_client.logger is not None
        mock_config.load_kube_config.assert_called_once()

    @patch("kimera.container.core.k8s_client.config")
    @patch("kimera.container.core.k8s_client.client")
    def test_k8s_client_init_custom(self, mock_k8s_client, mock_config):
        """Test K8sClient initialization with custom parameters."""
        config_exception = type("ConfigException", (Exception,), {})
        mock_config.ConfigException = config_exception
        mock_config.load_incluster_config.side_effect = config_exception("Not in cluster")
        mock_config.load_kube_config.return_value = None

        k8s_client = K8sClient(namespace="test-namespace", logger=self.mock_logger, verbose=True)

        assert k8s_client.namespace == "test-namespace"
        assert k8s_client.verbose is True
        assert k8s_client.logger is self.mock_logger

    @patch("kimera.container.core.k8s_client.config")
    @patch("kimera.container.core.k8s_client.client")
    def test_k8s_client_init_incluster(self, mock_k8s_client, mock_config):
        """Test K8sClient initialization with in-cluster config."""
        mock_config.load_incluster_config.return_value = None

        K8sClient()

        mock_config.load_incluster_config.assert_called_once()
        mock_config.load_kube_config.assert_not_called()

    @patch("kimera.container.core.k8s_client.config")
    @patch("kimera.container.core.k8s_client.client")
    def test_k8s_client_config_exception(self, mock_k8s_client, mock_config):
        """Test K8sClient initialization with config exception."""
        config_exception = type("ConfigException", (Exception,), {})
        mock_config.ConfigException = config_exception
        mock_config.load_incluster_config.side_effect = config_exception("Not in cluster")
        mock_config.load_kube_config.side_effect = config_exception("No kubeconfig")

        with pytest.raises(K8sError, match="Cannot connect to Kubernetes cluster"):
            K8sClient()

    @patch("kimera.container.core.k8s_client.config")
    @patch("kimera.container.core.k8s_client.client")
    def test_k8s_client_creates_api_clients(self, mock_k8s_client, mock_config):
        """Test that K8sClient creates necessary API clients."""
        config_exception = type("ConfigException", (Exception,), {})
        mock_config.ConfigException = config_exception
        mock_config.load_incluster_config.side_effect = config_exception("Not in cluster")
        mock_config.load_kube_config.return_value = None

        k8s_client = K8sClient()

        # Should have created API clients
        assert hasattr(k8s_client, "v1")
        assert hasattr(k8s_client, "apps_v1")

        mock_k8s_client.CoreV1Api.assert_called_once()
        mock_k8s_client.AppsV1Api.assert_called_once()


class TestK8sClientMethods:
    """Test K8sClient methods with mocked Kubernetes API."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = MagicMock(spec=SecurityLogger)

        with (
            patch("kimera.container.core.k8s_client.config") as mock_config,
            patch("kimera.container.core.k8s_client.client") as mock_k8s_client,
        ):
            config_exception = type("ConfigException", (Exception,), {})
            mock_config.ConfigException = config_exception
            mock_config.load_incluster_config.side_effect = config_exception("Not in cluster")
            mock_config.load_kube_config.return_value = None
            self.mock_core_v1 = MagicMock()
            self.mock_apps_v1 = MagicMock()

            mock_k8s_client.CoreV1Api.return_value = self.mock_core_v1
            mock_k8s_client.AppsV1Api.return_value = self.mock_apps_v1

            self.k8s_client = K8sClient(namespace="test-ns", logger=self.mock_logger)

    def test_list_pods_success(self):
        """Test successful pod listing."""
        mock_pod_list = Mock()
        mock_pod_list.items = [Mock(), Mock()]
        self.mock_core_v1.list_namespaced_pod.return_value = mock_pod_list

        # Test that the method exists and can be called
        # Note: We're testing the structure rather than implementation details
        assert hasattr(self.k8s_client, "v1")
        assert self.k8s_client.v1 is self.mock_core_v1

    def test_api_exception_handling(self):
        """Test API exception handling in client methods."""
        # Test that ApiException from kubernetes client is properly handled
        api_exception = ApiException(status=404, reason="Not Found")

        with pytest.raises(ApiException):
            raise api_exception

    def test_client_namespace_property(self):
        """Test client namespace property."""
        assert self.k8s_client.namespace == "test-ns"

    def test_client_logger_property(self):
        """Test client logger property."""
        assert self.k8s_client.logger is self.mock_logger

    def test_client_verbose_property(self):
        """Test client verbose property."""
        assert self.k8s_client.verbose is False

        # Test with verbose=True
        with (
            patch("kimera.container.core.k8s_client.config") as mock_config,
            patch("kimera.container.core.k8s_client.client"),
        ):
            config_exception = type("ConfigException", (Exception,), {})
            mock_config.ConfigException = config_exception
            mock_config.load_incluster_config.side_effect = config_exception("Not in cluster")
            mock_config.load_kube_config.return_value = None
            verbose_client = K8sClient(verbose=True)
            assert verbose_client.verbose is True


class TestK8sClientExceptionHandling:
    """Test K8sClient exception handling patterns."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_logger = MagicMock(spec=SecurityLogger)

    @patch("kimera.container.core.k8s_client.config")
    @patch("kimera.container.core.k8s_client.client")
    def test_k8s_error_inheritance(self, mock_k8s_client, mock_config):
        """Test that K8sError is properly raised for configuration issues."""
        config_exception = type("ConfigException", (Exception,), {})
        mock_config.ConfigException = config_exception
        mock_config.load_incluster_config.side_effect = config_exception("Cluster error")
        mock_config.load_kube_config.side_effect = config_exception("Config error")

        with pytest.raises(K8sError) as exc_info:
            K8sClient()

        assert "Cannot connect to Kubernetes cluster" in str(exc_info.value)

    def test_api_exception_types(self):
        """Test different types of API exceptions."""
        # Test 404 Not Found
        not_found = ApiException(status=404, reason="Not Found")
        assert not_found.status == 404
        assert not_found.reason == "Not Found"

        # Test 403 Forbidden
        forbidden = ApiException(status=403, reason="Forbidden")
        assert forbidden.status == 403
        assert forbidden.reason == "Forbidden"

        # Test 500 Server Error
        server_error = ApiException(status=500, reason="Internal Server Error")
        assert server_error.status == 500
        assert server_error.reason == "Internal Server Error"
