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

from kimera.container.core.k8s_client import K8sClient
from kimera.container.core.logger import SecurityLogger
from kimera.container.infrastructure.resource_applier import (
    SUPPORTED_KINDS,
    TOOLKIT_LABEL,
    TOOLKIT_LABEL_VALUE,
    ResourceApplier,
)


def _create_mock_k8s_client() -> tuple[K8sClient, MagicMock, MagicMock]:
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

        mock_k8s_client.CoreV1Api.return_value = mock_core_v1
        mock_k8s_client.AppsV1Api.return_value = mock_apps_v1
        mock_k8s_client.NetworkingV1Api.return_value = mock_networking_v1

        mock_logger = MagicMock(spec=SecurityLogger)
        k8s = K8sClient(namespace="test-ns", logger=mock_logger)

    return k8s, mock_networking_v1, mock_logger


class TestResourceApplierParsing:
    """Test YAML parsing and validation."""

    def setup_method(self):
        self.k8s, self.mock_networking, self.mock_logger = _create_mock_k8s_client()
        self.applier = ResourceApplier(self.k8s, self.mock_logger)

    def test_parse_valid_network_policy(self, tmp_path):
        yaml_content = """
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: test-policy
        spec:
          podSelector: {}
        """
        f = tmp_path / "policy.yaml"
        f.write_text(yaml_content)

        resources = self.applier._parse_yaml(f)
        assert len(resources) == 1
        assert resources[0]["kind"] == "NetworkPolicy"

    def test_parse_multi_document_yaml(self, tmp_path):
        yaml_content = (
            "apiVersion: networking.k8s.io/v1\n"
            "kind: NetworkPolicy\n"
            "metadata:\n"
            "  name: policy-1\n"
            "spec:\n"
            "  podSelector: {}\n"
            "---\n"
            "apiVersion: networking.k8s.io/v1\n"
            "kind: NetworkPolicy\n"
            "metadata:\n"
            "  name: policy-2\n"
            "spec:\n"
            "  podSelector: {}\n"
        )
        f = tmp_path / "policies.yaml"
        f.write_text(yaml_content)

        resources = self.applier._parse_yaml(f)
        assert len(resources) == 2

    def test_parse_skips_null_documents(self, tmp_path):
        yaml_content = (
            "---\n"
            "apiVersion: networking.k8s.io/v1\n"
            "kind: NetworkPolicy\n"
            "metadata:\n"
            "  name: policy-1\n"
            "spec:\n"
            "  podSelector: {}\n"
            "---\n"
        )
        f = tmp_path / "policy.yaml"
        f.write_text(yaml_content)

        resources = self.applier._parse_yaml(f)
        assert len(resources) == 1

    def test_parse_missing_file(self):
        resources = self.applier._parse_yaml("/nonexistent/path.yaml")
        assert resources == []

    def test_parse_invalid_yaml(self, tmp_path):
        f = tmp_path / "bad.yaml"
        f.write_text("{{invalid yaml")

        resources = self.applier._parse_yaml(f)
        assert resources == []

    def test_validate_rejects_missing_api_version(self, tmp_path):
        yaml_content = """
        kind: NetworkPolicy
        metadata:
          name: test
        """
        f = tmp_path / "bad.yaml"
        f.write_text(yaml_content)

        resources = self.applier._parse_yaml(f)
        assert len(resources) == 0

    def test_validate_rejects_unsupported_kind(self, tmp_path):
        yaml_content = """
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: test
        """
        f = tmp_path / "configmap.yaml"
        f.write_text(yaml_content)

        resources = self.applier._parse_yaml(f)
        assert len(resources) == 0


class TestResourceApplierLabelInjection:
    """Test label injection on resources."""

    def setup_method(self):
        self.k8s, self.mock_networking, self.mock_logger = _create_mock_k8s_client()
        self.applier = ResourceApplier(self.k8s, self.mock_logger)

    def test_injects_label_when_missing(self):
        resource: dict = {"metadata": {"name": "test"}}
        self.applier._inject_label(resource)

        assert resource["metadata"]["labels"][TOOLKIT_LABEL] == TOOLKIT_LABEL_VALUE

    def test_preserves_existing_toolkit_label(self):
        resource: dict = {
            "metadata": {
                "name": "test",
                "labels": {TOOLKIT_LABEL: TOOLKIT_LABEL_VALUE},
            }
        }
        self.applier._inject_label(resource)

        assert resource["metadata"]["labels"][TOOLKIT_LABEL] == TOOLKIT_LABEL_VALUE

    def test_injects_namespace_when_missing(self):
        resource = {"metadata": {"name": "test"}}
        self.applier._inject_namespace(resource, "my-ns")

        assert resource["metadata"]["namespace"] == "my-ns"

    def test_preserves_existing_namespace(self):
        resource = {"metadata": {"name": "test", "namespace": "original-ns"}}
        self.applier._inject_namespace(resource, "other-ns")

        assert resource["metadata"]["namespace"] == "original-ns"


class TestResourceApplierApply:
    """Test applying resources to the cluster."""

    def setup_method(self):
        self.k8s, self.mock_networking, self.mock_logger = _create_mock_k8s_client()
        self.applier = ResourceApplier(self.k8s, self.mock_logger)

    def test_apply_network_policy(self, tmp_path):
        yaml_content = """
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: test-policy
        spec:
          podSelector: {}
        """
        f = tmp_path / "policy.yaml"
        f.write_text(yaml_content)
        self.mock_networking.create_namespaced_network_policy.return_value = None

        applied, total = self.applier.apply_from_file(f, "test-ns")

        assert applied == 1
        assert total == 1
        self.mock_networking.create_namespaced_network_policy.assert_called_once()

    def test_apply_dry_run(self, tmp_path):
        yaml_content = """
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: test-policy
        spec:
          podSelector: {}
        """
        f = tmp_path / "policy.yaml"
        f.write_text(yaml_content)

        applied, total = self.applier.apply_from_file(f, "test-ns", dry_run=True)

        assert applied == 1
        assert total == 1
        self.mock_networking.create_namespaced_network_policy.assert_not_called()

    def test_apply_empty_file(self, tmp_path):
        f = tmp_path / "empty.yaml"
        f.write_text("")

        applied, total = self.applier.apply_from_file(f, "test-ns")

        assert applied == 0
        assert total == 0

    def test_apply_multiple_policies(self, tmp_path):
        yaml_content = (
            "apiVersion: networking.k8s.io/v1\n"
            "kind: NetworkPolicy\n"
            "metadata:\n"
            "  name: policy-1\n"
            "spec:\n"
            "  podSelector: {}\n"
            "---\n"
            "apiVersion: networking.k8s.io/v1\n"
            "kind: NetworkPolicy\n"
            "metadata:\n"
            "  name: policy-2\n"
            "spec:\n"
            "  podSelector: {}\n"
        )
        f = tmp_path / "policies.yaml"
        f.write_text(yaml_content)
        self.mock_networking.create_namespaced_network_policy.return_value = None

        applied, total = self.applier.apply_from_file(f, "test-ns")

        assert applied == 2
        assert total == 2


class TestSupportedKinds:
    """Test SUPPORTED_KINDS configuration."""

    def test_network_policy_is_supported(self):
        assert "NetworkPolicy" in SUPPORTED_KINDS
