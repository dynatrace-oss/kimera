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
from kimera.container.make_vulnerable.missing_network_policies import (
    TOOLKIT_LABEL,
    TOOLKIT_LABEL_VALUE,
    MissingNetworkPoliciesExploit,
)


def _create_mock_k8s_client() -> tuple[K8sClient, MagicMock, MagicMock]:
    """Create a mock K8sClient with networking_v1 API."""
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


def _make_mock_deployment(name: str, labels: dict[str, str], ports: list[int]) -> Mock:
    """Build a mock deployment with the given labels and container ports."""
    dep = Mock()
    dep.metadata.name = name
    dep.spec.selector.match_labels = labels

    mock_ports = []
    for p in ports:
        mp = Mock()
        mp.container_port = p
        mock_ports.append(mp)

    container = Mock()
    container.ports = mock_ports
    dep.spec.template.spec.containers = [container]
    return dep


class TestAutoDiscoverPolicies:
    """Test auto-discovery of network policies from deployments."""

    def setup_method(self):
        """Set up test fixtures."""
        self.k8s, self.mock_networking, self.mock_logger = _create_mock_k8s_client()
        self.exploit = MissingNetworkPoliciesExploit(self.k8s, "test-svc", self.mock_logger)

    def test_generates_default_deny_plus_per_deployment(self):
        """Test that auto-discovery generates default-deny + one policy per deployment."""
        deps = [
            _make_mock_deployment("frontend", {"app": "frontend"}, [80]),
            _make_mock_deployment("backend", {"app": "backend"}, [8080]),
        ]
        mock_result = Mock()
        mock_result.items = deps
        self.k8s.apps_v1.list_namespaced_deployment.return_value = mock_result

        policies = self.exploit._auto_discover_policies()

        assert len(policies) == 3  # deny-all + 2 deployments
        assert policies[0]["metadata"]["name"] == "default-deny-all"
        assert policies[1]["metadata"]["name"] == "allow-frontend"
        assert policies[2]["metadata"]["name"] == "allow-backend"

    def test_default_deny_structure(self):
        """Test the default-deny policy blocks all traffic."""
        mock_result = Mock()
        mock_result.items = []
        self.k8s.apps_v1.list_namespaced_deployment.return_value = mock_result

        policies = self.exploit._auto_discover_policies()
        deny = policies[0]

        assert deny["spec"]["podSelector"] == {}
        assert "Ingress" in deny["spec"]["policyTypes"]
        assert "Egress" in deny["spec"]["policyTypes"]

    def test_service_policy_has_correct_labels(self):
        """Test that per-deployment policies use the deployment's match labels."""
        deps = [_make_mock_deployment("web", {"app.kubernetes.io/name": "web"}, [80])]
        mock_result = Mock()
        mock_result.items = deps
        self.k8s.apps_v1.list_namespaced_deployment.return_value = mock_result

        policies = self.exploit._auto_discover_policies()
        svc_policy = policies[1]

        assert svc_policy["spec"]["podSelector"]["matchLabels"] == {"app.kubernetes.io/name": "web"}

    def test_service_policy_has_ingress_ports(self):
        """Test that per-deployment policies allow ingress on declared ports."""
        deps = [_make_mock_deployment("api", {"app": "api"}, [8080, 9090])]
        mock_result = Mock()
        mock_result.items = deps
        self.k8s.apps_v1.list_namespaced_deployment.return_value = mock_result

        policies = self.exploit._auto_discover_policies()
        ingress_ports = policies[1]["spec"]["ingress"][0]["ports"]

        assert len(ingress_ports) == 2
        assert {"protocol": "TCP", "port": 8080} in ingress_ports
        assert {"protocol": "TCP", "port": 9090} in ingress_ports

    def test_service_policy_includes_dns_egress(self):
        """Test that per-deployment policies include DNS egress."""
        deps = [_make_mock_deployment("svc", {"app": "svc"}, [80])]
        mock_result = Mock()
        mock_result.items = deps
        self.k8s.apps_v1.list_namespaced_deployment.return_value = mock_result

        policies = self.exploit._auto_discover_policies()
        egress = policies[1]["spec"]["egress"]

        dns_rule = egress[-1]
        assert dns_rule["ports"] == [{"protocol": "UDP", "port": 53}]

    def test_all_policies_have_toolkit_labels(self):
        """Test that all auto-discovered policies have the managed-by label."""
        deps = [_make_mock_deployment("svc", {"app": "svc"}, [80])]
        mock_result = Mock()
        mock_result.items = deps
        self.k8s.apps_v1.list_namespaced_deployment.return_value = mock_result

        policies = self.exploit._auto_discover_policies()
        for policy in policies:
            assert policy["metadata"]["labels"][TOOLKIT_LABEL] == TOOLKIT_LABEL_VALUE

    def test_all_policies_are_valid_k8s_resources(self):
        """Test that all policies have required Kubernetes resource fields."""
        deps = [_make_mock_deployment("app", {"app": "app"}, [80])]
        mock_result = Mock()
        mock_result.items = deps
        self.k8s.apps_v1.list_namespaced_deployment.return_value = mock_result

        policies = self.exploit._auto_discover_policies()
        for policy in policies:
            assert policy["apiVersion"] == "networking.k8s.io/v1"
            assert policy["kind"] == "NetworkPolicy"
            assert "name" in policy["metadata"]
            assert "namespace" in policy["metadata"]
            assert "podSelector" in policy["spec"]
            assert "policyTypes" in policy["spec"]

    def test_policy_names_are_unique(self):
        """Test that all policy names are unique."""
        deps = [
            _make_mock_deployment("a", {"app": "a"}, [80]),
            _make_mock_deployment("b", {"app": "b"}, [8080]),
        ]
        mock_result = Mock()
        mock_result.items = deps
        self.k8s.apps_v1.list_namespaced_deployment.return_value = mock_result

        policies = self.exploit._auto_discover_policies()
        names = [p["metadata"]["name"] for p in policies]
        assert len(names) == len(set(names))

    def test_handles_deployment_without_ports(self):
        """Test discovery handles deployments with no container ports."""
        dep = Mock()
        dep.metadata.name = "worker"
        dep.spec.selector.match_labels = {"app": "worker"}
        container = Mock()
        container.ports = None
        dep.spec.template.spec.containers = [container]

        mock_result = Mock()
        mock_result.items = [dep]
        self.k8s.apps_v1.list_namespaced_deployment.return_value = mock_result

        policies = self.exploit._auto_discover_policies()
        assert len(policies) == 2
        # No ingress ports means empty ingress rules
        assert policies[1]["spec"]["ingress"] == []

    def test_handles_api_error(self):
        """Test discovery returns just default-deny on API failure."""
        self.k8s.apps_v1.list_namespaced_deployment.side_effect = ApiException(
            status=500, reason="Server Error"
        )

        policies = self.exploit._auto_discover_policies()
        assert len(policies) == 1
        assert policies[0]["metadata"]["name"] == "default-deny-all"


class TestK8sClientNetworkPolicyMethods:
    """Test K8sClient network policy CRUD methods."""

    def setup_method(self):
        """Set up test fixtures."""
        self.k8s, self.mock_networking, self.mock_logger = _create_mock_k8s_client()

    def test_list_network_policies_success(self):
        """Test listing network policies returns items."""
        mock_result = Mock()
        mock_result.items = [Mock(), Mock()]
        self.mock_networking.list_namespaced_network_policy.return_value = mock_result

        policies = self.k8s.list_network_policies("test-ns")
        assert len(policies) == 2
        self.mock_networking.list_namespaced_network_policy.assert_called_once_with("test-ns")

    def test_list_network_policies_uses_default_namespace(self):
        """Test listing network policies falls back to client namespace."""
        mock_result = Mock()
        mock_result.items = []
        self.mock_networking.list_namespaced_network_policy.return_value = mock_result

        self.k8s.list_network_policies()
        self.mock_networking.list_namespaced_network_policy.assert_called_once_with("test-ns")

    def test_list_network_policies_api_error(self):
        """Test listing network policies raises K8sError on API failure."""
        self.mock_networking.list_namespaced_network_policy.side_effect = ApiException(
            status=500, reason="Server Error"
        )

        with pytest.raises(K8sError, match="Failed to list network policies"):
            self.k8s.list_network_policies("test-ns")

    def test_create_network_policy_success(self):
        """Test creating a network policy."""
        body = {"metadata": {"name": "test-policy"}}
        result = self.k8s.create_network_policy(body, "test-ns")

        assert result is True
        self.mock_networking.create_namespaced_network_policy.assert_called_once_with(
            namespace="test-ns", body=body
        )

    def test_create_network_policy_dry_run(self):
        """Test dry-run does not call the API."""
        body = {"metadata": {"name": "test-policy"}}
        result = self.k8s.create_network_policy(body, "test-ns", dry_run=True)

        assert result is True
        self.mock_networking.create_namespaced_network_policy.assert_not_called()

    def test_create_network_policy_conflict(self):
        """Test creating an already-existing policy returns True."""
        self.mock_networking.create_namespaced_network_policy.side_effect = ApiException(
            status=409, reason="Conflict"
        )
        body = {"metadata": {"name": "existing-policy"}}
        result = self.k8s.create_network_policy(body, "test-ns")

        assert result is True

    def test_create_network_policy_api_error(self):
        """Test creating a policy returns False on non-conflict errors."""
        self.mock_networking.create_namespaced_network_policy.side_effect = ApiException(
            status=500, reason="Server Error"
        )
        body = {"metadata": {"name": "bad-policy"}}
        result = self.k8s.create_network_policy(body, "test-ns")

        assert result is False

    def test_delete_network_policy_success(self):
        """Test deleting a network policy."""
        result = self.k8s.delete_network_policy("test-policy", "test-ns")

        assert result is True
        self.mock_networking.delete_namespaced_network_policy.assert_called_once_with(
            name="test-policy", namespace="test-ns"
        )

    def test_delete_network_policy_not_found(self):
        """Test deleting a non-existent policy returns True."""
        self.mock_networking.delete_namespaced_network_policy.side_effect = ApiException(
            status=404, reason="Not Found"
        )
        result = self.k8s.delete_network_policy("missing-policy", "test-ns")

        assert result is True

    def test_delete_network_policy_api_error(self):
        """Test deleting a policy returns False on API errors."""
        self.mock_networking.delete_namespaced_network_policy.side_effect = ApiException(
            status=500, reason="Server Error"
        )
        result = self.k8s.delete_network_policy("bad-policy", "test-ns")

        assert result is False

    def test_network_policy_exists_true(self):
        """Test checking existence of an existing policy."""
        assert self.k8s.network_policy_exists("my-policy", "test-ns") is True

    def test_network_policy_exists_false(self):
        """Test checking existence of a missing policy."""
        self.mock_networking.read_namespaced_network_policy.side_effect = ApiException(
            status=404, reason="Not Found"
        )
        assert self.k8s.network_policy_exists("missing", "test-ns") is False

    def test_network_policy_exists_api_error(self):
        """Test checking existence raises K8sError on API errors."""
        self.mock_networking.read_namespaced_network_policy.side_effect = ApiException(
            status=500, reason="Server Error"
        )
        with pytest.raises(K8sError, match="Failed to check NetworkPolicy"):
            self.k8s.network_policy_exists("bad", "test-ns")

    def test_k8s_client_has_networking_v1(self):
        """Test that K8sClient initializes the networking API client."""
        assert hasattr(self.k8s, "networking_v1")
        assert self.k8s.networking_v1 is self.mock_networking


class TestMissingNetworkPoliciesExploit:
    """Test MissingNetworkPoliciesExploit class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.k8s, self.mock_networking, self.mock_logger = _create_mock_k8s_client()
        self.exploit = MissingNetworkPoliciesExploit(self.k8s, "test-service", self.mock_logger)

    def test_class_attributes(self):
        """Test exploit class attributes are set correctly."""
        assert self.exploit.name == "Missing Network Policies"
        assert self.exploit.risk_level == "HIGH"
        assert self.exploit.vulnerability_type == "missing-network-policies"
        assert "network policies" in self.exploit.description.lower()

    def test_get_default_service_returns_empty(self):
        """Test default service returns empty string (no hardcoded default)."""
        assert self.exploit.get_default_service() == ""

    def test_requires_service(self):
        """Test that constructing without a service raises ValueError."""
        with pytest.raises(ValueError, match="No service specified"):
            MissingNetworkPoliciesExploit(self.k8s, None, self.mock_logger)

    def test_get_vulnerable_patch_returns_empty(self):
        """Test that vulnerable patch is empty (not deployment-based)."""
        assert self.exploit.get_vulnerable_patch() == []

    def test_get_secure_patch_returns_empty(self):
        """Test that secure patch is empty (not deployment-based)."""
        assert self.exploit.get_secure_patch() == []

    def test_check_vulnerability_no_policies(self):
        """Test vulnerability check when no policies exist."""
        mock_result = Mock()
        mock_result.items = []
        self.mock_networking.list_namespaced_network_policy.return_value = mock_result

        assert self.exploit.check_vulnerability() is True

    def test_check_vulnerability_policies_exist(self):
        """Test vulnerability check when policies are present."""
        mock_result = Mock()
        mock_result.items = [Mock()]
        self.mock_networking.list_namespaced_network_policy.return_value = mock_result

        assert self.exploit.check_vulnerability() is False

    def test_make_vulnerable_removes_toolkit_policies(self):
        """Test make_vulnerable removes only toolkit-managed policies."""
        toolkit_policy = Mock()
        toolkit_policy.metadata.name = "default-deny-all"
        toolkit_policy.metadata.labels = {TOOLKIT_LABEL: TOOLKIT_LABEL_VALUE}

        user_policy = Mock()
        user_policy.metadata.name = "user-custom-policy"
        user_policy.metadata.labels = {"app": "custom"}

        mock_result = Mock()
        mock_result.items = [toolkit_policy, user_policy]
        self.mock_networking.list_namespaced_network_policy.return_value = mock_result

        result = self.exploit.make_vulnerable()

        assert result is True
        self.mock_networking.delete_namespaced_network_policy.assert_called_once_with(
            name="default-deny-all", namespace="test-ns"
        )

    def test_make_vulnerable_dry_run(self):
        """Test make_vulnerable dry run does not delete anything."""
        toolkit_policy = Mock()
        toolkit_policy.metadata.name = "default-deny-all"
        toolkit_policy.metadata.labels = {TOOLKIT_LABEL: TOOLKIT_LABEL_VALUE}

        mock_result = Mock()
        mock_result.items = [toolkit_policy]
        self.mock_networking.list_namespaced_network_policy.return_value = mock_result

        result = self.exploit.make_vulnerable(dry_run=True)

        assert result is True
        self.mock_networking.delete_namespaced_network_policy.assert_not_called()

    def test_make_vulnerable_no_toolkit_policies(self):
        """Test make_vulnerable when no toolkit policies exist."""
        mock_result = Mock()
        mock_result.items = []
        self.mock_networking.list_namespaced_network_policy.return_value = mock_result

        result = self.exploit.make_vulnerable()

        assert result is True
        self.mock_networking.delete_namespaced_network_policy.assert_not_called()

    def test_make_vulnerable_handles_none_labels(self):
        """Test make_vulnerable handles policies with None labels."""
        policy = Mock()
        policy.metadata.name = "no-labels-policy"
        policy.metadata.labels = None

        mock_result = Mock()
        mock_result.items = [policy]
        self.mock_networking.list_namespaced_network_policy.return_value = mock_result

        result = self.exploit.make_vulnerable()

        assert result is True
        self.mock_networking.delete_namespaced_network_policy.assert_not_called()

    def test_make_secure_creates_policies_from_discovery(self):
        """Test make_secure creates policies based on auto-discovered deployments."""
        deps = [_make_mock_deployment("web", {"app": "web"}, [80])]
        mock_dep_result = Mock()
        mock_dep_result.items = deps
        self.k8s.apps_v1.list_namespaced_deployment.return_value = mock_dep_result
        self.mock_networking.create_namespaced_network_policy.return_value = None

        result = self.exploit.make_secure()

        assert result is True
        # default-deny + 1 per-deployment policy = 2
        assert self.mock_networking.create_namespaced_network_policy.call_count == 2

    def test_make_secure_dry_run(self):
        """Test make_secure dry run does not call API."""
        deps = [_make_mock_deployment("web", {"app": "web"}, [80])]
        mock_dep_result = Mock()
        mock_dep_result.items = deps
        self.k8s.apps_v1.list_namespaced_deployment.return_value = mock_dep_result

        result = self.exploit.make_secure(dry_run=True)

        assert result is True
        self.mock_networking.create_namespaced_network_policy.assert_not_called()

    def test_make_secure_partial_failure(self):
        """Test make_secure returns False when some policies fail."""
        deps = [
            _make_mock_deployment("a", {"app": "a"}, [80]),
            _make_mock_deployment("b", {"app": "b"}, [8080]),
        ]
        mock_dep_result = Mock()
        mock_dep_result.items = deps
        self.k8s.apps_v1.list_namespaced_deployment.return_value = mock_dep_result

        call_count = 0

        def side_effect(**kwargs):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise ApiException(status=500, reason="Server Error")

        self.mock_networking.create_namespaced_network_policy.side_effect = side_effect

        result = self.exploit.make_secure()
        assert result is False

    def test_demonstrate_no_pod(self):
        """Test demonstrate returns failure when no pod is found."""
        mock_pod_list = Mock()
        mock_pod_list.items = []
        self.k8s.v1.list_namespaced_pod.return_value = mock_pod_list

        result = self.exploit.demonstrate()

        assert result.success is False
        assert "not found" in result.message.lower()


class TestExploitRegistration:
    """Test that the exploit is properly registered in the CLI."""

    def test_exploit_in_registry(self):
        """Test that missing-network-policies is in the EXPLOITS registry."""
        from kimera.exploit_k8s import EXPLOITS

        assert "missing-network-policies" in EXPLOITS
        assert EXPLOITS["missing-network-policies"] is MissingNetworkPoliciesExploit
