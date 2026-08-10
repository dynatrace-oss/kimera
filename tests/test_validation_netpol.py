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

"""Unit tests for NetworkPolicy validation."""

from unittest.mock import MagicMock, patch

import pytest
from kubernetes.client import ApiException

from kimera.container.core.logger import SecurityLogger, setup_logger
from kimera.container.validation.models import ValidationVerdict
from kimera.container.validation.netpol_checks import (
    _check_default_deny,
    _discover_namespace_services,
)
from kimera.container.validation.network_policy import validate_network_policies
from kimera.container.validation.reachability import Workload, egress_permits


@pytest.fixture
def mock_k8s():
    k8s = MagicMock()
    k8s.namespace = "demo"
    return k8s


@pytest.fixture
def sec_logger():
    return SecurityLogger(setup_logger("test", debug=False))


def _make_netpol(name, pod_selector=None, policy_types=None, ingress=None, egress=None):
    """Build a mock NetworkPolicy."""
    policy = MagicMock()
    policy.metadata.name = name
    policy.spec.pod_selector = pod_selector or MagicMock(match_labels=None)
    policy.spec.policy_types = policy_types or []
    policy.spec.ingress = ingress
    policy.spec.egress = egress
    return policy


SOURCE = Workload(name="auth", labels={"app": "auth"})
DESTINATION = Workload(name="cache", labels={"app": "cache"})


def _egress_policy(rule):
    return {
        "metadata": {"name": "netpol-auth"},
        "spec": {
            "podSelector": {"matchLabels": {"app": "auth"}},
            "policyTypes": ["Egress"],
            "egress": [rule],
        },
    }


class TestRulesPermitMatching:
    """The pod-to-pod matcher must read protocol, and honour an empty peer list."""

    @pytest.mark.parametrize(
        "rule_protocol,permitted", [("TCP", True), (None, True), ("UDP", False)]
    )
    def test_protocol_must_match(self, rule_protocol, permitted):
        """A port entry without a protocol means TCP, not any protocol."""
        port_spec = {"port": 6379}
        if rule_protocol is not None:
            port_spec["protocol"] = rule_protocol
        policies = [
            _egress_policy(
                {"to": [{"podSelector": {"matchLabels": {"app": "cache"}}}], "ports": [port_spec]}
            )
        ]

        assert egress_permits(SOURCE, DESTINATION, 6379, policies, "TCP") is permitted

    def test_empty_peer_list_permits_every_destination(self):
        policies = [_egress_policy({"to": [], "ports": [{"port": 6379, "protocol": "TCP"}]})]

        assert egress_permits(SOURCE, DESTINATION, 6379, policies, "TCP") is True


class TestCheckDefaultDeny:
    def test_no_policies(self, mock_k8s):
        mock_k8s.list_network_policies.return_value = []
        result = _check_default_deny(mock_k8s, "demo")
        assert result is not None
        assert result.verdict == ValidationVerdict.FAIL
        assert "MISSING" in result.actual

    def test_has_default_deny(self, mock_k8s):
        policy = _make_netpol(
            "default-deny",
            pod_selector=MagicMock(match_labels=None),
            policy_types=["Ingress", "Egress"],
            ingress=None,
            egress=None,
        )
        mock_k8s.list_network_policies.return_value = [policy]

        result = _check_default_deny(mock_k8s, "demo")
        assert result is not None
        assert result.verdict == ValidationVerdict.PASS

    def test_partial_policy(self, mock_k8s):
        # Has a policy but only Ingress, not Egress
        policy = _make_netpol(
            "partial",
            pod_selector=MagicMock(match_labels=None),
            policy_types=["Ingress"],
            ingress=None,
            egress=None,
        )
        mock_k8s.list_network_policies.return_value = [policy]

        result = _check_default_deny(mock_k8s, "demo")
        assert result is not None
        assert result.verdict == ValidationVerdict.FAIL
        assert "PARTIAL" in result.actual

    def test_api_error(self, mock_k8s):
        mock_k8s.list_network_policies.side_effect = Exception("API error")
        result = _check_default_deny(mock_k8s, "demo")
        assert result is None


class TestDiscoverNamespaceServices:
    def test_discovers_services(self, mock_k8s):
        svc = MagicMock()
        svc.metadata.name = "frontend"
        port = MagicMock()
        port.port = 80
        port.protocol = "TCP"
        svc.spec.ports = [port]

        svc_list = MagicMock()
        svc_list.items = [svc]
        mock_k8s.v1.list_namespaced_service.return_value = svc_list

        result = _discover_namespace_services(mock_k8s, "demo")
        assert len(result) == 1
        assert result[0]["name"] == "frontend"
        assert result[0]["port"] == 80

    def test_api_error(self, mock_k8s):
        mock_k8s.v1.list_namespaced_service.side_effect = ApiException(status=403)
        result = _discover_namespace_services(mock_k8s, "demo")
        assert result == []


class TestValidateNetworkPolicies:
    @patch("kimera.container.validation.network_policy._deploy_probe_pod")
    @patch("kimera.container.validation.network_policy._cleanup_probe_pod")
    @patch("kimera.container.validation.network_policy._test_connectivity")
    def test_no_policies_all_open(self, mock_conn, mock_cleanup, mock_deploy, mock_k8s, sec_logger):
        mock_k8s.list_network_policies.return_value = []
        mock_deploy.return_value = None  # None means the probe pod started
        mock_conn.return_value = True  # Everything is reachable

        report = validate_network_policies(mock_k8s, sec_logger)

        # Should have default-deny failure + connectivity failures
        assert report.failed >= 1
        default_deny = [r for r in report.results if r.control_name == "default-deny"]
        assert len(default_deny) == 1
        assert default_deny[0].verdict == ValidationVerdict.FAIL

    @patch("kimera.container.validation.network_policy._deploy_probe_pod")
    @patch("kimera.container.validation.network_policy._cleanup_probe_pod")
    @patch("kimera.container.validation.network_policy._test_connectivity")
    def test_all_blocked(self, mock_conn, mock_cleanup, mock_deploy, mock_k8s, sec_logger):
        # Default deny exists
        policy = _make_netpol(
            "default-deny",
            pod_selector=MagicMock(match_labels=None),
            policy_types=["Ingress", "Egress"],
        )
        mock_k8s.list_network_policies.return_value = [policy]
        mock_deploy.return_value = None  # None means the probe pod started
        mock_conn.return_value = False  # Everything is blocked

        report = validate_network_policies(mock_k8s, sec_logger)
        # Only intra-namespace tests should fail (no services discovered in mock)
        assert report.passed >= 1  # default-deny passes + blocked targets pass

    @patch("kimera.container.validation.network_policy._deploy_probe_pod")
    def test_probe_deploy_fails(self, mock_deploy, mock_k8s, sec_logger):
        mock_k8s.list_network_policies.return_value = []
        mock_deploy.return_value = "rejected by admission control: HTTP 403 Forbidden"

        report = validate_network_policies(mock_k8s, sec_logger)

        skipped = [r for r in report.results if r.control_name == "active-connectivity-tests"]
        assert len(skipped) == 1
        assert skipped[0].verdict == ValidationVerdict.ERROR
        assert "HTTP 403" in skipped[0].evidence
        assert report.all_passed is False
        assert "NOT executed" in report.summary

    @patch("kimera.container.validation.network_policy._deploy_probe_pod")
    @patch("kimera.container.validation.network_policy._cleanup_probe_pod")
    @patch("kimera.container.validation.network_policy._test_connectivity")
    def test_metadata_endpoint_blocked(
        self, mock_conn, mock_cleanup, mock_deploy, mock_k8s, sec_logger
    ):
        mock_k8s.list_network_policies.return_value = []
        mock_deploy.return_value = None  # None means the probe pod started

        def conn_side_effect(k8s, ns, host, port, **kwargs):
            if host == "169.254.169.254":
                return False  # Blocked
            return True

        mock_conn.side_effect = conn_side_effect

        report = validate_network_policies(mock_k8s, sec_logger)
        metadata_results = [r for r in report.results if r.control_name == "cloud-metadata-block"]
        assert len(metadata_results) == 1
        assert metadata_results[0].verdict == ValidationVerdict.PASS
