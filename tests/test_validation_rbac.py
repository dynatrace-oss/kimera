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

"""Unit tests for RBAC validation."""

from unittest.mock import MagicMock

import pytest
from kubernetes.client import ApiException

from kimera.container.core.logger import SecurityLogger, setup_logger
from kimera.container.validation.models import ValidationVerdict
from kimera.container.validation.rbac import (
    DANGEROUS_PERMISSIONS,
    _check_sa_bindings,
    _list_service_accounts,
    validate_rbac,
)


@pytest.fixture
def mock_k8s():
    k8s = MagicMock()
    k8s.namespace = "demo"
    return k8s


@pytest.fixture
def sec_logger():
    return SecurityLogger(setup_logger("test", debug=False))


def _make_sa(name, namespace="demo"):
    sa = MagicMock()
    sa.metadata.name = name
    sa.metadata.namespace = namespace
    return sa


def _make_role_binding(name, sa_name, role_name, role_kind="Role", namespace="demo"):
    rb = MagicMock()
    rb.metadata.name = name
    subject = MagicMock()
    subject.kind = "ServiceAccount"
    subject.name = sa_name
    subject.namespace = namespace
    rb.subjects = [subject]
    rb.role_ref.kind = role_kind
    rb.role_ref.name = role_name
    return rb


def _make_role(name, rules):
    role = MagicMock()
    role.metadata.name = name
    role.rules = []
    for r in rules:
        rule = MagicMock()
        rule.verbs = r.get("verbs", [])
        rule.resources = r.get("resources", [])
        rule.api_groups = r.get("apiGroups", [""])
        role.rules.append(rule)
    return role


class TestListServiceAccounts:
    def test_lists_sas(self, mock_k8s):
        sa1 = _make_sa("default")
        sa2 = _make_sa("app-sa")
        sa_list = MagicMock()
        sa_list.items = [sa1, sa2]
        mock_k8s.v1.list_namespaced_service_account.return_value = sa_list

        result = _list_service_accounts(mock_k8s)
        assert len(result) == 2
        assert result[0]["name"] == "default"
        assert result[1]["name"] == "app-sa"

    def test_api_error(self, mock_k8s):
        mock_k8s.v1.list_namespaced_service_account.side_effect = ApiException(status=403)
        result = _list_service_accounts(mock_k8s)
        assert result == []


class TestCheckSaBindings:
    def test_finds_namespace_binding(self, mock_k8s):
        rb = _make_role_binding("my-binding", "app-sa", "my-role")
        rb_list = MagicMock()
        rb_list.items = [rb]
        mock_k8s.rbac_v1.list_namespaced_role_binding.return_value = rb_list

        crb_list = MagicMock()
        crb_list.items = []
        mock_k8s.rbac_v1.list_cluster_role_binding.return_value = crb_list

        result = _check_sa_bindings(mock_k8s, "app-sa", "demo")
        assert len(result) == 1
        assert result[0]["binding"] == "my-binding"
        assert result[0]["scope"] == "namespace"

    def test_finds_cluster_binding(self, mock_k8s):
        rb_list = MagicMock()
        rb_list.items = []
        mock_k8s.rbac_v1.list_namespaced_role_binding.return_value = rb_list

        crb = _make_role_binding("cluster-binding", "app-sa", "cluster-admin", "ClusterRole")
        crb_list = MagicMock()
        crb_list.items = [crb]
        mock_k8s.rbac_v1.list_cluster_role_binding.return_value = crb_list

        result = _check_sa_bindings(mock_k8s, "app-sa", "demo")
        assert len(result) == 1
        assert result[0]["scope"] == "cluster"
        assert result[0]["role_name"] == "cluster-admin"


class TestValidateRbac:
    def test_cluster_admin_detected(self, mock_k8s, sec_logger):
        """SA with cluster-admin binding should fail."""
        sa = _make_sa("bad-sa")
        sa_list = MagicMock()
        sa_list.items = [sa]
        mock_k8s.v1.list_namespaced_service_account.return_value = sa_list

        # No namespace bindings
        rb_list = MagicMock()
        rb_list.items = []
        mock_k8s.rbac_v1.list_namespaced_role_binding.return_value = rb_list

        # cluster-admin binding
        crb = _make_role_binding("admin-binding", "bad-sa", "cluster-admin", "ClusterRole")
        crb_list = MagicMock()
        crb_list.items = [crb]
        mock_k8s.rbac_v1.list_cluster_role_binding.return_value = crb_list

        # The cluster-admin role has wildcard rules
        role = _make_role(
            "cluster-admin",
            [
                {"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]},
            ],
        )
        mock_k8s.rbac_v1.read_cluster_role.return_value = role

        report = validate_rbac(mock_k8s, sec_logger)

        failures = [r for r in report.results if r.verdict == ValidationVerdict.FAIL]
        assert len(failures) >= 1

        # Check that cluster-admin was flagged
        admin_failures = [f for f in failures if "cluster-admin" in f.actual]
        assert len(admin_failures) >= 1

    def test_least_privilege_sa_passes(self, mock_k8s, sec_logger):
        """SA with no bindings should pass."""
        sa = _make_sa("minimal-sa")
        sa_list = MagicMock()
        sa_list.items = [sa]
        mock_k8s.v1.list_namespaced_service_account.return_value = sa_list

        rb_list = MagicMock()
        rb_list.items = []
        mock_k8s.rbac_v1.list_namespaced_role_binding.return_value = rb_list

        crb_list = MagicMock()
        crb_list.items = []
        mock_k8s.rbac_v1.list_cluster_role_binding.return_value = crb_list

        report = validate_rbac(mock_k8s, sec_logger)
        passes = [r for r in report.results if r.verdict == ValidationVerdict.PASS]
        assert len(passes) >= 1

    def test_dangerous_secrets_access(self, mock_k8s, sec_logger):
        """SA with secrets list access should fail."""
        sa = _make_sa("secrets-sa")
        sa_list = MagicMock()
        sa_list.items = [sa]
        mock_k8s.v1.list_namespaced_service_account.return_value = sa_list

        rb = _make_role_binding("secrets-binding", "secrets-sa", "secrets-role")
        rb_list = MagicMock()
        rb_list.items = [rb]
        mock_k8s.rbac_v1.list_namespaced_role_binding.return_value = rb_list

        crb_list = MagicMock()
        crb_list.items = []
        mock_k8s.rbac_v1.list_cluster_role_binding.return_value = crb_list

        role = _make_role(
            "secrets-role",
            [
                {"verbs": ["get", "list"], "resources": ["secrets"], "apiGroups": [""]},
            ],
        )
        mock_k8s.rbac_v1.read_namespaced_role.return_value = role

        report = validate_rbac(mock_k8s, sec_logger)
        failures = [r for r in report.results if r.verdict == ValidationVerdict.FAIL]
        secrets_failures = [f for f in failures if "secret" in f.test_description.lower()]
        assert len(secrets_failures) >= 1

    def test_empty_namespace(self, mock_k8s, sec_logger):
        """No SAs found."""
        sa_list = MagicMock()
        sa_list.items = []
        mock_k8s.v1.list_namespaced_service_account.return_value = sa_list

        report = validate_rbac(mock_k8s, sec_logger)
        assert report.total == 0

    def test_dangerous_permissions_completeness(self):
        """Verify dangerous permissions list covers key vectors."""
        resources_checked = {p[1] for p in DANGEROUS_PERMISSIONS}
        assert "secrets" in resources_checked
        assert "pods/exec" in resources_checked
        assert "clusterrolebindings" in resources_checked
