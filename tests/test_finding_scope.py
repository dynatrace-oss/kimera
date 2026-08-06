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

import pytest

from kimera.application.config.schemas import NetworkTopologyEntry
from kimera.container.remediations.exploit_findings import AttackPathRecord, FindingsDocument
from kimera.container.remediations.finding_scope import (
    Scope,
    classify,
    declared_dependencies,
    report,
)
from kimera.domain.models import PathResult

SOURCE_LABELS = {"app.kubernetes.io/name": "ad-service"}
NAMESPACE_WORKLOADS = {"ad-service", "frontend", "user-auth-service", "mariadb"}


def _document(*paths: AttackPathRecord) -> FindingsDocument:
    return FindingsDocument(
        exploit_type="missing-network-policies",
        namespace="unguard",
        source_workload="ad-service",
        attack_paths=list(paths),
    )


def _path(host: str, port: int, result: PathResult = PathResult.REACHABLE) -> AttackPathRecord:
    return AttackPathRecord(host=host, port=port, result=result)


def _topology(*destinations: str) -> dict[str, NetworkTopologyEntry]:
    return {
        destination: NetworkTopologyEntry(allowed_ingress_from=[SOURCE_LABELS])
        for destination in destinations
    }


class TestDeclaredDependencies:
    def test_inverts_ingress_declarations_for_the_source(self):
        topology = {
            "user-auth-service": NetworkTopologyEntry(allowed_ingress_from=[SOURCE_LABELS]),
            "frontend": NetworkTopologyEntry(
                allowed_ingress_from=[{"app.kubernetes.io/name": "other"}]
            ),
            "mariadb": NetworkTopologyEntry(allowed_ingress_from=None),
        }
        assert declared_dependencies(SOURCE_LABELS, topology) == {"user-auth-service"}

    def test_a_selector_matches_only_when_every_key_matches(self):
        topology = {
            "user-auth-service": NetworkTopologyEntry(
                allowed_ingress_from=[{**SOURCE_LABELS, "tier": "backend"}]
            )
        }
        assert declared_dependencies(SOURCE_LABELS, topology) == set()

    def test_a_source_with_no_labels_declares_nothing(self):
        assert declared_dependencies({}, _topology("user-auth-service")) == set()


class TestClassification:
    def test_sorts_data_store_declared_and_undeclared_paths(self):
        document = _document(
            _path("mariadb", 3306),
            _path("user-auth-service", 8080),
            _path("frontend", 3000),
        )
        result = classify(
            document, SOURCE_LABELS, _topology("user-auth-service"), NAMESPACE_WORKLOADS
        )

        assert [p.path.host for p in result.deny] == ["mariadb"]
        assert [p.path.host for p in result.keep] == ["user-auth-service"]
        assert [p.path.host for p in result.review] == ["frontend"]

    def test_declaring_a_review_path_moves_it_to_keep(self):
        document = _document(_path("frontend", 3000))

        undeclared = classify(document, SOURCE_LABELS, {}, NAMESPACE_WORKLOADS)
        declared = classify(document, SOURCE_LABELS, _topology("frontend"), NAMESPACE_WORKLOADS)

        assert undeclared.review[0].scope is Scope.REVIEW
        assert [p.path.host for p in declared.keep] == ["frontend"]
        assert declared.review == []

    def test_a_declared_data_store_is_kept_not_denied(self):
        document = _document(_path("mariadb", 3306))
        result = classify(document, SOURCE_LABELS, _topology("mariadb"), NAMESPACE_WORKLOADS)

        assert [p.path.host for p in result.keep] == ["mariadb"]
        assert result.deny == []

    @pytest.mark.parametrize(
        "host",
        ["kubernetes.default.svc", "169.254.169.254", "redis.other-namespace"],
    )
    def test_destinations_outside_the_namespace_are_denied(self, host):
        result = classify(_document(_path(host, 443)), SOURCE_LABELS, {}, NAMESPACE_WORKLOADS)

        assert [p.path.host for p in result.deny] == [host]

    def test_a_declaration_is_not_satisfied_by_a_name_prefix(self):
        document = _document(_path("user-auth-service-admin", 8080))
        result = classify(
            document, SOURCE_LABELS, _topology("user-auth-service"), NAMESPACE_WORKLOADS
        )

        assert result.keep == []
        assert [p.path.host for p in result.review] == ["user-auth-service-admin"]

    def test_a_cluster_dns_name_matches_its_declaration(self):
        document = _document(_path("user-auth-service.unguard.svc.cluster.local", 8080))
        result = classify(
            document, SOURCE_LABELS, _topology("user-auth-service"), NAMESPACE_WORKLOADS
        )

        assert len(result.keep) == 1

    def test_unknown_paths_are_never_classified(self):
        document = _document(_path("unmeasured", 9999, PathResult.UNKNOWN))
        result = classify(document, SOURCE_LABELS, {}, NAMESPACE_WORKLOADS)

        assert (result.deny, result.keep, result.review) == ([], [], [])
        assert [p.host for p in result.unmeasured] == ["unmeasured"]

    def test_a_blocked_path_is_still_classified(self):
        document = _document(_path("mariadb", 3306, PathResult.BLOCKED))
        result = classify(document, SOURCE_LABELS, {}, NAMESPACE_WORKLOADS)

        assert [p.path.host for p in result.deny] == ["mariadb"]

    def test_all_declared_findings_close_nothing(self):
        document = _document(_path("user-auth-service", 8080), _path("mariadb", 3306))
        result = classify(
            document, SOURCE_LABELS, _topology("user-auth-service", "mariadb"), NAMESPACE_WORKLOADS
        )

        assert (result.deny, result.review) == ([], [])
        assert result.closes_nothing() is True

    def test_a_denied_path_does_not_close_nothing(self):
        result = classify(_document(_path("mariadb", 3306)), SOURCE_LABELS, {}, NAMESPACE_WORKLOADS)

        assert result.closes_nothing() is False


class TestReport:
    def test_names_every_path_under_its_class(self, capsys):
        document = _document(
            _path("mariadb", 3306),
            _path("user-auth-service", 8080),
            _path("frontend", 3000),
            _path("unmeasured", 9999, PathResult.UNKNOWN),
        )
        report(
            classify(document, SOURCE_LABELS, _topology("user-auth-service"), NAMESPACE_WORKLOADS)
        )
        out = capsys.readouterr().out

        assert "mariadb:3306" in out
        assert "user-auth-service:8080" in out
        assert "frontend:3000" in out
        assert "unmeasured:9999" in out
        assert "network_topology" in out

    def test_says_so_when_nothing_is_closed(self, capsys):
        document = _document(_path("user-auth-service", 8080))
        report(
            classify(document, SOURCE_LABELS, _topology("user-auth-service"), NAMESPACE_WORKLOADS)
        )

        assert "closes no observed path" in capsys.readouterr().out
