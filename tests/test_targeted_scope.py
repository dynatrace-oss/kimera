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

from typing import Any

import pytest
import yaml

from kimera.application.config.schemas import ExternalEgressDestination, NetworkTopologyEntry
from kimera.cli.generate import _resolve_scope
from kimera.container.remediations.exploit_findings import AttackPathRecord, FindingsDocument
from kimera.container.remediations.finding_scope import NAMESPACE_SCOPE, TARGETED_SCOPE
from kimera.container.remediations.generator import _load_template
from kimera.container.remediations.targeted import build_plan, enforce
from kimera.container.validation.reachability import Workload, egress_permits
from kimera.domain.models import PathResult

NAMESPACE = "unguard"
SOURCE_LABELS = {"app.kubernetes.io/name": "ad-service"}
AUTH_LABELS = {"app.kubernetes.io/name": "user-auth-service"}
MARIADB_LABELS = {"app.kubernetes.io/name": "mariadb"}

CONTEXT: dict[str, Any] = {
    "deployments": {
        "ad-service": {"labels": SOURCE_LABELS, "ports": [8080]},
        "user-auth-service": {"labels": AUTH_LABELS, "ports": [8080]},
        "frontend": {"labels": {"app.kubernetes.io/name": "frontend"}, "ports": [3000]},
    },
    "statefulsets": {"mariadb": {"labels": MARIADB_LABELS, "ports": [3306]}},
    "services": {"user-auth-service": {"ports": [{"port": 8080}], "selector": AUTH_LABELS}},
}

TOPOLOGY = {"user-auth-service": NetworkTopologyEntry(allowed_ingress_from=[SOURCE_LABELS])}


def _findings(*paths: tuple[str, int], namespace: str = NAMESPACE, source: str = "ad-service"):
    return FindingsDocument(
        exploit_type="missing-network-policies",
        namespace=namespace,
        source_workload=source,
        attack_paths=[
            AttackPathRecord(host=host, port=port, result=PathResult.REACHABLE)
            for host, port in paths
        ],
    )


OBSERVED = _findings(
    ("mariadb", 3306),
    ("redis", 6379),
    ("kubernetes.default.svc", 443),
    ("169.254.169.254", 80),
    ("user-auth-service", 8080),
)


def _policy(name: str, labels: dict[str, str], egress: list[dict[str, Any]] | None = None):
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": NAMESPACE},
        "spec": {
            "podSelector": {"matchLabels": labels},
            "policyTypes": ["Egress"],
            "egress": egress if egress is not None else [],
        },
    }


def _plan(document: FindingsDocument | None = None, topology: Any = None):
    return build_plan(
        document or OBSERVED, CONTEXT, TOPOLOGY if topology is None else topology, NAMESPACE
    )


class TestPlanValidation:
    def test_findings_from_another_namespace_are_rejected(self):
        with pytest.raises(ValueError, match="recorded in namespace 'other'"):
            build_plan(_findings(namespace="other"), CONTEXT, TOPOLOGY, NAMESPACE)

    def test_a_source_workload_absent_from_the_namespace_is_rejected(self):
        with pytest.raises(ValueError, match="retired-service"):
            build_plan(_findings(source="retired-service"), CONTEXT, TOPOLOGY, NAMESPACE)

    def test_dependency_ports_come_from_the_service(self):
        assert [(d.workload.name, d.ports) for d in _plan().dependencies] == [
            ("user-auth-service", [8080])
        ]


class TestEnforce:
    def test_only_the_source_workload_is_selected(self):
        docs = [
            _policy("default-deny", {}),
            _policy("ad-service-egress", SOURCE_LABELS),
            _policy("frontend-egress", {"app.kubernetes.io/name": "frontend"}),
        ]
        kept, deviations = enforce(docs, _plan(), NAMESPACE)

        assert [d["metadata"]["name"] for d in kept] == ["ad-service-egress"]
        assert any("selects every pod" in d for d in deviations)
        assert any("selects a workload other than ad-service" in d for d in deviations)

    def test_a_default_deny_with_an_empty_selector_never_survives(self):
        kept, _ = enforce(
            [{**_policy("deny-all", {}), "spec": {"podSelector": {}}}], _plan(), NAMESPACE
        )

        assert all(policy["spec"]["podSelector"]["matchLabels"] == SOURCE_LABELS for policy in kept)

    def test_observed_paths_are_not_permitted_by_the_emitted_set(self):
        kept, _ = enforce([_policy("ad-service-egress", SOURCE_LABELS)], _plan(), NAMESPACE)
        source = Workload(name="ad-service", labels=SOURCE_LABELS)

        for host, port, labels in (
            ("mariadb", 3306, MARIADB_LABELS),
            ("frontend", 3000, {"app.kubernetes.io/name": "frontend"}),
        ):
            assert not egress_permits(source, Workload(name=host, labels=labels), port, kept)

    def test_the_declared_dependency_stays_permitted(self):
        kept, _ = enforce([_policy("ad-service-egress", SOURCE_LABELS)], _plan(), NAMESPACE)

        assert egress_permits(
            Workload(name="ad-service", labels=SOURCE_LABELS),
            Workload(name="user-auth-service", labels=AUTH_LABELS),
            8080,
            kept,
        )

    def test_dns_is_permitted(self):
        kept, _ = enforce([_policy("ad-service-egress", SOURCE_LABELS)], _plan(), NAMESPACE)
        rules = kept[0]["spec"]["egress"]

        assert any(
            peer.get("podSelector", {}).get("matchLabels") == {"k8s-app": "kube-dns"}
            for rule in rules
            for peer in rule.get("to", [])
        )

    def test_a_permitted_deny_path_is_reported_and_removed(self):
        permissive = [{"to": [{"podSelector": {"matchLabels": MARIADB_LABELS}}]}]
        _, deviations = enforce(
            [_policy("ad-service-egress", SOURCE_LABELS, permissive)], _plan(), NAMESPACE
        )

        assert any("mariadb:3306 was permitted" in d for d in deviations)

    def test_a_severed_dependency_is_reported_and_restored(self):
        kept, deviations = enforce(
            [_policy("ad-service-egress", SOURCE_LABELS, [])], _plan(), NAMESPACE
        )

        assert any("user-auth-service:8080 was severed" in d for d in deviations)
        assert egress_permits(
            Workload(name="ad-service", labels=SOURCE_LABELS),
            Workload(name="user-auth-service", labels=AUTH_LABELS),
            8080,
            kept,
        )

    def test_a_set_with_no_policy_for_the_source_gets_one(self):
        kept, deviations = enforce([], _plan(), NAMESPACE)

        assert kept[0]["spec"]["podSelector"]["matchLabels"] == SOURCE_LABELS
        assert any("no policy selecting ad-service" in d for d in deviations)

    def test_declared_external_egress_is_carried_into_the_policy(self):
        topology = {
            **TOPOLOGY,
            "ad-service": NetworkTopologyEntry(
                allowed_egress_to=[
                    ExternalEgressDestination(
                        cidr="0.0.0.0/0", **{"except": ["10.0.0.0/8"]}, ports=[443]
                    )
                ]
            ),
        }
        kept, _ = enforce(
            [_policy("ad-service-egress", SOURCE_LABELS)], _plan(topology=topology), NAMESPACE
        )
        blocks = [
            peer["ipBlock"]
            for rule in kept[0]["spec"]["egress"]
            for peer in rule.get("to", [])
            if "ipBlock" in peer
        ]

        assert blocks == [{"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}]

    def test_no_policy_is_emitted_for_a_non_source_workload_declaring_external_egress(self):
        topology = {
            **TOPOLOGY,
            "frontend": NetworkTopologyEntry(
                allowed_egress_to=[ExternalEgressDestination(cidr="0.0.0.0/0", ports=[443])]
            ),
        }
        kept, _ = enforce(
            [_policy("ad-service-egress", SOURCE_LABELS)], _plan(topology=topology), NAMESPACE
        )

        assert [p["spec"]["podSelector"]["matchLabels"] for p in kept] == [SOURCE_LABELS]

    def test_non_networkpolicy_documents_are_dropped(self):
        deployment = {"kind": "Deployment", "metadata": {"name": "ad-service"}}
        kept, deviations = enforce(
            [deployment, _policy("ad-service-egress", SOURCE_LABELS)], _plan(), NAMESPACE
        )

        assert [d["kind"] for d in kept] == ["NetworkPolicy"]
        assert any("not a NetworkPolicy" in d for d in deviations)

    def test_the_result_is_serialisable_yaml(self):
        kept, _ = enforce([_policy("ad-service-egress", SOURCE_LABELS)], _plan(), NAMESPACE)

        assert list(yaml.safe_load_all(yaml.safe_dump_all(kept))) == kept


class TestPromptScope:
    def test_namespace_scope_still_asks_for_a_default_deny(self):
        rendered = _load_template("generate_system.j2").render(
            exploit_type="missing-network-policies", scope=NAMESPACE_SCOPE
        )

        assert "default-deny-all policy first" in rendered

    def test_targeted_scope_forbids_a_default_deny(self):
        rendered = _load_template("generate_system.j2").render(
            exploit_type="missing-network-policies", scope=TARGETED_SCOPE
        )

        assert "Never emit a default-deny-all policy" in rendered
        assert "default-deny-all policy first" not in rendered

    def test_the_targeted_prompt_names_the_source_and_the_denied_paths(self):
        rendered = _load_template("generate_user.j2").render(
            exploit_type="missing-network-policies",
            namespace=NAMESPACE,
            context=CONTEXT,
            topology={},
            scope=TARGETED_SCOPE,
            plan=_plan(),
        )

        assert "Targeted scope: ad-service" in rendered
        assert "[DENY] mariadb:3306" in rendered
        assert "user-auth-service: labels=" in rendered


class TestScopeDefaulting:
    def test_findings_without_a_scope_select_targeted(self, tmp_path):
        path = tmp_path / "findings.json"
        path.write_text(OBSERVED.model_dump_json())

        document, scope = _resolve_scope(path, None)

        assert scope == TARGETED_SCOPE
        assert document is not None and document.source_workload == "ad-service"

    def test_no_findings_and_no_scope_stays_namespace_wide(self):
        assert _resolve_scope(None, None) == (None, NAMESPACE_SCOPE)

    def test_targeted_without_findings_is_an_error(self):
        with pytest.raises(ValueError, match="requires --from-findings"):
            _resolve_scope(None, TARGETED_SCOPE)

    def test_namespace_scope_with_findings_keeps_the_namespace_set(self, tmp_path):
        path = tmp_path / "findings.json"
        path.write_text(OBSERVED.model_dump_json())

        document, scope = _resolve_scope(path, NAMESPACE_SCOPE)

        assert scope == NAMESPACE_SCOPE
        assert document is not None
