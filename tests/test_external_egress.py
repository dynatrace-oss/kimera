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

from kimera.application.config.schemas import NetworkTopologyEntry
from kimera.container.validation.external_egress import (
    close_external_gaps,
    find_external_gaps,
    unmatched_declarations,
)
from kimera.container.validation.reachability import Workload

NAMESPACE = "unguard"
SIMULATOR = Workload(name="user-simulator", labels={"app.kubernetes.io/name": "user-simulator"})


def topology(**overrides: Any) -> dict[str, NetworkTopologyEntry]:
    """Build a topology declaring one internet destination for user-simulator.

    Override the carve-out list with ``excepts=``; ``except`` is a keyword.
    """
    destination = {
        "cidr": "0.0.0.0/0",
        "except": ["10.0.0.0/8", "169.254.169.254/32"],
        "ports": [80, 443],
        "protocol": "TCP",
    }
    if "excepts" in overrides:
        destination["except"] = overrides.pop("excepts")
    destination.update(overrides)
    return {
        "user-simulator": NetworkTopologyEntry.model_validate({"allowed_egress_to": [destination]})
    }


def default_deny() -> dict:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "default-deny-all", "namespace": NAMESPACE},
        "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
    }


def simulator_policy(egress: list[dict]) -> dict:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "netpol-user-simulator", "namespace": NAMESPACE},
        "spec": {
            "podSelector": {"matchLabels": {"app.kubernetes.io/name": "user-simulator"}},
            "policyTypes": ["Egress"],
            "egress": egress,
        },
    }


DNS_ONLY = [{"ports": [{"port": 53, "protocol": "UDP"}]}]


class TestFindExternalGaps:
    """The gap that a pod-to-pod reachability model cannot see."""

    def test_dns_only_egress_leaves_both_declared_ports_as_gaps(self):
        policies = [default_deny(), simulator_policy(DNS_ONLY)]

        gaps = find_external_gaps(policies, [SIMULATOR], topology())

        assert sorted(g.port for g in gaps) == [80, 443]
        assert all(g.workload == "user-simulator" for g in gaps)

    def test_matching_ipblock_rule_closes_the_gap(self):
        rule = {
            "to": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}}],
            "ports": [{"port": 80, "protocol": "TCP"}, {"port": 443, "protocol": "TCP"}],
        }
        policies = [default_deny(), simulator_policy([*DNS_ONLY, rule])]

        assert find_external_gaps(policies, [SIMULATOR], topology()) == []

    def test_wider_rule_cidr_satisfies_a_narrower_declaration(self):
        rule = {
            "to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}],
            "ports": [{"port": 443, "protocol": "TCP"}],
        }
        policies = [default_deny(), simulator_policy([rule])]
        declared = topology(cidr="93.184.216.0/24", excepts=[], ports=[443])

        assert find_external_gaps(policies, [SIMULATOR], declared) == []

    def test_except_entry_overlapping_the_declaration_reopens_the_gap(self):
        rule = {
            "to": [{"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8"]}}],
            "ports": [{"port": 443, "protocol": "TCP"}],
        }
        policies = [default_deny(), simulator_policy([rule])]
        declared = topology(cidr="10.1.0.0/16", excepts=[], ports=[443])

        gaps = find_external_gaps(policies, [SIMULATOR], declared)

        assert [g.cidr for g in gaps] == ["10.1.0.0/16"]

    def test_no_governing_egress_policy_means_no_gap(self):
        """Without a default-deny nothing restricts egress, so nothing is severed."""
        assert find_external_gaps([], [SIMULATOR], topology()) == []

    def test_pod_name_resolves_to_its_workload_declaration(self):
        """The live validator supplies pod names, not workload names."""
        pod = Workload(
            name="user-simulator-29001234-x7k2p",
            labels={"app.kubernetes.io/name": "user-simulator"},
        )
        policies = [default_deny(), simulator_policy(DNS_ONLY)]

        assert len(find_external_gaps(policies, [pod], topology())) == 2

    def test_declaration_for_absent_workload_is_reported_not_raised(self):
        other = Workload(name="frontend", labels={"app.kubernetes.io/name": "frontend"})

        assert find_external_gaps([default_deny()], [other], topology()) == []
        assert unmatched_declarations([other], topology()) == ["user-simulator"]
        assert unmatched_declarations([SIMULATOR], topology()) == []


class TestCloseExternalGaps:
    """The deterministic guarantee that does not depend on the model complying."""

    def test_rule_added_when_the_model_omitted_it(self):
        docs = [default_deny(), simulator_policy(DNS_ONLY)]

        closed = close_external_gaps(docs, [SIMULATOR], topology(), NAMESPACE)

        assert sorted(g.port for g in closed) == [80, 443]
        added = docs[1]["spec"]["egress"][-1]
        assert added["to"] == [
            {"ipBlock": {"cidr": "0.0.0.0/0", "except": ["10.0.0.0/8", "169.254.169.254/32"]}}
        ]
        assert added["ports"] == [
            {"port": 80, "protocol": "TCP"},
            {"port": 443, "protocol": "TCP"},
        ]
        assert find_external_gaps(docs, [SIMULATOR], topology()) == []

    def test_second_pass_over_its_own_output_changes_nothing(self):
        docs = [default_deny(), simulator_policy(DNS_ONLY)]
        close_external_gaps(docs, [SIMULATOR], topology(), NAMESPACE)
        before = [dict(d) for d in docs]

        assert close_external_gaps(docs, [SIMULATOR], topology(), NAMESPACE) == []
        assert docs == before

    def test_default_deny_is_never_widened(self):
        """Adding the rule to the namespace-wide policy would grant it to every pod."""
        docs = [default_deny()]

        close_external_gaps(docs, [SIMULATOR], topology(), NAMESPACE)

        assert docs[0]["spec"].get("egress") is None
        assert len(docs) == 2
        created = docs[1]
        assert created["kind"] == "NetworkPolicy"
        assert created["metadata"]["name"] == "user-simulator-external-egress"
        assert created["metadata"]["namespace"] == NAMESPACE
        assert created["metadata"]["labels"]["app.kubernetes.io/managed-by"] == "kimera"
        assert created["spec"]["podSelector"]["matchLabels"] == SIMULATOR.labels
        assert find_external_gaps(docs, [SIMULATOR], topology()) == []

    def test_only_the_missing_port_is_added(self):
        """The emitted rule must permit what was reported missing, and nothing more."""
        permitted_80 = {
            "to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}],
            "ports": [{"port": 80, "protocol": "TCP"}],
        }
        docs = [default_deny(), simulator_policy([permitted_80])]

        closed = close_external_gaps(docs, [SIMULATOR], topology(), NAMESPACE)

        assert [g.port for g in closed] == [443]
        assert docs[1]["spec"]["egress"][-1]["ports"] == [{"port": 443, "protocol": "TCP"}]

    def test_nothing_added_without_a_declaration(self):
        docs = [default_deny(), simulator_policy(DNS_ONLY)]
        undeclared = {"user-simulator": NetworkTopologyEntry()}

        assert close_external_gaps(docs, [SIMULATOR], undeclared, NAMESPACE) == []
        assert len(docs) == 2

    @pytest.mark.parametrize(
        "declared_port,rule_port,expect_gap", [(443, 443, False), (443, 80, True)]
    )
    def test_port_must_match(self, declared_port, rule_port, expect_gap):
        rule = {
            "to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}],
            "ports": [{"port": rule_port, "protocol": "TCP"}],
        }
        policies = [default_deny(), simulator_policy([rule])]

        gaps = find_external_gaps(policies, [SIMULATOR], topology(ports=[declared_port]))

        assert bool(gaps) is expect_gap


class TestRuleMatching:
    """What the rule matcher must read before calling a destination permitted."""

    @pytest.mark.parametrize(
        "rule_protocol,expect_gap", [("TCP", False), (None, False), ("UDP", True)]
    )
    def test_protocol_must_match_the_declaration(self, rule_protocol, expect_gap):
        """A missing protocol on a port entry is TCP, not a wildcard."""
        port_spec: dict[str, Any] = {"port": 443}
        if rule_protocol is not None:
            port_spec["protocol"] = rule_protocol
        rule = {"to": [{"ipBlock": {"cidr": "0.0.0.0/0"}}], "ports": [port_spec]}
        policies = [default_deny(), simulator_policy([rule])]

        gaps = find_external_gaps(policies, [SIMULATOR], topology(ports=[443], protocol="TCP"))

        assert bool(gaps) is expect_gap

    def test_empty_peer_list_permits_every_destination(self):
        """``to: []`` means allow-all, exactly as an absent ``to`` does."""
        rule = {"to": [], "ports": [{"port": 443, "protocol": "TCP"}]}
        policies = [default_deny(), simulator_policy([rule])]

        assert find_external_gaps(policies, [SIMULATOR], topology(ports=[443])) == []

    def test_two_peers_covering_the_declaration_between_them(self):
        """Neither half covers 203.0.113.0/24 alone; their union does."""
        rule = {
            "to": [
                {"ipBlock": {"cidr": "203.0.113.0/25"}},
                {"ipBlock": {"cidr": "203.0.113.128/25"}},
            ],
            "ports": [{"port": 443, "protocol": "TCP"}],
        }
        policies = [default_deny(), simulator_policy([rule])]
        declared = topology(cidr="203.0.113.0/24", excepts=[], ports=[443])

        assert find_external_gaps(policies, [SIMULATOR], declared) == []

    def test_partial_peer_coverage_is_still_a_gap(self):
        rule = {
            "to": [{"ipBlock": {"cidr": "203.0.113.0/25"}}],
            "ports": [{"port": 443, "protocol": "TCP"}],
        }
        policies = [default_deny(), simulator_policy([rule])]
        declared = topology(cidr="203.0.113.0/24", excepts=[], ports=[443])

        assert [g.cidr for g in find_external_gaps(policies, [SIMULATOR], declared)] == [
            "203.0.113.0/24"
        ]


class TestPolicyNaming:
    """Generated names must survive the 63-character RFC1123 limit."""

    def _created_name(self, workload: Workload) -> str:
        docs: list[dict] = [default_deny()]
        entry = topology()["user-simulator"]
        close_external_gaps(docs, [workload], {workload.name: entry}, NAMESPACE)
        return str(docs[1]["metadata"]["name"])

    def test_long_workloads_sharing_a_prefix_get_distinct_names(self):
        # The names differ only past character 63, so truncation alone collides.
        prefix = "unguard-very-long-workload-name-that-runs-well-past-the-name-limit"
        labels = {"app.kubernetes.io/name": "user-simulator"}
        first = self._created_name(Workload(name=f"{prefix}-alpha", labels=labels))
        second = self._created_name(Workload(name=f"{prefix}-beta", labels=labels))

        assert first != second
        for name in (first, second):
            assert len(name) <= 63
            assert not name.endswith("-")
            assert all(c.islower() or c.isdigit() or c == "-" for c in name)

    def test_short_name_is_left_alone(self):
        assert self._created_name(SIMULATOR) == "user-simulator-external-egress"


class TestGeneratorIntegration:
    """The shipped unguard profile, through the generator's own post-processing."""

    def _generator(self):
        from unittest.mock import MagicMock, patch

        from kimera.application.config.loader import ConfigLoader
        from kimera.container.core.k8s_client import K8sClient
        from kimera.container.core.logger import SecurityLogger
        from kimera.container.remediations.generator import LLMRemediationGenerator

        with (
            patch("kimera.container.core.k8s_client.config") as mock_config,
            patch("kimera.container.core.k8s_client.client"),
        ):
            config_exception = type("ConfigException", (Exception,), {})
            mock_config.ConfigException = config_exception
            mock_config.load_incluster_config.side_effect = config_exception("Not in cluster")
            logger = MagicMock(spec=SecurityLogger)
            k8s = K8sClient(namespace=NAMESPACE, logger=logger)

        topology_config = ConfigLoader().load(profile="unguard").network_topology
        return LLMRemediationGenerator(k8s, logger, network_topology=topology_config), logger

    def test_unguard_profile_declaration_survives_a_model_that_omits_it(self):
        """The blog's claim is that Kimera produced these policies, so the guarantee
        cannot rest on the model having complied."""
        import yaml

        generator, logger = self._generator()
        context = {
            "cronjobs": {
                "unguard-user-simulator": {
                    "labels": {"app.kubernetes.io/name": "user-simulator"},
                    "ports": [],
                }
            }
        }
        generated = yaml.safe_dump_all([default_deny()])

        closed = yaml.safe_load_all(generator._close_gaps(generated, context))
        policies = [d for d in closed if d]

        added = [p for p in policies if p["metadata"]["name"].endswith("-external-egress")]
        assert len(added) == 1
        rule = added[0]["spec"]["egress"][0]
        assert rule["to"][0]["ipBlock"]["cidr"] == "0.0.0.0/0"
        assert "169.254.169.254/32" in rule["to"][0]["ipBlock"]["except"]
        assert [p["port"] for p in rule["ports"]] == [80, 443]
        assert logger.warning.called

    def test_no_other_workload_gains_external_egress(self):
        import yaml

        generator, _ = self._generator()
        context = {
            "deployments": {
                "unguard-frontend": {
                    "labels": {"app.kubernetes.io/name": "frontend"},
                    "ports": [8000],
                }
            }
        }

        result = generator._close_gaps(yaml.safe_dump_all([default_deny()]), context)

        assert "ipBlock" not in result
