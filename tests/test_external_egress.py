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
