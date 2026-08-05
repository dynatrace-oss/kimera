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

from kimera.container.validation.reachability import (
    Workload,
    close_gaps,
    egress_permits,
    find_gaps,
)

# Reproduces the measured cns-zero defect: the Bitnami MariaDB subchart does not
# carry app.kubernetes.io/part-of, which every generated egress rule selects on.
AUTH = Workload(
    name="unguard-user-auth-service",
    labels={"app.kubernetes.io/name": "user-auth-service", "app.kubernetes.io/part-of": "unguard"},
)
MARIADB = Workload(
    name="unguard-mariadb-0",
    labels={"app.kubernetes.io/name": "mariadb", "app.kubernetes.io/instance": "unguard-mariadb"},
)
REDIS = Workload(
    name="unguard-redis",
    labels={"app.kubernetes.io/name": "redis", "app.kubernetes.io/part-of": "unguard"},
)


def _policy(name: str, selector: dict[str, str], **rules: Any) -> dict[str, Any]:
    spec: dict[str, Any] = {
        "podSelector": {"matchLabels": selector},
        "policyTypes": ["Ingress", "Egress"],
    }
    spec.update(rules)
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name},
        "spec": spec,
    }


def _part_of_egress() -> list[dict[str, Any]]:
    return [{"to": [{"podSelector": {"matchLabels": {"app.kubernetes.io/part-of": "unguard"}}}]}]


def _auth_policy() -> dict[str, Any]:
    return _policy(
        "netpol-user-auth-service",
        {"app.kubernetes.io/name": "user-auth-service"},
        egress=_part_of_egress(),
    )


def _mariadb_policy() -> dict[str, Any]:
    return _policy(
        "netpol-mariadb",
        {"app.kubernetes.io/name": "mariadb", "app.kubernetes.io/instance": "unguard-mariadb"},
        ingress=[
            {
                "from": [
                    {
                        "podSelector": {
                            "matchLabels": {"app.kubernetes.io/name": "user-auth-service"}
                        }
                    }
                ],
                "ports": [{"port": 3306, "protocol": "TCP"}],
            }
        ],
        egress=_part_of_egress(),
    )


class TestGapDetection:
    def test_ingress_allowed_but_egress_denied_is_a_gap(self):
        """The destination lacks part-of, so the source's egress rule cannot reach it."""
        policies = [_auth_policy(), _mariadb_policy()]
        gaps = find_gaps(policies, [AUTH, MARIADB])

        assert len(gaps) == 1
        assert gaps[0].source == "unguard-user-auth-service"
        assert gaps[0].destination == "unguard-mariadb-0"
        assert gaps[0].port == 3306
        assert gaps[0].destination_selector == {
            "app.kubernetes.io/name": "mariadb",
            "app.kubernetes.io/instance": "unguard-mariadb",
        }

    def test_destination_carrying_the_shared_label_is_not_a_gap(self):
        """Redis has part-of, so the same egress rule already reaches it."""
        redis_policy = _policy(
            "netpol-redis",
            {"app.kubernetes.io/name": "redis"},
            ingress=[
                {
                    "from": [
                        {
                            "podSelector": {
                                "matchLabels": {"app.kubernetes.io/name": "user-auth-service"}
                            }
                        }
                    ],
                    "ports": [{"port": 6379, "protocol": "TCP"}],
                }
            ],
        )
        assert find_gaps([_auth_policy(), redis_policy], [AUTH, REDIS]) == []

    def test_unrestricted_source_has_no_gap(self):
        """A source no Egress policy selects is unrestricted, so nothing is severed."""
        policies = [_mariadb_policy()]
        assert find_gaps(policies, [AUTH, MARIADB]) == []

    def test_namespace_selector_peer_never_matches_local_workload(self):
        """A cross-namespace egress peer must not be credited with reaching a local pod."""
        auth = _policy(
            "netpol-user-auth-service",
            {"app.kubernetes.io/name": "user-auth-service"},
            egress=[
                {
                    "to": [
                        {
                            "namespaceSelector": {
                                "matchLabels": {"kubernetes.io/metadata.name": "data"}
                            }
                        }
                    ]
                }
            ],
        )
        assert not egress_permits(AUTH, MARIADB, 3306, [auth, _mariadb_policy()])


class TestGapClosing:
    def test_close_gaps_makes_the_flow_reachable(self):
        policies = [_auth_policy(), _mariadb_policy()]
        closed = close_gaps(policies, [AUTH, MARIADB])

        assert len(closed) == 1
        assert egress_permits(AUTH, MARIADB, 3306, policies)
        assert find_gaps(policies, [AUTH, MARIADB]) == []

    def test_added_rule_is_scoped_to_the_declared_port(self):
        """Closing 3306 must not open every other port to the database."""
        policies = [_auth_policy(), _mariadb_policy()]
        close_gaps(policies, [AUTH, MARIADB])

        assert not egress_permits(AUTH, MARIADB, 22, policies)

    def test_added_rule_lands_on_the_workload_policy_not_default_deny(self):
        """A blanket default-deny must not absorb a workload-scoped exception."""
        default_deny = {
            "kind": "NetworkPolicy",
            "metadata": {"name": "default-deny-all"},
            "spec": {"podSelector": {}, "policyTypes": ["Ingress", "Egress"]},
        }
        auth = _auth_policy()
        policies = [default_deny, auth, _mariadb_policy()]
        close_gaps(policies, [AUTH, MARIADB])

        assert "egress" not in default_deny["spec"]
        assert len(auth["spec"]["egress"]) == 2

    def test_closing_is_idempotent(self):
        policies = [_auth_policy(), _mariadb_policy()]
        close_gaps(policies, [AUTH, MARIADB])
        assert close_gaps(policies, [AUTH, MARIADB]) == []


@pytest.mark.parametrize(
    "port_spec,probe_port,reachable",
    [
        ({"port": 3306, "protocol": "TCP"}, 3306, True),
        ({"port": 3306, "protocol": "TCP"}, 3307, False),
    ],
)
def test_closed_gap_respects_port_boundaries(port_spec, probe_port, reachable):
    mariadb = _mariadb_policy()
    mariadb["spec"]["ingress"][0]["ports"] = [port_spec]
    policies = [_auth_policy(), mariadb]
    close_gaps(policies, [AUTH, MARIADB])

    assert egress_permits(AUTH, MARIADB, probe_port, policies) is reachable
