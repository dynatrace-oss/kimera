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

from dataclasses import dataclass
from typing import Any

# A NetworkPolicy permits a flow only when the source's egress and the destination's
# ingress both allow it; one side alone silently severs the flow it claims to permit.


@dataclass(frozen=True)
class Workload:
    """A pod-producing workload reduced to the labels a podSelector can match."""

    name: str
    labels: dict[str, str]


@dataclass(frozen=True)
class Gap:
    """A flow one side of a policy set declares and the other side denies."""

    source: str
    destination: str
    port: int
    protocol: str
    declared_by: str
    destination_selector: dict[str, str]
    # Which side denies the flow. Defaults to "egress" because that is the only
    # direction close_gaps can remedy: it appends egress rules.
    denied_by: str = "egress"

    def describe(self) -> str:
        """Return a one-line explanation naming both sides of the mismatch."""
        if self.denied_by == "ingress":
            return (
                f"{self.source} -> {self.destination}:{self.port}/{self.protocol} "
                f"is allowed by egress in '{self.declared_by}' but denied by "
                f"{self.destination}'s ingress rules"
            )
        return (
            f"{self.source} -> {self.destination}:{self.port}/{self.protocol} "
            f"is allowed by ingress in '{self.declared_by}' but denied by "
            f"{self.source}'s egress rules"
        )


def _selector_matches(selector: dict[str, Any] | None, workload: Workload) -> bool:
    if selector is None:
        return False
    match_labels = selector.get("matchLabels") or {}
    return all(workload.labels.get(key) == value for key, value in match_labels.items())


def peer_matches(peer: dict[str, Any], workload: Workload) -> bool:
    """Whether a policy peer addresses this workload."""
    # namespaceSelector/ipBlock peers address other namespaces or CIDRs, never a
    # workload in this one.
    if "namespaceSelector" in peer or "ipBlock" in peer:
        return False
    return _selector_matches(peer.get("podSelector"), workload)


def _governs(policy: dict[str, Any], workload: Workload, direction: str) -> bool:
    spec = policy.get("spec") or {}
    if direction not in (spec.get("policyTypes") or []):
        return False
    return _selector_matches(spec.get("podSelector") or {"matchLabels": {}}, workload)


def _ports_permit(ports: list[dict[str, Any]] | None, port: int, protocol: str) -> bool:
    """Whether a rule's port list covers ``port`` on ``protocol``.

    An absent or empty port list covers every port, and a port entry without a
    protocol means TCP, both per the NetworkPolicy spec.
    """
    if not ports:
        return True
    return any(
        p.get("port") == port and str(p.get("protocol") or "TCP").upper() == protocol.upper()
        for p in ports
    )


def rules_permit(
    rules: list[dict[str, Any]] | None,
    peer_key: str,
    other: Workload,
    port: int,
    protocol: str = "TCP",
) -> bool:
    """Whether any rule permits ``other`` on ``port``/``protocol`` under the peer key."""
    for rule in rules or []:
        peers = rule.get(peer_key)
        # An absent or empty peer list applies to every destination.
        if peers and not any(peer_matches(p, other) for p in peers):
            continue
        if _ports_permit(rule.get("ports"), port, protocol):
            return True
    return False


def egress_permits(
    source: Workload,
    destination: Workload,
    port: int,
    policies: list[dict[str, Any]],
    protocol: str = "TCP",
) -> bool:
    """Whether ``source`` may open a connection to ``destination`` on ``port``."""
    governing = [p for p in policies if _governs(p, source, "Egress")]
    if not governing:
        return True
    return any(
        rules_permit((p.get("spec") or {}).get("egress"), "to", destination, port, protocol)
        for p in governing
    )


def ingress_permits(
    source: Workload,
    destination: Workload,
    port: int,
    policies: list[dict[str, Any]],
    protocol: str = "TCP",
) -> bool:
    """Whether ``destination`` accepts a connection from ``source`` on ``port``."""
    governing = [p for p in policies if _governs(p, destination, "Ingress")]
    if not governing:
        return True
    return any(
        rules_permit((p.get("spec") or {}).get("ingress"), "from", source, port, protocol)
        for p in governing
    )


def find_gaps(policies: list[dict[str, Any]], workloads: list[Workload]) -> list[Gap]:
    """Return every flow declared by an ingress rule that egress rules deny."""
    gaps: list[Gap] = []
    seen: set[tuple[str, str, int]] = set()

    for policy in policies:
        spec = policy.get("spec") or {}
        selector = spec.get("podSelector") or {"matchLabels": {}}
        destinations = [w for w in workloads if _selector_matches(selector, w)]
        if not destinations:
            continue

        for rule in spec.get("ingress") or []:
            port_specs = rule.get("ports") or []
            for peer in rule.get("from") or []:
                sources = [w for w in workloads if peer_matches(peer, w)]
                for source in sources:
                    for destination in destinations:
                        if source.name == destination.name:
                            continue
                        for port_spec in port_specs:
                            port = port_spec.get("port")
                            if not isinstance(port, int):
                                continue
                            key = (source.name, destination.name, port)
                            if key in seen:
                                continue
                            protocol = port_spec.get("protocol") or "TCP"
                            if egress_permits(source, destination, port, policies, protocol):
                                continue
                            seen.add(key)
                            gaps.append(
                                Gap(
                                    source=source.name,
                                    destination=destination.name,
                                    port=port,
                                    protocol=protocol,
                                    declared_by=(policy.get("metadata") or {}).get("name", "?"),
                                    destination_selector=dict(selector.get("matchLabels") or {}),
                                )
                            )
    return gaps


def find_ingress_gaps(policies: list[dict[str, Any]], workloads: list[Workload]) -> list[Gap]:
    """Return every flow declared by an egress rule that ingress rules deny.

    The converse of ``find_gaps``, and reported rather than closed. A missing
    ingress rule is the destination's decision about who may reach it, so
    inferring one would grant access nobody declared; the egress side is the only
    direction ``close_gaps`` may safely widen.
    """
    gaps: list[Gap] = []
    seen: set[tuple[str, str, int]] = set()

    for policy in policies:
        spec = policy.get("spec") or {}
        selector = spec.get("podSelector") or {"matchLabels": {}}
        sources = [w for w in workloads if _selector_matches(selector, w)]
        if not sources:
            continue

        for rule in spec.get("egress") or []:
            port_specs = rule.get("ports") or []
            for peer in rule.get("to") or []:
                destinations = [w for w in workloads if peer_matches(peer, w)]
                for source in sources:
                    for destination in destinations:
                        if source.name == destination.name:
                            continue
                        for port_spec in port_specs:
                            port = port_spec.get("port")
                            if not isinstance(port, int):
                                continue
                            key = (source.name, destination.name, port)
                            if key in seen:
                                continue
                            protocol = port_spec.get("protocol") or "TCP"
                            if ingress_permits(source, destination, port, policies, protocol):
                                continue
                            seen.add(key)
                            gaps.append(
                                Gap(
                                    source=source.name,
                                    destination=destination.name,
                                    port=port,
                                    protocol=protocol,
                                    declared_by=(policy.get("metadata") or {}).get("name", "?"),
                                    destination_selector=dict(selector.get("matchLabels") or {}),
                                    denied_by="ingress",
                                )
                            )
    return gaps


def close_gaps(policies: list[dict[str, Any]], workloads: list[Workload]) -> list[Gap]:
    """Append egress rules so every declared ingress flow is permitted end to end.

    Mutates ``policies`` in place. The destination selector is copied from the
    destination policy's own ``podSelector``, so no label is ever inferred.

    Returns:
        The gaps that were closed.
    """
    closed: list[Gap] = []

    for gap in find_gaps(policies, workloads):
        source = next((w for w in workloads if w.name == gap.source), None)
        if source is None:
            continue

        # Prefer the workload's own policy over a blanket default-deny, so the added
        # rule stays scoped to that workload.
        governing = [p for p in policies if _governs(p, source, "Egress")]
        specific = [
            p
            for p in governing
            if ((p.get("spec") or {}).get("podSelector") or {}).get("matchLabels")
        ]
        candidates = specific or governing
        if not candidates:
            continue

        spec = candidates[0].setdefault("spec", {})
        spec.setdefault("egress", []).append(
            {
                "to": [{"podSelector": {"matchLabels": dict(gap.destination_selector)}}],
                "ports": [{"port": gap.port, "protocol": gap.protocol}],
            }
        )
        closed.append(gap)

    return closed
