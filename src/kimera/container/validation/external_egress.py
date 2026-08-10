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
from hashlib import blake2b
from ipaddress import IPv4Network, IPv6Network, ip_network
from typing import Any

from ...application.config.schemas import ExternalEgressDestination, NetworkTopologyEntry
from .reachability import Workload, _governs, _ports_permit, _selector_matches

MANAGED_BY_LABEL = "app.kubernetes.io/managed-by"
TOOLKIT_NAME = "kimera"
POLICY_NAME_SUFFIX = "-external-egress"
MAX_RESOURCE_NAME_LENGTH = 63
NAME_DIGEST_BYTES = 4

IPNetwork = IPv4Network | IPv6Network


@dataclass(frozen=True)
class ExternalGap:
    """A declared external destination that no egress rule in the set permits."""

    workload: str
    cidr: str
    port: int
    protocol: str

    def describe(self) -> str:
        """Return a one-line explanation naming the workload and destination."""
        return (
            f"{self.workload} declares egress to {self.cidr}:{self.port}/{self.protocol} "
            "but no egress rule in the policy set permits it"
        )


def _parse(cidr: str) -> IPNetwork | None:
    try:
        return ip_network(cidr)
    except ValueError:
        return None


def _contains(outer: IPNetwork, inner: IPNetwork) -> bool:
    if outer.version != inner.version:
        return False
    return inner.subnet_of(outer)  # type: ignore[arg-type]  # versions checked above


def _overlaps(left: IPNetwork, right: IPNetwork) -> bool:
    if left.version != right.version:
        return False
    return left.overlaps(right)


def effective_range(cidr: IPNetwork, excluded: list[IPNetwork]) -> list[IPNetwork]:
    """Return ``cidr`` minus ``excluded`` as a list of disjoint networks.

    A declaration and a rule are both a CIDR with carve-outs, so comparing the
    CIDRs alone would call a rule that excludes the declared range a match.
    """
    remaining = [cidr]
    for carve_out in excluded:
        narrowed: list[IPNetwork] = []
        for net in remaining:
            if not _overlaps(net, carve_out):
                narrowed.append(net)
            elif _contains(carve_out, net):
                continue  # the carve-out swallows this network entirely
            else:
                narrowed.extend(net.address_exclude(carve_out))  # type: ignore[arg-type]
        remaining = narrowed
    return remaining


def _permitted_networks(peers: list[dict[str, Any]]) -> list[IPNetwork]:
    """Every network the rule's ipBlock peers permit, carve-outs applied."""
    permitted: list[IPNetwork] = []
    for peer in peers:
        block = peer.get("ipBlock")
        if not block:
            continue
        rule_net = _parse(block.get("cidr", ""))
        if rule_net is None:
            continue
        rule_excepts = [net for net in (_parse(c) for c in block.get("except") or []) if net]
        permitted.extend(effective_range(rule_net, rule_excepts))
    return permitted


def rule_permits(
    rule: dict[str, Any], declared: list[IPNetwork], port: int, protocol: str = "TCP"
) -> bool:
    """Whether an egress rule reaches every declared network on ``port``/``protocol``."""
    peers = rule.get("to")
    # An absent or empty peer list applies to every destination, external ones included.
    if peers:
        # A declared network may need several peers together to cover it, so the
        # permitted set is subtracted from it as a whole.
        permitted = _permitted_networks(peers)
        if any(effective_range(net, permitted) for net in declared):
            return False
    return _ports_permit(rule.get("ports"), port, protocol)


def _policies_permit(
    policies: list[dict[str, Any]],
    workload: Workload,
    declared: list[IPNetwork],
    port: int,
    protocol: str,
) -> bool:
    governing = [p for p in policies if _governs(p, workload, "Egress")]
    if not governing:
        return True
    return any(
        any(
            rule_permits(rule, declared, port, protocol)
            for rule in (p.get("spec") or {}).get("egress") or []
        )
        for p in governing
    )


def _declared_range(destination: ExternalEgressDestination) -> list[IPNetwork]:
    cidr = _parse(str(destination.cidr))
    if cidr is None:
        return []
    excluded = [net for net in (_parse(str(c)) for c in destination.except_) if net]
    return effective_range(cidr, excluded)


def _match_workload(name: str, workloads: list[Workload]) -> Workload | None:
    """Resolve a topology key to a workload.

    The generator supplies workload names, the live validator supplies pod names,
    so an exact match is tried before the `<workload>-<hash>` pod naming convention.
    """
    for workload in workloads:
        if workload.name == name:
            return workload
    for workload in workloads:
        if workload.name.startswith(f"{name}-"):
            return workload
    return None


def find_external_gaps(
    policies: list[dict[str, Any]],
    workloads: list[Workload],
    topology: dict[str, NetworkTopologyEntry],
) -> list[ExternalGap]:
    """Return every declared external destination the policy set does not permit."""
    gaps: list[ExternalGap] = []

    for name, entry in topology.items():
        if not entry.allowed_egress_to:
            continue
        workload = _match_workload(name, workloads)
        if workload is None:
            continue
        for destination in entry.allowed_egress_to:
            declared = _declared_range(destination)
            if not declared:
                continue
            for port in destination.ports:
                if _policies_permit(policies, workload, declared, port, destination.protocol):
                    continue
                gaps.append(
                    ExternalGap(
                        workload=name,
                        cidr=str(destination.cidr),
                        port=port,
                        protocol=destination.protocol,
                    )
                )
    return gaps


def unmatched_declarations(
    workloads: list[Workload],
    topology: dict[str, NetworkTopologyEntry],
) -> list[str]:
    """Return topology keys declaring external egress that match no workload."""
    return [
        name
        for name, entry in topology.items()
        if entry.allowed_egress_to and _match_workload(name, workloads) is None
    ]


def egress_rule(
    destination: ExternalEgressDestination, ports: list[int] | None = None
) -> dict[str, Any]:
    """Build the egress rule that permits one declared external destination.

    Args:
        destination: The declared destination.
        ports: Ports to emit, defaulting to every port the destination declares.
    """
    block: dict[str, Any] = {"cidr": str(destination.cidr)}
    if destination.except_:
        block["except"] = [str(net) for net in destination.except_]
    return {
        "to": [{"ipBlock": block}],
        "ports": [
            {"port": port, "protocol": destination.protocol}
            for port in (destination.ports if ports is None else ports)
        ],
    }


def _policy_name(workload_name: str) -> str:
    """Name the workload's external-egress policy, uniquely even when truncated.

    Two workloads sharing a long prefix would otherwise collide on one name.
    """
    name = f"{workload_name}{POLICY_NAME_SUFFIX}"
    if len(name) <= MAX_RESOURCE_NAME_LENGTH:
        return name
    digest = blake2b(workload_name.encode(), digest_size=NAME_DIGEST_BYTES).hexdigest()
    keep = MAX_RESOURCE_NAME_LENGTH - len(digest) - 1
    return f"{name[:keep].rstrip('-')}-{digest}"


def _new_policy(workload: Workload, namespace: str) -> dict[str, Any]:
    name = _policy_name(workload.name)
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {MANAGED_BY_LABEL: TOOLKIT_NAME},
        },
        "spec": {
            "podSelector": {"matchLabels": dict(workload.labels)},
            "policyTypes": ["Egress"],
            "egress": [],
        },
    }


def close_external_gaps(
    docs: list[dict[str, Any]],
    workloads: list[Workload],
    topology: dict[str, NetworkTopologyEntry],
    namespace: str,
) -> list[ExternalGap]:
    """Add egress rules so every declared external destination is permitted.

    Mutates ``docs`` in place, appending a workload-scoped NetworkPolicy when the
    only policy governing that workload's egress is a namespace-wide default-deny.
    Widening the default-deny instead would grant the destination to every pod in
    the namespace.

    Returns:
        The gaps that were closed.
    """
    closed: list[ExternalGap] = []

    for name, entry in topology.items():
        if not entry.allowed_egress_to:
            continue
        workload = _match_workload(name, workloads)
        if workload is None:
            continue

        for destination in entry.allowed_egress_to:
            declared = _declared_range(destination)
            if not declared:
                continue
            missing = [
                port
                for port in destination.ports
                if not _policies_permit(
                    [d for d in docs if d.get("kind") == "NetworkPolicy"],
                    workload,
                    declared,
                    port,
                    destination.protocol,
                )
            ]
            if not missing:
                continue

            target = _egress_policy_for(docs, workload)
            if target is None:
                target = _new_policy(workload, namespace)
                docs.append(target)
            spec = target.setdefault("spec", {})
            policy_types = spec.setdefault("policyTypes", [])
            if "Egress" not in policy_types:
                policy_types.append("Egress")
            spec.setdefault("egress", []).append(egress_rule(destination, missing))

            closed.extend(
                ExternalGap(
                    workload=name,
                    cidr=str(destination.cidr),
                    port=port,
                    protocol=destination.protocol,
                )
                for port in missing
            )

    return closed


def _egress_policy_for(docs: list[dict[str, Any]], workload: Workload) -> dict[str, Any] | None:
    """Return the workload-scoped egress policy, never a namespace-wide default-deny."""
    for doc in docs:
        if doc.get("kind") != "NetworkPolicy":
            continue
        selector = (doc.get("spec") or {}).get("podSelector") or {}
        if not selector.get("matchLabels"):
            continue
        if _selector_matches(selector, workload) and _governs(doc, workload, "Egress"):
            return doc
    return None
