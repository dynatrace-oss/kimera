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

from dataclasses import dataclass, field
from ipaddress import ip_network
from typing import Any

import yaml

from ...application.config.schemas import ExternalEgressDestination, NetworkTopologyEntry
from ..core.logger import SecurityLogger
from ..validation.external_egress import egress_rule, rule_permits
from ..validation.reachability import Workload, peer_matches, rules_permit
from .exploit_findings import AttackPathRecord, FindingsDocument
from .finding_scope import DNS_PORT, Classification, classify, declared_dependencies

DNS_SELECTOR = {"k8s-app": "kube-dns"}
WORKLOAD_KINDS = ("deployments", "statefulsets", "cronjobs")
MANAGED_BY = {"app.kubernetes.io/managed-by": "kimera"}


@dataclass(frozen=True)
class Dependency:
    """A destination the source workload is declared to reach, and on which ports."""

    workload: Workload
    ports: list[int]


@dataclass
class TargetedPlan:
    """Everything a targeted policy set for one source workload is determined by."""

    source: Workload
    classification: Classification
    dependencies: list[Dependency] = field(default_factory=list)
    external: list[ExternalEgressDestination] = field(default_factory=list)
    workloads: dict[str, Workload] = field(default_factory=dict)


def workloads_from_context(context: dict[str, Any]) -> dict[str, Workload]:
    """Index every pod-producing workload in the cluster context by name."""
    return {
        name: Workload(name=name, labels=dict(info.get("labels") or {}))
        for kind in WORKLOAD_KINDS
        for name, info in (context.get(kind) or {}).items()
    }


def build_plan(
    document: FindingsDocument,
    context: dict[str, Any],
    topology: dict[str, NetworkTopologyEntry],
    namespace: str,
) -> TargetedPlan:
    """Resolve findings against the live namespace into a plan.

    Raises:
        ValueError: if the findings were recorded elsewhere or their source
            workload is gone — a set built from either would target the wrong pods.
    """
    if document.namespace != namespace:
        raise ValueError(
            f"Findings were recorded in namespace '{document.namespace}', "
            f"but generation targets '{namespace}'"
        )

    workloads = workloads_from_context(context)
    source = workloads.get(document.source_workload)
    if source is None:
        raise ValueError(
            f"Findings name source workload '{document.source_workload}', "
            f"which is not present in namespace '{namespace}'"
        )

    entry = topology.get(document.source_workload)
    return TargetedPlan(
        source=source,
        classification=classify(document, source.labels, topology, set(workloads)),
        dependencies=[
            Dependency(workload=workloads[name], ports=_target_ports(name, context))
            for name in sorted(declared_dependencies(source.labels, topology))
            if name in workloads
        ],
        external=list(entry.allowed_egress_to) if entry else [],
        workloads=workloads,
    )


def enforce(
    docs: list[dict[str, Any]], plan: TargetedPlan, namespace: str
) -> tuple[list[dict[str, Any]], list[str]]:
    """Reduce an emitted set to the policies the finding justifies.

    Egress is replaced with the plan's allow-list rather than edited rule by rule:
    in targeted scope the correct set is fully determined by the plan.
    """
    deviations: list[str] = []
    kept: list[dict[str, Any]] = []

    for doc in docs:
        rejection = _rejection(doc, plan.source)
        if rejection:
            deviations.append(rejection)
        else:
            kept.append(doc)

    if not kept:
        deviations.append(f"no policy selecting {plan.source.name} was emitted — one was built")
        kept = [_new_policy(plan.source, namespace)]

    policy = kept[0]
    deviations.extend(_egress_deviations(policy, plan))

    spec = policy.setdefault("spec", {})
    spec["egress"] = _allowed_egress(plan)
    spec["policyTypes"] = sorted(set(spec.get("policyTypes") or []) | {"Egress"})
    return kept, deviations


def apply_scope(yaml_text: str, plan: TargetedPlan, namespace: str, logger: SecurityLogger) -> str:
    """Enforce the plan on generated YAML and report every correction made."""
    docs = [doc for doc in yaml.safe_load_all(yaml_text) if doc]
    kept, deviations = enforce(docs, plan, namespace)
    for deviation in deviations:
        logger.warning(f"Targeted scope: {deviation}")
    return str(yaml.safe_dump_all(kept, default_flow_style=False, sort_keys=False))


def _rejection(doc: dict[str, Any], source: Workload) -> str | None:
    """Why this document has no place in a targeted set, or None if it belongs."""
    name = (doc.get("metadata") or {}).get("name", "<unnamed>")
    if doc.get("kind") != "NetworkPolicy":
        return f"dropped {doc.get('kind', 'unknown')}/{name}: not a NetworkPolicy"
    selector = (doc.get("spec") or {}).get("podSelector") or {}
    if not selector.get("matchLabels"):
        return f"dropped {name}: selects every pod in the namespace"
    if not peer_matches({"podSelector": selector}, source):
        return f"dropped {name}: selects a workload other than {source.name}"
    return None


def _egress_deviations(policy: dict[str, Any], plan: TargetedPlan) -> list[str]:
    """Report what the emitted egress got wrong, before it is replaced."""
    rules = (policy.get("spec") or {}).get("egress") or []
    deviations = [
        f"{scoped.scope} path {scoped.path.host}:{scoped.path.port} was permitted — removed"
        for scoped in plan.classification.deny + plan.classification.review
        if _permits(rules, scoped.path, plan.workloads)
    ]
    for dependency in plan.dependencies:
        for port in dependency.ports:
            if not rules_permit(rules, "to", dependency.workload, port):
                deviations.append(
                    f"declared dependency {dependency.workload.name}:{port} was severed — restored"
                )
    return deviations


def _permits(
    rules: list[dict[str, Any]], path: AttackPathRecord, workloads: dict[str, Workload]
) -> bool:
    """Whether any emitted egress rule permits an observed path.

    An address is checked against ``ipBlock`` peers, a name against podSelectors.
    A name matching no workload can only be permitted by a rule with no peer list.
    """
    address = _address(path.host)
    if address is not None:
        return any(rule_permits(rule, [address], path.port) for rule in rules)
    destination = workloads.get(path.host.split(".")[0], Workload(name=path.host, labels={}))
    return rules_permit(rules, "to", destination, path.port)


def _address(host: str) -> Any:
    try:
        return ip_network(host)
    except ValueError:
        return None


def _allowed_egress(plan: TargetedPlan) -> list[dict[str, Any]]:
    """DNS, the declared dependencies and the declared external destinations. Nothing else."""
    rules: list[dict[str, Any]] = [
        {
            "to": [{"namespaceSelector": {}, "podSelector": {"matchLabels": DNS_SELECTOR}}],
            "ports": [{"protocol": "UDP", "port": DNS_PORT}, {"protocol": "TCP", "port": DNS_PORT}],
        }
    ]
    for dependency in plan.dependencies:
        rule: dict[str, Any] = {
            "to": [{"podSelector": {"matchLabels": dependency.workload.labels}}]
        }
        if dependency.ports:
            rule["ports"] = [{"protocol": "TCP", "port": port} for port in dependency.ports]
        rules.append(rule)
    return rules + [egress_rule(dest) for dest in plan.external]


def _target_ports(name: str, context: dict[str, Any]) -> list[int]:
    """Ports the destination's pods listen on.

    A policy matches the pod port, not the Service port: traffic to a Service is
    translated before the rule is evaluated, so a rule naming the Service's own
    port permits nothing. The Service is read only for its ``targetPort``, and a
    named one resolves through the workload's container ports.
    """
    service = (context.get("services") or {}).get(name) or {}
    targets = [
        int(port["target_port"])
        for port in service.get("ports") or []
        if str(port.get("target_port") or "").isdigit()
    ]
    if targets:
        return targets

    for kind in WORKLOAD_KINDS:
        info = (context.get(kind) or {}).get(name) or {}
        container_ports = [int(p) for p in info.get("ports") or [] if isinstance(p, int)]
        if container_ports:
            return container_ports
    return []


def _new_policy(source: Workload, namespace: str) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"{source.name}-targeted-egress",
            "namespace": namespace,
            "labels": dict(MANAGED_BY),
        },
        "spec": {"podSelector": {"matchLabels": source.labels}, "policyTypes": ["Egress"]},
    }
