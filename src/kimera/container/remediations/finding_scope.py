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
from enum import StrEnum

from ...application.config.schemas import NetworkTopologyEntry
from ...domain.models import PathResult
from ..core.logger import console
from ..make_vulnerable.missing_network_policies import DATA_STORE_PORTS
from .exploit_findings import AttackPathRecord, FindingsDocument

TARGETED_SCOPE = "targeted"
NAMESPACE_SCOPE = "namespace"


class Scope(StrEnum):
    """What a targeted remediation should do about one observed path."""

    DENY = "DENY"
    KEEP = "KEEP"
    REVIEW = "REVIEW"


@dataclass(frozen=True)
class ScopedPath:
    """One observed path and the decision reached about it."""

    path: AttackPathRecord
    scope: Scope
    reason: str


@dataclass
class Classification:
    """The three lists a targeted policy is generated from."""

    deny: list[ScopedPath] = field(default_factory=list)
    keep: list[ScopedPath] = field(default_factory=list)
    review: list[ScopedPath] = field(default_factory=list)
    unmeasured: list[AttackPathRecord] = field(default_factory=list)

    def closes_nothing(self) -> bool:
        """Whether a policy built from this would deny no observed path."""
        return not self.deny


def declared_dependencies(
    source_labels: dict[str, str], topology: dict[str, NetworkTopologyEntry]
) -> set[str]:
    """Workloads the topology says this source may reach.

    Inverted from the ingress declarations so the fact is declared once.
    """
    if not source_labels:
        return set()

    reachable: set[str] = set()
    for destination, entry in topology.items():
        for selector in entry.allowed_ingress_from or []:
            if selector and all(source_labels.get(k) == v for k, v in selector.items()):
                reachable.add(destination)
                break
    return reachable


def classify(
    document: FindingsDocument,
    source_labels: dict[str, str],
    topology: dict[str, NetworkTopologyEntry],
    namespace_workloads: set[str],
) -> Classification:
    """Sort each observed path into DENY, KEEP or REVIEW.

    An undeclared in-namespace flow is REVIEW, not DENY: an incomplete topology
    is likelier than a real need to sever it.
    """
    declared = declared_dependencies(source_labels, topology)
    result = Classification()

    for path in document.attack_paths:
        if path.result is PathResult.UNKNOWN:
            # Nothing measured this; classifying it would act on absent evidence.
            result.unmeasured.append(path)
            continue

        if _matches_declared(path.host, declared):
            result.keep.append(ScopedPath(path, Scope.KEEP, "declared in network_topology"))
        elif path.port in DATA_STORE_PORTS:
            result.deny.append(
                ScopedPath(path, Scope.DENY, f"undeclared {DATA_STORE_PORTS[path.port]} access")
            )
        elif not _in_namespace(path.host, namespace_workloads):
            result.deny.append(ScopedPath(path, Scope.DENY, "destination outside the namespace"))
        else:
            result.review.append(
                ScopedPath(path, Scope.REVIEW, "undeclared in-namespace destination")
            )

    return result


def report(classification: Classification) -> None:
    """Show the operator what the generated set will block, keep and question."""
    console.print("\n[bold]Observed paths from the source workload[/bold]")
    for scope, style, scoped in (
        (Scope.DENY, "red", classification.deny),
        (Scope.KEEP, "green", classification.keep),
        (Scope.REVIEW, "yellow", classification.review),
    ):
        console.print(f"\n[{style}]{scope}[/{style}] ({len(scoped)})")
        for item in scoped:
            console.print(f"  {item.path.host}:{item.path.port} — {item.reason}", highlight=False)

    for path in classification.unmeasured:
        console.print(
            f"  [dim]{path.host}:{path.port} — not measured, unclassified[/dim]", highlight=False
        )

    if classification.review:
        console.print(
            "\n[dim]REVIEW paths are denied. Add a legitimate one to network_topology "
            "and regenerate to keep it.[/dim]"
        )
    if classification.closes_nothing():
        console.print("\n[yellow]This set closes no observed path.[/yellow]")


def _matches_declared(host: str, declared: set[str]) -> bool:
    """Whether a probed host names one of the declared destinations.

    Matches the leading DNS segment, never a substring: `auth` must not satisfy
    a declaration of `auth-admin`.
    """
    return host in declared or host.split(".")[0] in declared


def _in_namespace(host: str, namespace_workloads: set[str]) -> bool:
    """Whether the host is in the target namespace.

    A bare name resolves in-namespace by cluster DNS; a dotted one names elsewhere.
    """
    return host in namespace_workloads or "." not in host
