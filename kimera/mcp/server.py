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

# Run:
#   uv run python -m kimera.mcp.server          # stdio (Claude Desktop)
#   uv run python -m kimera.mcp.server --http    # streamable HTTP
#
# Claude Desktop config:
#   {
#     "mcpServers": {
#       "kimera": {
#         "command": "uv",
#         "args": ["run", "python", "-m", "kimera.mcp.server"],
#         "cwd": "/path/to/k8s-exploit-toolkit"
#       }
#     }
#   }

import logging
from typing import Any

from mcp.server.fastmcp import FastMCP

from ..container.core.k8s_client import K8sClient
from ..core.assessor import assess_namespace
from ..core.enumerator import enumerate_targets
from ..core.findings import AssessmentReport, TechniqueResult
from ..core.technique_engine import TechniqueRegistry, execute_technique

logger = logging.getLogger(__name__)

# ── Server & shared state ────────────────────────────────────────────

_registry = TechniqueRegistry()

mcp_server = FastMCP(
    name="kimera",
    instructions=(
        "Kimera is a Kubernetes penetration testing toolkit. "
        "You are an offensive security expert conducting a K8s security assessment. "
        "Start with enumerate_targets to understand the attack surface, then use "
        "assess_namespace to find misconfigurations. Use attempt_technique to test "
        "specific attack paths (C1=SA token theft, L1=network probe, etc.). "
        "After each successful technique, use validate_defense to check if the "
        "blue team's controls caught it. All destructive operations default to "
        "dry_run=True — set dry_run=False only when explicitly instructed."
    ),
)


def _get_k8s(namespace: str, kubeconfig: str | None = None) -> K8sClient:
    """Create a K8sClient for the given namespace.

    The client is created per-call rather than held as server state so that
    different tool invocations can target different namespaces.
    """
    return K8sClient(namespace=namespace, kubeconfig=kubeconfig)


# ── Tools ─────────────────────────────────────────────────────────────


@mcp_server.tool()
def list_techniques(
    phase: str | None = None,
) -> dict[str, Any]:
    """List available attack techniques with MITRE ATT&CK mappings.

    Returns all registered techniques, optionally filtered by attack phase.
    Use this to plan an attack path before executing techniques.

    Args:
        phase: Filter by phase (reconnaissance, credential-access,
               privilege-escalation, lateral-movement, defense-validation).
               Omit to list all.
    """
    if phase:
        ids = _registry.list_by_phase(phase)
        techniques = [t for t in _registry.list_techniques() if t["id"] in ids]
    else:
        techniques = _registry.list_techniques()

    return {
        "techniques": techniques,
        "total": len(techniques),
        "summary": f"{len(techniques)} techniques available"
        + (f" in phase '{phase}'" if phase else " across all phases"),
    }


@mcp_server.tool()
def assess_target(
    namespace: str,
    kubeconfig: str | None = None,
) -> dict[str, Any]:
    """Scan a namespace for workload security misconfigurations.

    Non-destructive. Checks all deployments against CIS Kubernetes Benchmark
    controls: privileged containers, dangerous capabilities, host namespaces,
    missing resource limits, root execution, writable filesystems, and more.

    Each finding includes severity, MITRE ATT&CK mapping, CIS control ID,
    and remediation guidance.

    Args:
        namespace: Kubernetes namespace to scan.
        kubeconfig: Path to kubeconfig file (optional, uses default if omitted).
    """
    k8s = _get_k8s(namespace, kubeconfig)
    report: AssessmentReport = assess_namespace(k8s)
    data = report.model_dump()
    data["summary"] = report.to_summary()
    return data


@mcp_server.tool()
def enumerate_attack_surface(
    namespace: str,
    kubeconfig: str | None = None,
) -> dict[str, Any]:
    """Discover all security-relevant resources in a namespace.

    Low-noise reconnaissance via standard Kubernetes API list calls.
    Returns deployments (with security context details), services, service
    accounts, network policies, secrets metadata, and RBAC bindings.

    This is the recommended first step in any assessment — understand the
    attack surface before choosing techniques.

    Args:
        namespace: Kubernetes namespace to enumerate.
        kubeconfig: Path to kubeconfig file (optional).
    """
    k8s = _get_k8s(namespace, kubeconfig)
    inventory = enumerate_targets(k8s)

    dep_count = len(inventory.get("deployments", []))
    svc_count = len(inventory.get("services", []))
    secret_count = len(inventory.get("secrets_metadata", []))
    netpol_count = len(inventory.get("network_policies", []))

    inventory["summary"] = (
        f"Namespace '{namespace}': {dep_count} deployments, {svc_count} services, "
        f"{secret_count} secrets, {netpol_count} network policies"
    )
    return inventory


@mcp_server.tool()
def attempt_technique(
    technique_id: str,
    namespace: str,
    target_pod: str | None = None,
    params: dict[str, str] | None = None,
    dry_run: bool = True,
    kubeconfig: str | None = None,
) -> dict[str, Any]:
    """Execute a specific attack technique against the cluster.

    Each technique maps to a MITRE ATT&CK technique and uses real K8s API
    calls or in-pod execution. Results include evidence of success/failure,
    impact assessment, and whether defenses caught the attempt.

    SAFETY: Defaults to dry_run=True. Set dry_run=False only when explicitly
    instructed by the operator.

    Common technique IDs:
      C1 = SA token theft from volume mount
      C2 = Secret enumeration via API
      C5 = Cloud metadata SSRF
      C6 = Environment variable secrets
      L1 = Network service probe
      L5 = DNS service enumeration
      R2 = Enumerate workloads

    Use list_techniques() to see all available techniques.

    Args:
        technique_id: Technique ID (e.g. "C1", "L1", "E1").
        namespace: Target namespace.
        target_pod: Pod name for exec-mode techniques (required for C1, C5, L1, etc.).
        params: Runtime parameters (e.g. {"probe_host": "redis", "probe_port": "6379"}).
        dry_run: If True, preview only — no cluster state changes. Default: True.
        kubeconfig: Path to kubeconfig file (optional).
    """
    k8s = _get_k8s(namespace, kubeconfig)
    result: TechniqueResult = execute_technique(
        k8s=k8s,
        registry=_registry,
        technique_id=technique_id,
        target_pod=target_pod,
        params=params,
    )
    result.dry_run = dry_run
    data = result.model_dump()
    data["summary"] = result.to_summary()
    return data


@mcp_server.tool()
def validate_defense(
    namespace: str,
    control_type: str = "all",
    kubeconfig: str | None = None,
) -> dict[str, Any]:
    """Test whether security controls actually block attacks.

    Safe for production: uses server-side dry-run for admission testing,
    ephemeral probe pods with TTLs for network policy testing, and
    read-only RBAC analysis.

    Control types:
      admission      — Tests Kyverno/OPA/PSA policies via dry-run=server
      network-policy — Tests pod-to-pod isolation with ephemeral probes
      rbac           — Analyzes role bindings for excessive permissions
      all            — Runs all validators

    Args:
        namespace: Namespace to validate.
        control_type: Type of control to test (admission, network-policy, rbac, all).
        kubeconfig: Path to kubeconfig file (optional).
    """
    from ..container.core.logger import SecurityLogger
    from ..container.validation.engine import validate_controls

    k8s = _get_k8s(namespace, kubeconfig)
    log = SecurityLogger(namespace=namespace)

    reports = validate_controls(
        k8s=k8s,
        logger=log,
        control_type=control_type,
        output_json=False,
    )

    results = []
    for report in reports:
        results.append(report.to_dict())

    total_passed = sum(r.passed for r in reports)
    total_failed = sum(r.failed for r in reports)

    return {
        "reports": results,
        "total_passed": total_passed,
        "total_failed": total_failed,
        "all_secure": total_failed == 0,
        "summary": (
            f"Validated {control_type} controls in '{namespace}': "
            f"{total_passed} passed, {total_failed} failed"
            + (" — defenses are holding" if total_failed == 0 else " — GAPS FOUND")
        ),
    }


@mcp_server.tool()
def get_remediation(
    check_id: str,
) -> dict[str, Any]:
    """Get remediation guidance for a specific security finding.

    Use after assess_target to get detailed fix instructions for findings.
    Returns CIS benchmark control ID, MITRE ATT&CK mapping, and
    step-by-step remediation.

    Args:
        check_id: Finding check_id from assess_target results
                  (e.g. "privileged_mode", "host_pid", "missing_resource_limits").
    """
    from ..core.assessor import _load_checks

    checks = _load_checks()
    for check in checks:
        if check.get("id") == check_id:
            return {
                "check_id": check_id,
                "title": check.get("title", ""),
                "severity": check.get("severity", ""),
                "remediation": check.get("remediation", ""),
                "mitre_id": check.get("mitre_id", ""),
                "mitre_name": check.get("mitre_name", ""),
                "cis_controls": check.get("cis_controls", []),
                "summary": f"Remediation for {check_id}: {check.get('remediation', 'N/A')}",
            }

    return {
        "check_id": check_id,
        "error": f"Unknown check_id: {check_id}",
        "summary": f"No remediation found for check_id '{check_id}'",
    }


@mcp_server.tool()
def reload_techniques() -> dict[str, Any]:
    """Reload technique definitions from disk.

    Call after adding new YAML files to config/techniques/. The server
    picks up new technique definitions without restart.

    This enables runtime extension: drop a YAML file defining a new attack
    technique and it becomes available as an MCP tool parameter.
    """
    old_count = _registry.technique_count
    _registry.reload()
    new_count = _registry.technique_count
    added = new_count - old_count

    return {
        "previous_count": old_count,
        "current_count": new_count,
        "added": added,
        "techniques": _registry.list_techniques(),
        "summary": (
            f"Reloaded: {new_count} techniques"
            + (f" (+{added} new)" if added > 0 else " (no changes)")
        ),
    }


# ── Entry point ───────────────────────────────────────────────────────

def main() -> None:
    """Run the MCP server."""
    import sys

    transport = "streamable-http" if "--http" in sys.argv else "stdio"
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting kimera MCP server (transport=%s)", transport)
    mcp_server.run(transport=transport)


if __name__ == "__main__":
    main()
