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

# API-mode technique execution: list, delete, patch, create, permission probe,
# and defense tool version detection.
# Exec-mode execution stays in technique_engine.py.

import logging
import re
from typing import Any

from kubernetes.client.rest import ApiException

from ..container.core.k8s_client import K8sClient
from .findings import TechniqueResult
from .technique_registry import TechniqueDefinition

logger = logging.getLogger(__name__)


def execute_api_technique(
    k8s: K8sClient,
    technique: TechniqueDefinition,
    result: TechniqueResult,
) -> None:
    """Execute an API-mode technique: list, delete, patch, or create."""
    for api_call in technique.api_calls:
        verb = api_call.get("verb", "list")
        resource_type = api_call.get("resource", "")

        try:
            if verb == "list":
                _handle_list(k8s, resource_type, result)
            elif verb == "delete":
                _handle_delete(k8s, resource_type, result)
            elif verb == "patch":
                _handle_patch(k8s, resource_type, api_call, result)
            elif verb == "create":
                _handle_create(k8s, resource_type, api_call, result)
            elif verb == "detect_tool_version":
                _handle_detect_tool_version(k8s, api_call, result)
            else:
                result.evidence.append(f"Unsupported verb: {verb}")
        except ApiException as exc:
            marker = _denied_marker(technique)
            result.evidence.append(
                marker or f"API call failed ({verb} {resource_type}): {exc.reason}"
            )

    _match_evidence_markers(technique, result)


def enumerate_for_technique(
    k8s: K8sClient,
    technique: TechniqueDefinition,
    namespace: str,
) -> list[dict[str, Any]]:
    """Enumerate K8s resources defined in technique api_calls."""
    resources: list[dict[str, Any]] = []

    for api_call in technique.api_calls:
        resource_type = api_call.get("resource", "")
        ns = api_call.get("namespace", namespace)
        try:
            items = list_resource(k8s, ns, resource_type)
            resources.extend(items)
        except ApiException as exc:
            logger.warning("Failed to enumerate %s: %s", resource_type, exc.reason)

    return resources


# ── Verb handlers ─────────────────────────────────────────────────────


def _handle_list(
    k8s: K8sClient,
    resource_type: str,
    result: TechniqueResult,
) -> None:
    resources = list_resource(k8s, k8s.namespace, resource_type)
    if resources:
        result.success = True
        result.evidence.append(f"Enumerated {len(resources)} {resource_type}")
        for r in resources[:10]:
            result.evidence.append(f"{r['type']}: {r['name']}")


def _handle_delete(
    k8s: K8sClient,
    resource_type: str,
    result: TechniqueResult,
) -> None:
    delete_dispatch: dict[str, Any] = {
        "events": lambda: k8s.v1.delete_collection_namespaced_event(k8s.namespace),
    }
    handler = delete_dispatch.get(resource_type)
    if handler is None:
        result.evidence.append(f"Delete not supported for: {resource_type}")
        return
    handler()
    result.success = True
    result.evidence.append(f"{resource_type} deleted from {k8s.namespace}")


def _handle_patch(
    k8s: K8sClient,
    resource_type: str,
    api_call: dict[str, Any],
    result: TechniqueResult,
) -> None:
    patch_body = api_call.get("patch", {}).get("body", {})
    if not patch_body:
        result.evidence.append("No patch body defined")
        return

    if resource_type == "namespaces":
        k8s.v1.patch_namespace(k8s.namespace, patch_body)
        result.success = True
        result.evidence.append(f"Namespace {k8s.namespace} patched")
    elif resource_type == "pods":
        result.evidence.append("Pod patch requires target_pod parameter")
    else:
        result.evidence.append(f"Patch not supported for: {resource_type}")


def _handle_create(
    k8s: K8sClient,
    resource_type: str,
    api_call: dict[str, Any],
    result: TechniqueResult,
) -> None:
    if resource_type == "selfsubjectaccessreviews":
        _handle_permission_probe(k8s, result)
        return

    result.evidence.append(f"Create for {resource_type} — use dry_run=False to execute")


def _handle_permission_probe(
    k8s: K8sClient,
    result: TechniqueResult,
) -> None:
    """Probe permissions via SelfSubjectAccessReview — zero Falco alerts."""
    from kubernetes.client import (
        AuthorizationV1Api,
        V1ResourceAttributes,
        V1SelfSubjectAccessReview,
    )

    auth_api = AuthorizationV1Api(api_client=k8s.v1.api_client)

    checks = [
        ("secrets", "list"),
        ("secrets", "get"),
        ("pods", "create"),
        ("pods/exec", "create"),
        ("rolebindings", "create"),
        ("clusterrolebindings", "create"),
        ("events", "delete"),
        ("namespaces", "patch"),
        ("cronjobs", "create"),
        ("serviceaccounts", "create"),
        ("daemonsets", "create"),
    ]

    allowed: list[str] = []
    denied: list[str] = []

    for resource, verb in checks:
        parts = resource.split("/", 1)
        attrs = V1ResourceAttributes(
            namespace=k8s.namespace,
            verb=verb,
            resource=parts[0],
            subresource=parts[1] if len(parts) > 1 else "",
        )
        review = V1SelfSubjectAccessReview(spec={"resourceAttributes": attrs})
        resp = auth_api.create_self_subject_access_review(review)
        perm_str = f"{verb} {resource}"
        if resp.status.allowed:
            allowed.append(perm_str)
        else:
            denied.append(perm_str)

    result.success = True
    result.evidence.append(f"Permissions mapped: {len(allowed)} allowed, {len(denied)} denied")

    if allowed:
        result.evidence.append(f"DANGEROUS_PERMISSIONS: {', '.join(allowed)}")
        result.impact.append(f"Identity has {len(allowed)} dangerous permissions")
    else:
        result.evidence.append("No dangerous permissions found")


def _handle_detect_tool_version(
    k8s: K8sClient,
    api_call: dict[str, Any],
    result: TechniqueResult,
) -> None:
    """Check if a defense tool is installed and whether its version is vulnerable.

    Fetches the tool's DaemonSet or Deployment, extracts the container image tag,
    and compares it against the fixed version for a specific CVE.
    """
    tool = api_call.get("tool", "")
    namespace = api_call.get("namespace", "kube-system")
    resource_kind = api_call.get("resource_kind", "daemonset")
    name_prefix = api_call.get("name_prefix", tool)
    fixed_version = api_call.get("fixed_version", "")
    cve = api_call.get("cve", "")

    try:
        if resource_kind == "daemonset":
            items = k8s.apps_v1.list_namespaced_daemon_set(namespace).items
        else:
            items = k8s.apps_v1.list_namespaced_deployment(namespace).items
    except ApiException as exc:
        result.evidence.append(
            f"ACCESS_DENIED: cannot list {resource_kind}s in {namespace}: {exc.reason}"
        )
        return

    matching = [i for i in items if name_prefix.lower() in (i.metadata.name or "").lower()]

    if not matching:
        result.evidence.append(f"TOOL_NOT_FOUND: {tool} not detected in {namespace}")
        return

    item = matching[0]
    result.evidence.append(
        f"TOOL_FOUND: {tool} {resource_kind} '{item.metadata.name}' in {namespace}"
    )
    result.success = True

    containers = item.spec.template.spec.containers or []
    version = _parse_image_version(containers, tool)

    if not version:
        result.evidence.append("VERSION_UNKNOWN: could not parse version from container image")
        return

    result.evidence.append(f"VERSION_DETECTED: {tool} {version}")

    if fixed_version and _version_is_vulnerable(version, fixed_version):
        result.evidence.append(
            f"TOOL_VULNERABLE: {tool} {version} is older than fixed version "
            f"{fixed_version} ({cve})"
        )
        result.impact.append(
            f"{tool} {version} may be vulnerable to {cve} — upgrade to {fixed_version}+"
        )
    else:
        result.evidence.append(f"TOOL_PATCHED: {tool} {version} >= {fixed_version} ({cve})")


def _parse_image_version(containers: list[Any], tool: str) -> str:
    """Extract a semver version string from a container image tag.

    Looks for a container whose image contains the tool name, then extracts
    the tag part (after ``:``) and strips any leading ``v``.
    """
    for container in containers:
        image = getattr(container, "image", "") or ""
        if tool.lower() in image.lower():
            tag_match = re.search(r":([vV]?\d+\.\d+[\.\d]*)", image)
            if tag_match:
                return tag_match.group(1).lstrip("vV")

    # Fallback: first container tag regardless of name
    for container in containers:
        image = getattr(container, "image", "") or ""
        tag_match = re.search(r":([vV]?\d+\.\d+[\.\d]*)", image)
        if tag_match:
            return tag_match.group(1).lstrip("vV")

    return ""


def _version_is_vulnerable(current: str, fixed: str) -> bool:
    """Return True if current semver < fixed semver."""

    def to_tuple(v: str) -> tuple[int, ...]:
        v = v.lstrip("vV")
        parts = v.split(".")
        result = []
        for p in parts[:3]:
            try:
                result.append(int(p))
            except ValueError:
                result.append(0)
        while len(result) < 3:
            result.append(0)
        return tuple(result)

    return to_tuple(current) < to_tuple(fixed)


# ── Helpers ───────────────────────────────────────────────────────────


def _denied_marker(technique: TechniqueDefinition) -> str:
    """Find the DENIED evidence marker text for a technique."""
    for m in technique.evidence_markers:
        marker = m.get("marker", "")
        if "DENIED" in marker:
            return m.get("evidence", marker)
    return ""


def _match_evidence_markers(
    technique: TechniqueDefinition,
    result: TechniqueResult,
) -> None:
    """Match evidence markers against collected evidence text."""
    evidence_text = " ".join(result.evidence)
    for marker_def in technique.evidence_markers:
        marker = marker_def.get("marker", "")
        if marker and marker in evidence_text:
            impact_text = marker_def.get("impact", "")
            if impact_text and impact_text not in result.impact:
                result.impact.append(impact_text)

    if not result.success:
        for indicator in technique.success_indicators:
            if indicator in evidence_text:
                result.success = True
                break


# ── Resource listing dispatch table ───────────────────────────────────


def list_resource(k8s: K8sClient, namespace: str, resource_type: str) -> list[dict[str, Any]]:
    """List K8s resources by type. Returns dicts with name and type keys."""
    list_dispatch: dict[str, Any] = {
        "deployments": lambda: [
            {"name": i.metadata.name, "type": "deployment"}
            for i in k8s.apps_v1.list_namespaced_deployment(namespace).items
        ],
        "services": lambda: [
            {"name": i.metadata.name, "type": "service"}
            for i in k8s.v1.list_namespaced_service(namespace).items
        ],
        "serviceaccounts": lambda: [
            {"name": i.metadata.name, "type": "serviceaccount"}
            for i in k8s.v1.list_namespaced_service_account(namespace).items
        ],
        "secrets": lambda: [
            {"name": i.metadata.name, "type": f"secret/{i.type}"}
            for i in k8s.v1.list_namespaced_secret(namespace).items
        ],
        "configmaps": lambda: [
            {"name": i.metadata.name, "type": "configmap", "keys": list((i.data or {}).keys())}
            for i in k8s.v1.list_namespaced_config_map(namespace).items
        ],
        "namespaces": lambda: [
            {"name": i.metadata.name, "type": "namespace"} for i in k8s.v1.list_namespace().items
        ],
        "networkpolicies": lambda: [
            {"name": i.metadata.name, "type": "networkpolicy"}
            for i in k8s.list_network_policies(namespace)
        ],
        "rolebindings": lambda: [
            {"name": i.metadata.name, "type": "rolebinding", "role": i.role_ref.name}
            for i in k8s.rbac_v1.list_namespaced_role_binding(namespace).items
        ],
        "clusterrolebindings": lambda: [
            {"name": i.metadata.name, "type": "clusterrolebinding", "role": i.role_ref.name}
            for i in k8s.rbac_v1.list_cluster_role_binding().items
        ],
        "endpoints": lambda: [
            {"name": i.metadata.name, "type": "endpoints"}
            for i in k8s.v1.list_namespaced_endpoints(namespace).items
        ],
        "events": lambda: [
            {"name": i.metadata.name, "type": "event", "reason": getattr(i, "reason", "")}
            for i in k8s.v1.list_namespaced_event(namespace).items
        ],
        "daemonsets": lambda: [
            {"name": i.metadata.name, "type": "daemonset", "namespace": i.metadata.namespace}
            for i in k8s.apps_v1.list_namespaced_daemon_set(
                namespace if namespace != "_all" else "kube-system"
            ).items
        ],
        "validatingwebhookconfigurations": lambda: [
            {"name": i.metadata.name, "type": "validatingwebhookconfiguration"}
            for i in k8s.admissionregistration_v1.list_validating_webhook_configuration().items
        ],
        "mutatingwebhookconfigurations": lambda: [
            {"name": i.metadata.name, "type": "mutatingwebhookconfiguration"}
            for i in k8s.admissionregistration_v1.list_mutating_webhook_configuration().items
        ],
        "customresourcedefinitions": lambda: [
            {"name": i.metadata.name, "type": "crd"}
            for i in k8s.apiextensions_v1.list_custom_resource_definition().items
        ],
        "cronjobs": lambda: [
            {"name": i.metadata.name, "type": "cronjob"}
            for i in k8s.batch_v1.list_namespaced_cron_job(namespace).items
        ],
        "validate_controls": lambda: [],
    }

    handler = list_dispatch.get(resource_type)
    if handler is None:
        logger.warning("Unknown API resource type: %s", resource_type)
        return []
    return list(handler())
