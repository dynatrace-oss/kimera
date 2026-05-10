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

import logging
from typing import Any

from kubernetes.client.rest import ApiException

from ..container.core.k8s_client import K8sClient

logger = logging.getLogger(__name__)


def enumerate_targets(k8s: K8sClient) -> dict[str, Any]:
    """Discover all security-relevant resources in the namespace.

    Low-noise reconnaissance via standard API list calls. Returns structured
    inventory for MCP enumerate_attack_surface tool. Maps to T1613.
    """
    namespace = k8s.namespace
    inventory: dict[str, Any] = {
        "namespace": namespace,
        "deployments": [],
        "services": [],
        "service_accounts": [],
        "network_policies": [],
        "secrets_metadata": [],
        "role_bindings": [],
    }

    _enumerate_deployments(k8s, namespace, inventory)
    _enumerate_services(k8s, namespace, inventory)
    _enumerate_service_accounts(k8s, namespace, inventory)
    _enumerate_network_policies(k8s, namespace, inventory)
    _enumerate_secrets(k8s, namespace, inventory)
    _enumerate_role_bindings(k8s, namespace, inventory)

    return inventory


def _enumerate_deployments(k8s: K8sClient, namespace: str, inventory: dict) -> None:
    try:
        deps = k8s.apps_v1.list_namespaced_deployment(namespace)
        for dep in deps.items:
            pod_spec = dep.spec.template.spec
            containers = []
            for c in pod_spec.containers:
                ctx = c.security_context
                containers.append({
                    "name": c.name,
                    "image": c.image,
                    "privileged": bool(ctx and ctx.privileged),
                    "capabilities_add": list(ctx.capabilities.add or [])
                    if ctx and ctx.capabilities and ctx.capabilities.add else [],
                    "has_limits": bool(c.resources and c.resources.limits),
                })
            inventory["deployments"].append({
                "name": dep.metadata.name,
                "replicas": dep.spec.replicas,
                "service_account": pod_spec.service_account_name or "default",
                "host_pid": bool(pod_spec.host_pid),
                "host_network": bool(pod_spec.host_network),
                "automount_token": pod_spec.automount_service_account_token is not False,
                "containers": containers,
            })
    except ApiException as exc:
        logger.warning("Failed to list deployments: %s", exc.reason)


def _enumerate_services(k8s: K8sClient, namespace: str, inventory: dict) -> None:
    try:
        svcs = k8s.v1.list_namespaced_service(namespace)
        for svc in svcs.items:
            ports = [
                {"port": p.port, "protocol": p.protocol or "TCP"}
                for p in (svc.spec.ports or [])
            ]
            inventory["services"].append({
                "name": svc.metadata.name,
                "type": svc.spec.type,
                "ports": ports,
                "selector": dict(svc.spec.selector) if svc.spec.selector else {},
            })
    except ApiException as exc:
        logger.warning("Failed to list services: %s", exc.reason)


def _enumerate_service_accounts(k8s: K8sClient, namespace: str, inventory: dict) -> None:
    try:
        sas = k8s.v1.list_namespaced_service_account(namespace)
        inventory["service_accounts"] = [sa.metadata.name for sa in sas.items]
    except ApiException as exc:
        logger.warning("Failed to list service accounts: %s", exc.reason)


def _enumerate_network_policies(k8s: K8sClient, namespace: str, inventory: dict) -> None:
    try:
        policies = k8s.list_network_policies(namespace)
        inventory["network_policies"] = [p.metadata.name for p in policies]
    except ApiException as exc:
        logger.warning("Failed to list network policies: %s", exc.reason)


def _enumerate_secrets(k8s: K8sClient, namespace: str, inventory: dict) -> None:
    try:
        secrets = k8s.v1.list_namespaced_secret(namespace)
        inventory["secrets_metadata"] = [
            {"name": s.metadata.name, "type": s.type}
            for s in secrets.items
        ]
    except ApiException as exc:
        logger.warning("Failed to list secrets: %s", exc.reason)


def _enumerate_role_bindings(k8s: K8sClient, namespace: str, inventory: dict) -> None:
    try:
        bindings = k8s.rbac_v1.list_namespaced_role_binding(namespace)
        for rb in bindings.items:
            subjects = [
                {"kind": s.kind, "name": s.name}
                for s in (rb.subjects or [])
            ]
            inventory["role_bindings"].append({
                "name": rb.metadata.name,
                "role": rb.role_ref.name,
                "role_kind": rb.role_ref.kind,
                "subjects": subjects,
            })
    except ApiException as exc:
        logger.warning("Failed to list role bindings: %s", exc.reason)
