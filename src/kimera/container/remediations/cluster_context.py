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

from ..core.exceptions import PermissionDeniedError
from ..core.k8s_client import K8sClient
from ..core.logger import SecurityLogger

# Exploit types whose remediation needs every workload a namespace-wide policy
# would select, not just deployments.
_NETWORK_TYPES = frozenset({"missing-network-policies", "all"})

# Exploit types remediated by changing a container's security context.
_SECURITY_CONTEXT_TYPES = frozenset(
    {
        "privileged-containers",
        "dangerous-capabilities",
        "host-namespace-sharing",
        "missing-resource-limits",
        "all",
    }
)


def gather_cluster_context(
    k8s: K8sClient, logger: SecurityLogger, exploit_type: str
) -> dict[str, Any]:
    """Read the cluster state an LLM needs to remediate this exploit type.

    Read-only. A listing failure is logged and yields an empty section rather
    than aborting, so a partial context still reaches the model.

    Raises:
        PermissionDeniedError: if the API refuses the read (401/403).
    """
    namespace = k8s.namespace
    context: dict[str, Any] = {"deployments": deployment_info(k8s, logger, namespace)}

    if exploit_type in _NETWORK_TYPES:
        # A default-deny policy selects every pod, so a workload missing from
        # this context loses all traffic once the generated set is applied.
        context["statefulsets"] = statefulset_info(k8s, logger, namespace)
        context["cronjobs"] = cronjob_info(k8s, logger, namespace)
        context["services"] = service_info(k8s, logger, namespace)

    if exploit_type in _SECURITY_CONTEXT_TYPES:
        context["security_contexts"] = security_contexts(k8s, logger, namespace)

    return context


def _reject_unreadable(error: Exception, kind: str) -> None:
    """A refused read is not an empty namespace.

    Generating from one would sever every workload it could not see.
    """
    status = getattr(error, "status", None)
    if status in (401, 403):
        raise PermissionDeniedError(
            f"Cannot read {kind} in the namespace (HTTP {status}); the credential is "
            "unauthenticated or lacks permission. Refusing to generate from a namespace "
            "that cannot be read."
        ) from error


def deployment_info(
    k8s: K8sClient, logger: SecurityLogger, namespace: str
) -> dict[str, dict[str, Any]]:
    """Return deployment name to labels and ports mapping."""
    result: dict[str, dict[str, Any]] = {}
    try:
        deps = k8s.apps_v1.list_namespaced_deployment(namespace)
        for dep in deps.items:
            labels = dep.spec.selector.match_labels or {}
            result[dep.metadata.name] = {"labels": dict(labels), "ports": extract_ports(dep)}
    except Exception as e:
        _reject_unreadable(e, "deployments")
        logger.error(f"Failed to list deployments: {e}")
    return result


def statefulset_info(
    k8s: K8sClient, logger: SecurityLogger, namespace: str
) -> dict[str, dict[str, Any]]:
    """Return statefulset name to labels and ports mapping."""
    result: dict[str, dict[str, Any]] = {}
    try:
        stss = k8s.apps_v1.list_namespaced_stateful_set(namespace)
        for sts in stss.items:
            labels = sts.spec.selector.match_labels or {}
            result[sts.metadata.name] = {"labels": dict(labels), "ports": extract_ports(sts)}
    except Exception as e:
        _reject_unreadable(e, "statefulsets")
        logger.error(f"Failed to list statefulsets: {e}")
    return result


def cronjob_info(
    k8s: K8sClient, logger: SecurityLogger, namespace: str
) -> dict[str, dict[str, Any]]:
    """Return cronjob name to pod labels and ports mapping."""
    result: dict[str, dict[str, Any]] = {}
    try:
        cjs = k8s.batch_v1.list_namespaced_cron_job(namespace)
        for cj in cjs.items:
            job_template = cj.spec.job_template
            labels = job_template.spec.template.metadata.labels or {}
            result[cj.metadata.name] = {
                "labels": dict(labels),
                "ports": extract_ports(job_template),
            }
    except Exception as e:
        _reject_unreadable(e, "cronjobs")
        logger.error(f"Failed to list cronjobs: {e}")
    return result


def service_info(
    k8s: K8sClient, logger: SecurityLogger, namespace: str
) -> dict[str, dict[str, Any]]:
    """Return service name to ports and selector mapping."""
    result: dict[str, dict[str, Any]] = {}
    try:
        svcs = k8s.v1.list_namespaced_service(namespace)
        for svc in svcs.items:
            ports = [
                {
                    "port": p.port,
                    "target_port": str(p.target_port) if p.target_port else None,
                    "protocol": p.protocol or "TCP",
                }
                for p in (svc.spec.ports or [])
            ]
            result[svc.metadata.name] = {
                "ports": ports,
                "selector": dict(svc.spec.selector) if svc.spec.selector else {},
            }
    except Exception as e:
        _reject_unreadable(e, "services")
        logger.error(f"Failed to list services: {e}")
    return result


def security_contexts(
    k8s: K8sClient, logger: SecurityLogger, namespace: str
) -> dict[str, dict[str, Any]]:
    """Return deployment security context details for hardening analysis."""
    result: dict[str, dict[str, Any]] = {}
    try:
        deps = k8s.apps_v1.list_namespaced_deployment(namespace)
        for dep in deps.items:
            pod_spec = dep.spec.template.spec
            result[dep.metadata.name] = {
                "pod": {
                    "host_pid": getattr(pod_spec, "host_pid", False) or False,
                    "host_network": getattr(pod_spec, "host_network", False) or False,
                    "host_ipc": getattr(pod_spec, "host_ipc", False) or False,
                },
                "containers": [_container_context(c) for c in pod_spec.containers],
            }
    except Exception as e:
        _reject_unreadable(e, "workloads")
        logger.error(f"Failed to get security contexts: {e}")
    return result


def _container_context(container: Any) -> dict[str, Any]:
    """Describe one container's security context and resource limits."""
    info: dict[str, Any] = {"name": container.name}

    ctx = container.security_context
    if ctx:
        info["privileged"] = getattr(ctx, "privileged", None)
        info["allow_privilege_escalation"] = getattr(ctx, "allow_privilege_escalation", None)
        info["run_as_non_root"] = getattr(ctx, "run_as_non_root", None)
        info["run_as_user"] = getattr(ctx, "run_as_user", None)
        info["read_only_root_filesystem"] = getattr(ctx, "read_only_root_filesystem", None)
        caps = getattr(ctx, "capabilities", None)
        if caps:
            info["capabilities_add"] = list(caps.add or [])
            info["capabilities_drop"] = list(caps.drop or [])

    resources = container.resources
    if resources:
        info["resources"] = {
            "limits": dict(resources.limits) if resources.limits else None,
            "requests": dict(resources.requests) if resources.requests else None,
        }

    return info


def extract_ports(workload: Any) -> list[int]:
    """Extract declared container ports from a workload spec."""
    ports: list[int] = []
    try:
        for container in workload.spec.template.spec.containers:
            for port in container.ports or []:
                if port.container_port:
                    ports.append(int(port.container_port))
    except (AttributeError, TypeError):
        # A workload whose spec is shaped differently contributes no ports
        # rather than failing the whole context gather.
        pass
    return ports
