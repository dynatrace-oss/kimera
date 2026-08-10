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
import time
from typing import Any

from kubernetes.client import ApiException

from ..core.k8s_client import K8sClient
from ..make_vulnerable.probe_prelude import PROBE_PRELUDE, UNKNOWN_STATE

logger = logging.getLogger(__name__)

PROBE_POD_NAME = "kimera-netpol-probe"
PROBE_IMAGE = "busybox:1.36"
PROBE_LABELS = {
    "app.kubernetes.io/managed-by": "kimera",
    "app.kubernetes.io/component": "netpol-probe",
}

# Targets to test connectivity against


def _deploy_probe_pod(k8s: K8sClient, namespace: str) -> str | None:
    """Deploy an ephemeral busybox probe pod for network testing.

    Returns:
        ``None`` on success, otherwise the reason the pod could not be run. The
        reason is reported as evidence: a probe rejected by admission control and
        a probe that never became ready are different facts about the namespace.
    """
    pod_body: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": PROBE_POD_NAME,
            "namespace": namespace,
            "labels": PROBE_LABELS,
        },
        "spec": {
            "containers": [
                {
                    "name": "probe",
                    "image": PROBE_IMAGE,
                    "command": ["sleep", "300"],
                    "resources": {
                        "limits": {"cpu": "10m", "memory": "16Mi"},
                        "requests": {"cpu": "10m", "memory": "16Mi"},
                    },
                    "securityContext": {
                        "runAsNonRoot": False,
                        "allowPrivilegeEscalation": False,
                    },
                }
            ],
            "restartPolicy": "Never",
            "terminationGracePeriodSeconds": 0,
            # Auto-cleanup after 5 minutes via activeDeadlineSeconds
            "activeDeadlineSeconds": 300,
        },
    }

    try:
        k8s.v1.create_namespaced_pod(namespace=namespace, body=pod_body)
    except ApiException as e:
        if e.status == 409:
            # Pod already exists — delete and recreate
            try:
                k8s.v1.delete_namespaced_pod(PROBE_POD_NAME, namespace)
                time.sleep(5)
                k8s.v1.create_namespaced_pod(namespace=namespace, body=pod_body)
            except ApiException as retry_error:
                return f"recreate failed: HTTP {retry_error.status} {retry_error.reason}"
        elif e.status in (403, 422):
            # Admission rejected — that's actually useful info
            logger.warning(
                "Probe pod rejected by admission controller: %s. "
                "This may indicate strict policies that also block the probe itself.",
                e.reason,
            )
            return f"rejected by admission control: HTTP {e.status} {e.reason}"
        else:
            return f"create failed: HTTP {e.status} {e.reason}"

    # Wait for pod to be running
    for _ in range(30):
        try:
            pod = k8s.v1.read_namespaced_pod(PROBE_POD_NAME, namespace)
            if pod.status.phase == "Running":
                return None
        except ApiException:
            pass
        time.sleep(2)

    return "probe pod never reached Running within 60s"


def _cleanup_probe_pod(k8s: K8sClient, namespace: str) -> None:
    """Remove the probe pod."""
    try:
        k8s.v1.delete_namespaced_pod(
            PROBE_POD_NAME,
            namespace,
            grace_period_seconds=0,
        )
    except ApiException:
        pass


def _test_connectivity(
    k8s: K8sClient,
    namespace: str,
    host: str,
    port: int,
    timeout: int = 3,
) -> str:
    """Test TCP connectivity from the probe pod.

    Returns:
        ``"OPEN"``, ``"CLOSED"``, or ``UNKNOWN_STATE`` when the probe pod has no
        usable probe tool. ``UNKNOWN_STATE`` must never be collapsed into
        ``"CLOSED"`` — an untested port is not a blocked port.
    """
    cmd = f"{PROBE_PRELUDE}\nkimera_port_open {host} {port} {timeout}"
    try:
        output = k8s.exec_in_pod(PROBE_POD_NAME, cmd, container="probe")
    except Exception:
        return UNKNOWN_STATE
    if "OPEN" in output:
        return "OPEN"
    if "CLOSED" in output:
        return "CLOSED"
    return UNKNOWN_STATE
