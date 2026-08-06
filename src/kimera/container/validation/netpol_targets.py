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

from ..make_vulnerable.probe_prelude import UNKNOWN_STATE
from .models import ValidationVerdict

INFRASTRUCTURE_TARGETS: list[dict[str, Any]] = [
    {
        "host": "kubernetes.default.svc.cluster.local",
        "port": 443,
        "label": "Kubernetes API server",
        "should_block": True,
        "remediation": (
            "Add an egress NetworkPolicy denying access to the Kubernetes API server "
            "from application pods, or use a default-deny egress policy."
        ),
    },
]

CROSS_NAMESPACE_TARGETS: list[dict[str, Any]] = [
    {
        "host": "kube-dns.kube-system.svc.cluster.local",
        "port": 53,
        "label": "CoreDNS (kube-system)",
        "should_block": False,  # DNS is usually allowed
        "remediation": "",
    },
    {
        "host": "kube-dns.kube-system.svc.cluster.local",
        "port": 9153,
        "label": "CoreDNS metrics (kube-system)",
        "should_block": True,
        "remediation": (
            "Add an egress NetworkPolicy restricting access to kube-system ports "
            "other than DNS (53/TCP, 53/UDP)."
        ),
    },
]

# Cloud metadata endpoints (SSRF vector)
METADATA_TARGETS: list[dict[str, Any]] = [
    {
        "host": "169.254.169.254",
        "port": 80,
        "label": "Cloud metadata API (SSRF vector)",
        "should_block": True,
        "remediation": (
            "Add a NetworkPolicy egress rule blocking 169.254.169.254/32. "
            "On AWS, also enable IMDSv2 with hop limit 1."
        ),
    },
]


def _verdict_for(state: str, host: str, port: int) -> tuple[str, ValidationVerdict, str]:
    """Map a probe state to (actual, verdict, evidence).

    An ``UNKNOWN_STATE`` probe never yields PASS or FAIL: nothing was measured, so
    the check is reported as ERROR rather than asserting the control's behaviour.
    """
    if state == UNKNOWN_STATE:
        return (
            "UNKNOWN",
            ValidationVerdict.ERROR,
            f"probe {host}:{port}: {UNKNOWN_STATE} - control not verified",
        )
    reachable = state == "OPEN"
    return (
        "ALLOWED" if reachable else "BLOCKED",
        ValidationVerdict.FAIL if reachable else ValidationVerdict.PASS,
        f"probe {host}:{port}: {state}",
    )
