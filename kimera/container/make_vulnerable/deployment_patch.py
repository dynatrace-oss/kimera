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

from pathlib import Path
from typing import Any

import yaml

from ...domain.models import ExploitResult
from ..core.k8s_client import K8sClient
from ..core.logger import SecurityLogger, console
from .base import BaseExploit
from .test_loader import load_exploit_tests

_CONFIG_DIR = Path(__file__).resolve().parents[3] / "config" / "exploits"


def _load_exploit_config(config_key: str) -> dict[str, Any]:
    path = _CONFIG_DIR / f"{config_key}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"Exploit config not found: {path}")
    with open(path) as fh:
        return yaml.safe_load(fh) or {}


class DeploymentPatchExploit(BaseExploit):
    """Data-driven exploit that reads all behavior from YAML config.

    Replaces PrivilegedContainersExploit, DangerousCapabilitiesExploit,
    HostNamespaceSharingExploit, and MissingResourceLimitsExploit — all
    of which had identical demonstrate() methods differing only in patch
    data and check logic, both of which are now in the YAML config.
    """

    def __init__(  # noqa: D107
        self,
        k8s_client: K8sClient,
        service: str | None = None,
        logger: SecurityLogger | None = None,
        *,
        config_key: str = "",
    ) -> None:
        self._config_key = config_key
        self._exploit_config = _load_exploit_config(config_key)

        self.name = self._exploit_config.get("name", config_key)
        self.risk_level = self._exploit_config.get("risk_level", "MEDIUM")
        self.vulnerability_type = config_key
        self.description = self._exploit_config.get("description", "")

        super().__init__(k8s_client, service, logger)

    def get_vulnerable_patch(self) -> list[dict[str, Any]]:  # noqa: D102
        return list(self._exploit_config.get("vulnerable_patch", []))

    def check_vulnerability(self) -> bool:  # noqa: D102
        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return False

        try:
            pod = self.k8s.v1.read_namespaced_pod(pod_name, self.k8s.namespace)
            container = pod.spec.containers[0]

            for check in self._exploit_config.get("vulnerability_checks", []):
                if self._check_field(check, pod, container):
                    return True
            return False
        except Exception as e:
            self.logger.error(f"Error checking vulnerability for {self.service}: {e}")
            return False

    def demonstrate(self) -> ExploitResult:  # noqa: D102
        self.logger.exploit(f"Demonstrating {self.name} exploit...")

        pod_name = self.k8s.find_pod_for_service(self.service)
        if not pod_name:
            return ExploitResult(success=False, message="Pod not found for service")

        tests, summary_impact = load_exploit_tests(self.vulnerability_type)
        result = self._run_tests(pod_name, tests, f"{self.name} exploit demonstrated")

        self.logger.exploit("=== Impact Summary ===")
        for item in summary_impact:
            console.print(f"  • {item}")

        return result

    def _check_field(self, check: dict[str, Any], pod: Any, container: Any) -> bool:
        """Evaluate a single vulnerability check from YAML config."""
        field = check.get("field", "")
        condition = check.get("condition", "")

        value = self._resolve_field(field, pod, container)

        if condition == "equals_true":
            return value is True
        if condition == "missing":
            return value is None
        if condition == "contains_any":
            if not value or not isinstance(value, list):
                return False
            match_values = set(check.get("match_values", []))
            return bool(match_values & set(value))
        return False

    @staticmethod
    def _resolve_field(field: str, pod: Any, container: Any) -> Any:
        """Resolve a dotted field path against pod or container spec."""
        if field.startswith("pod."):
            obj = pod.spec
            path = field[4:]
        elif field.startswith("container."):
            obj = container
            path = field[10:]
        else:
            return None

        for segment in path.split("."):
            if obj is None:
                return None
            obj = getattr(obj, segment, None)
        return obj
