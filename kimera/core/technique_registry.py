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
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_CONFIG_DIR = Path(__file__).resolve().parents[2] / "config" / "techniques"


class TechniqueDefinition:
    """A loaded technique definition from YAML config."""

    def __init__(self, technique_id: str, data: dict[str, Any]) -> None:  # noqa: D107
        self.technique_id = technique_id
        self.name: str = data.get("name", technique_id)
        self.enabled: bool = data.get("enabled", True)
        self.severity: str = data.get("severity", "medium")
        self.description: str = data.get("description", "")

        mitre = data.get("mitre", {})
        self.mitre_id: str = mitre.get("technique_id", "")
        self.mitre_name: str = mitre.get("technique_name", "")
        self.tactic: str = mitre.get("tactic", "")

        execution = data.get("execution", {})
        self.mode: str = execution.get("mode", "exec")
        self.requires_target_pod: bool = execution.get("requires_target_pod", True)
        self.probes: list[dict[str, Any]] = execution.get("probes", [])
        self.parameters: list[dict[str, Any]] = execution.get("parameters", [])
        self.api_calls: list[dict[str, Any]] = execution.get("api_calls", [])

        self.evidence_markers: list[dict[str, str]] = execution.get("evidence_markers", [])
        self.success_indicators: list[str] = data.get("success_indicators", [])
        self.impact: list[str] = data.get("impact", [])
        self.remediation: str = data.get("remediation", "")
        self.data_store_ports: dict[int, str] = data.get("data_store_ports", {})


class TechniqueRegistry:
    """Loads and manages technique definitions from YAML configs.

    Supports runtime extension: call reload() after adding new YAML files
    to config/techniques/.
    """

    def __init__(self, config_dir: Path | None = None) -> None:  # noqa: D107
        self._config_dir = config_dir or _CONFIG_DIR
        self._techniques: dict[str, TechniqueDefinition] = {}
        self._registry_data: dict[str, dict[str, Any]] = {}
        self.reload()

    def reload(self) -> None:
        """Reload all technique definitions from disk."""
        self._techniques.clear()
        self._registry_data.clear()

        registry_path = self._config_dir / "registry.yaml"
        if not registry_path.exists():
            logger.warning("Technique registry not found: %s", registry_path)
            return

        with open(registry_path) as fh:
            registry = yaml.safe_load(fh) or {}

        for tech_id, meta in registry.get("techniques", {}).items():
            tech_file = self._config_dir / meta["file"]
            if not tech_file.exists():
                logger.debug("Technique file not found (skipping): %s", tech_file)
                continue

            with open(tech_file) as fh:
                tech_data = yaml.safe_load(fh) or {}

            self._techniques[tech_id] = TechniqueDefinition(tech_id, tech_data)
            self._registry_data[tech_id] = {
                "name": meta["name"],
                "phase": meta.get("phase", "unknown"),
                "noise": meta.get("noise", "medium"),
            }

    def get(self, technique_id: str) -> TechniqueDefinition | None:  # noqa: D102
        return self._techniques.get(technique_id)

    def list_techniques(self) -> list[dict[str, str]]:  # noqa: D102
        result = []
        for tech_id, meta in self._registry_data.items():
            tech = self._techniques.get(tech_id)
            if tech and tech.enabled:
                result.append(
                    {
                        "id": tech_id,
                        "name": meta["name"],
                        "phase": meta["phase"],
                        "noise": meta["noise"],
                        "mitre_id": tech.mitre_id,
                        "tactic": tech.tactic,
                        "mode": tech.mode,
                    }
                )
        return result

    def list_by_phase(self, phase: str) -> list[str]:  # noqa: D102
        return [
            tech_id
            for tech_id, meta in self._registry_data.items()
            if meta["phase"] == phase
            and self._techniques.get(tech_id, TechniqueDefinition(tech_id, {})).enabled
        ]

    @property
    def technique_count(self) -> int:  # noqa: D102
        return sum(1 for t in self._techniques.values() if t.enabled)

    def __contains__(self, technique_id: str) -> bool:  # noqa: D105
        return technique_id in self._techniques
